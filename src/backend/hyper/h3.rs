//! HTTP/3 over QUIC connections for the hyper backend.
//!
//! An [`H3Connection`] is the shared send handle of one QUIC connection: h3
//! multiplexes requests over it, so the connection pool (#69) hands clones of
//! it to every request for the origin. The h3 connection driver is spawned at
//! connect time through the backend's spawner and keeps the connection alive
//! in the background.

use std::{fmt, net::SocketAddr};

use bytes::{Buf, Bytes};
use futures_util::{StreamExt, stream};
use tracing::debug;

use super::HyperError;
use crate::{Error, transport::quic::Spawn};

/// One HTTP/3 connection to an origin: an h3 send-request handle over a QUIC
/// connection whose driver runs in the background.
///
/// Cheap to clone; clones issue requests on the same QUIC connection.
pub struct H3Connection {
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

impl Clone for H3Connection {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl fmt::Debug for H3Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Connection").finish_non_exhaustive()
    }
}

impl H3Connection {
    /// Open a QUIC connection to `(addr, server_name)` on `endpoint` and run
    /// the h3 handshake, spawning the connection driver through `spawn`.
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        config: quinn::ClientConfig,
        addr: SocketAddr,
        server_name: &str,
        spawn: &Spawn,
    ) -> Result<Self, Error> {
        let connection = endpoint
            .connect_with(config, addr, server_name)
            .map_err(HyperError::http3)?
            .await
            .map_err(HyperError::http3)?;
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(HyperError::http3)?;
        (spawn)(Box::pin(async move {
            // `wait_idle` resolves with the reason every connection ends —
            // idle timeouts and graceful closes included — so it is not a
            // warning.
            let error = driver.wait_idle().await;
            debug!(error = %error, "h3 connection closed");
        }));
        Ok(Self { sender })
    }

    /// Issue `request` on this connection, streaming its body, and return the
    /// response with a streaming body.
    ///
    /// The request URI must be absolute: h3 requests carry `:scheme` and
    /// `:authority`. `http_kit::Body` has no trailer surface, so response
    /// trailers are consumed and dropped.
    pub async fn request(
        &mut self,
        request: http::Request<http_kit::Body>,
    ) -> Result<http::Response<http_kit::Body>, Error> {
        let (parts, mut body) = request.into_parts();
        let mut stream = self
            .sender
            .send_request(http::Request::from_parts(parts, ()))
            .await
            .map_err(HyperError::http3)?;

        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(Error::from)?;
            if !chunk.is_empty() {
                stream.send_data(chunk).await.map_err(HyperError::http3)?;
            }
        }
        stream.finish().await.map_err(HyperError::http3)?;

        let response = stream.recv_response().await.map_err(HyperError::http3)?;
        let (parts, ()) = response.into_parts();
        let body = http_kit::Body::from_stream(stream::unfold(stream, |mut stream| async move {
            match stream.recv_data().await {
                Ok(Some(mut data)) => {
                    let chunk = data.copy_to_bytes(data.remaining());
                    Some((Ok::<_, http_kit::BodyError>(chunk), stream))
                }
                Ok(None) => {
                    // Body has no trailer surface; drain them so the stream
                    // terminates cleanly.
                    let _ = stream.recv_trailers().await;
                    None
                }
                Err(error) => Some((Err(http_kit::BodyError::Other(Box::new(error))), stream)),
            }
        }));
        Ok(http::Response::from_parts(parts, body))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        net::{SocketAddr, UdpSocket},
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use bytes::{Buf, Bytes};
    use futures_channel::oneshot;
    use futures_util::{StreamExt, TryStreamExt, future::Either, stream};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use rustls::{
        crypto::ring,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };

    use super::H3Connection;
    use crate::{
        Transport,
        transport::quic::{self, AsyncIoRuntime, Spawn},
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const ECHO_BODY_SIZE: usize = 1024 * 1024;

    type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

    /// Spawn each future on its own thread running `async_io::block_on`,
    /// mirroring `HyperBackend::spawn_background` without an executor.
    fn thread_spawn() -> Spawn {
        Arc::new(|future| {
            thread::spawn(move || {
                async_io::block_on(future);
            });
        })
    }

    /// A CA and a `localhost` leaf it signed; the leaf serves the test server
    /// and the CA goes to the client through `extra_root_certificate_der`.
    fn certificates() -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        PrivatePkcs8KeyDer<'static>,
    ) {
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .expect("leaf params");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");

        (
            ca_cert.der().clone(),
            leaf.der().clone(),
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        )
    }

    struct TestServer {
        addr: SocketAddr,
        ca_der: CertificateDer<'static>,
        /// QUIC connections the server accepted; h3 multiplexes, so one
        /// `H3Connection` must produce exactly one.
        connection_count: Arc<AtomicUsize>,
        /// Releases the second `/slow` response chunk.
        release_slow: oneshot::Sender<()>,
    }

    impl TestServer {
        fn start() -> Self {
            let (ca_der, leaf_der, key) = certificates();
            let mut tls =
                rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .expect("TLS 1.3 is supported")
                    .with_no_client_auth()
                    .with_single_cert(vec![leaf_der], PrivateKeyDer::Pkcs8(key))
                    .expect("server certificate is valid");
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let quic =
                quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC server config");
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));

            let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("UDP socket binds");
            let addr = socket.local_addr().expect("local address");
            let spawn = thread_spawn();
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket,
                Arc::new(AsyncIoRuntime {
                    spawn: spawn.clone(),
                }),
            )
            .expect("server endpoint binds");

            let connection_count = Arc::new(AtomicUsize::new(0));
            let (release_slow, slow_rx) = oneshot::channel();
            thread::spawn({
                let connection_count = connection_count.clone();
                let spawn = spawn.clone();
                move || {
                    async_io::block_on(async move {
                        let mut slow_rx = Some(slow_rx);
                        while let Some(incoming) = endpoint.accept().await {
                            connection_count.fetch_add(1, Ordering::SeqCst);
                            (spawn)(Box::pin(serve_connection(
                                incoming,
                                spawn.clone(),
                                slow_rx.take(),
                            )));
                        }
                    });
                }
            });

            Self {
                addr,
                ca_der,
                connection_count,
                release_slow,
            }
        }

        fn uri(&self, path: &str) -> String {
            format!("https://localhost:{}{path}", self.addr.port())
        }
    }

    async fn serve_connection(
        incoming: quinn::Incoming,
        spawn: Spawn,
        mut slow_release: Option<oneshot::Receiver<()>>,
    ) {
        let connection = incoming.await.expect("QUIC handshake completes");
        let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
            .await
            .expect("h3 handshake completes");
        // `Ok(None)` is a graceful close and an error means the client went
        // away — either ends the connection.
        while let Ok(Some(resolver)) = h3.accept().await {
            let release = slow_release.take();
            (spawn)(Box::pin(serve_request(resolver, release)));
        }
    }

    async fn serve_request(
        resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
        slow_release: Option<oneshot::Receiver<()>>,
    ) {
        let (request, mut stream) = resolver.resolve_request().await.expect("request resolves");
        let result = match (request.method().as_str(), request.uri().path()) {
            ("GET", "/hello") => {
                serve_body(&mut stream, Bytes::from_static(b"hello over h3")).await
            }
            ("POST", "/echo") => serve_echo(&mut stream).await,
            ("GET", "/slow") => {
                serve_slow(&mut stream, slow_release.expect("one /slow per test")).await
            }
            _ => serve_status(&mut stream, http::StatusCode::NOT_FOUND).await,
        };
        result.expect("request is served");
    }

    fn ok_response() -> http::Response<()> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .expect("response builds")
    }

    async fn serve_body(
        stream: &mut ServerStream,
        body: Bytes,
    ) -> Result<(), h3::error::StreamError> {
        stream.send_response(ok_response()).await?;
        stream.send_data(body).await?;
        stream.finish().await
    }

    async fn serve_echo(stream: &mut ServerStream) -> Result<(), h3::error::StreamError> {
        stream.send_response(ok_response()).await?;
        while let Some(mut chunk) = stream.recv_data().await? {
            let data = chunk.copy_to_bytes(chunk.remaining());
            stream.send_data(data).await?;
        }
        stream.finish().await
    }

    /// The second chunk waits for the test to release it: a client that buffers
    /// the whole body before answering hangs here forever.
    async fn serve_slow(
        stream: &mut ServerStream,
        release: oneshot::Receiver<()>,
    ) -> Result<(), h3::error::StreamError> {
        stream.send_response(ok_response()).await?;
        stream.send_data(Bytes::from_static(&[0xA5; 64])).await?;
        let _ = release.await;
        stream.send_data(Bytes::from_static(&[0x5A; 64])).await?;
        stream.finish().await
    }

    async fn serve_status(
        stream: &mut ServerStream,
        status: http::StatusCode,
    ) -> Result<(), h3::error::StreamError> {
        let response = http::Response::builder()
            .status(status)
            .body(())
            .expect("response builds");
        stream.send_response(response).await?;
        stream.finish().await
    }

    /// A client h3 connection to `server`, over a transport trusting its CA.
    /// The returned `Transport` owns the shared QUIC endpoint and must outlive
    /// the connection.
    async fn client(server: &TestServer) -> (Transport, H3Connection) {
        let transport = Transport::builder()
            .extra_root_certificate_der(server.ca_der.to_vec())
            .build()
            .expect("transport builds");
        let spawn = thread_spawn();
        let endpoint = transport
            .quic_endpoint(spawn.clone())
            .expect("client endpoint binds");
        let config =
            quic::client_config(transport.tls().client_config()).expect("QUIC client config");
        let connection = H3Connection::connect(endpoint, config, server.addr, "localhost", &spawn)
            .await
            .expect("h3 connection is established");
        (transport, connection)
    }

    fn request(method: &str, uri: String, body: http_kit::Body) -> http::Request<http_kit::Body> {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(body)
            .expect("request builds")
    }

    fn block_on_test<F: Future>(future: F) -> F::Output {
        async_io::block_on(async {
            let future = pin!(future);
            let timeout = pin!(async_io::Timer::after(TEST_TIMEOUT));
            match futures_util::future::select(future, timeout).await {
                Either::Left((output, _)) => output,
                Either::Right(_) => panic!("h3 test timed out after {TEST_TIMEOUT:?}"),
            }
        })
    }

    async fn body_bytes(body: http_kit::Body) -> Vec<u8> {
        body.try_collect::<Vec<Bytes>>()
            .await
            .expect("body is valid")
            .concat()
    }

    #[test]
    fn get_streams_a_response_body() {
        let server = TestServer::start();
        block_on_test(async {
            let (_transport, mut connection) = client(&server).await;
            let response = connection
                .request(request(
                    "GET",
                    server.uri("/hello"),
                    http_kit::Body::empty(),
                ))
                .await
                .expect("request succeeds");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(body_bytes(response.into_body()).await, b"hello over h3");
        });
    }

    #[test]
    fn post_streams_a_request_body() {
        let server = TestServer::start();
        block_on_test(async {
            let (_transport, mut connection) = client(&server).await;
            // Several chunks, so the echo proves the body is streamed rather
            // than buffered into one write.
            let chunks = vec![
                Bytes::from(vec![0xAA; ECHO_BODY_SIZE / 2]),
                Bytes::from(vec![0xBB; ECHO_BODY_SIZE / 4]),
                Bytes::from(vec![0xCC; ECHO_BODY_SIZE / 4]),
            ];
            let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            let body = http_kit::Body::from_stream(stream::iter(
                chunks.into_iter().map(Ok::<_, http_kit::BodyError>),
            ));
            let response = connection
                .request(request("POST", server.uri("/echo"), body))
                .await
                .expect("request succeeds");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(body_bytes(response.into_body()).await, expected);
        });
    }

    #[test]
    fn concurrent_requests_share_one_quic_connection() {
        let server = TestServer::start();
        block_on_test(async {
            let (_transport, mut connection) = client(&server).await;
            let mut second = connection.clone();
            let (first, second) = futures_util::join!(
                connection.request(request(
                    "GET",
                    server.uri("/hello"),
                    http_kit::Body::empty()
                )),
                second.request(request(
                    "GET",
                    server.uri("/hello"),
                    http_kit::Body::empty()
                )),
            );
            assert_eq!(
                first.expect("first request succeeds").status(),
                http::StatusCode::OK
            );
            assert_eq!(
                second.expect("second request succeeds").status(),
                http::StatusCode::OK
            );
            assert_eq!(
                server.connection_count.load(Ordering::SeqCst),
                1,
                "two h3 requests on one H3Connection must multiplex over one QUIC connection"
            );
        });
    }

    #[test]
    fn headers_and_first_chunk_arrive_before_body_completes() {
        let server = TestServer::start();
        block_on_test(async {
            let (_transport, mut connection) = client(&server).await;
            let response = connection
                .request(request("GET", server.uri("/slow"), http_kit::Body::empty()))
                .await
                .expect("response arrives while the body is still streaming");
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut body = response.into_body();
            // The server is still holding the second chunk; the first must
            // already be readable.
            let first = body
                .next()
                .await
                .expect("first chunk arrives")
                .expect("first chunk is valid");
            assert_eq!(first.as_ref(), &[0xA5; 64]);
            server.release_slow.send(()).expect("release second chunk");
            let second = body
                .next()
                .await
                .expect("second chunk arrives")
                .expect("second chunk is valid");
            assert_eq!(second.as_ref(), &[0x5A; 64]);
            assert!(body.next().await.is_none());
        });
    }
}
