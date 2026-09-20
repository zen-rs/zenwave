//! HTTP/3 over QUIC connections for the hyper backend.
//!
//! An [`H3Connection`] is the shared send handle of one QUIC connection: h3
//! multiplexes requests over it, so the connection pool (#69) hands clones of
//! it to every request for the origin. The h3 connection driver is spawned at
//! connect time through the backend's spawner and keeps the connection alive
//! in the background.

use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{Buf, Bytes};
use futures_util::{StreamExt, stream};
use tracing::debug;

use super::HyperError;
use crate::{Error, transport::Spawn};

/// One HTTP/3 connection to an origin: an h3 send-request handle over a QUIC
/// connection whose driver runs in the background.
///
/// Cheap to clone; clones issue requests on the same QUIC connection.
pub struct H3Connection {
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// Set once the driver ends, however it ends — the pool's liveness check.
    closed: Arc<AtomicBool>,
}

impl Clone for H3Connection {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            closed: self.closed.clone(),
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
        let closed = Arc::new(AtomicBool::new(false));
        (spawn)(Box::pin({
            let closed = closed.clone();
            async move {
                // `wait_idle` resolves with the reason every connection ends —
                // idle timeouts and graceful closes included — so it is not a
                // warning.
                let error = driver.wait_idle().await;
                closed.store(true, Ordering::SeqCst);
                debug!(error = %error, "h3 connection closed");
            }
        }));
        Ok(Self { sender, closed })
    }

    /// Whether the connection's driver has ended. A closed handle is evicted
    /// from the pool rather than handed out again.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Issue `request` on this connection, streaming its body, and return the
    /// response with a streaming body.
    ///
    /// The request URI must be absolute: h3 requests carry `:scheme` and
    /// `:authority`. `http_kit::Body` has no trailer surface, so response
    /// trailers are consumed and dropped.
    ///
    /// A failure before the request was written returns it inside
    /// [`SendError`] so the caller can retry it on another connection.
    pub async fn request(
        &mut self,
        request: http::Request<http_kit::Body>,
    ) -> Result<http::Response<http_kit::Body>, SendError> {
        let (parts, mut body) = request.into_parts();
        let mut stream = match self
            .sender
            .send_request(http::Request::from_parts(parts.clone(), ()))
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                return Err(SendError {
                    error: HyperError::http3(error).into(),
                    unsent: Some(Box::new(http::Request::from_parts(parts, body))),
                });
            }
        };

        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|error| SendError {
                error: Error::from(error),
                unsent: None,
            })?;
            if !chunk.is_empty() {
                stream.send_data(chunk).await.map_err(|error| SendError {
                    error: HyperError::http3(error).into(),
                    unsent: None,
                })?;
            }
        }
        stream.finish().await.map_err(|error| SendError {
            error: HyperError::http3(error).into(),
            unsent: None,
        })?;

        let response = stream.recv_response().await.map_err(|error| SendError {
            error: HyperError::http3(error).into(),
            unsent: None,
        })?;
        let (parts, ()) = response.into_parts();
        // Fused: body readers may poll a stream once more after `None` —
        // `unfold` alone panics on that.
        let body = http_kit::Body::from_stream(
            stream::unfold(stream, |mut stream| async move {
                match stream.recv_data().await {
                    Ok(Some(mut data)) => {
                        let chunk = data.copy_to_bytes(data.remaining());
                        Some((Ok::<_, http_kit::BodyError>(chunk), stream))
                    }
                    Ok(None) => {
                        // Body has no trailer surface; drain them so the
                        // stream terminates cleanly.
                        let _ = stream.recv_trailers().await;
                        None
                    }
                    Err(error) => Some((Err(http_kit::BodyError::Other(Box::new(error))), stream)),
                }
            })
            .fuse(),
        );
        Ok(http::Response::from_parts(parts, body))
    }
}

/// A failed request on an h3 connection. When the connection died before the
/// request was written, the request rides inside so the caller can retry it
/// on another connection — the shape `hyper::client::conn::TrySendError` has.
pub struct SendError {
    error: Error,
    unsent: Option<Box<http::Request<http_kit::Body>>>,
}

impl SendError {
    /// The request, when the connection died before it was sent.
    pub(crate) fn take_request(&mut self) -> Option<http::Request<http_kit::Body>> {
        self.unsent.take().map(|request| *request)
    }

    /// The error itself.
    pub(crate) fn into_error(self) -> Error {
        self.error
    }
}

impl fmt::Debug for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendError")
            .field("error", &self.error)
            .field("unsent", &self.unsent.is_some())
            .finish()
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl core::error::Error for SendError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::{StreamExt, TryStreamExt, stream};

    use crate::backend::test_support::{H3Server, TestCa, block_on_test, h3_connection};

    const ECHO_BODY_SIZE: usize = 1024 * 1024;

    fn request(method: &str, uri: String, body: http_kit::Body) -> http::Request<http_kit::Body> {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(body)
            .expect("request builds")
    }

    async fn body_bytes(body: http_kit::Body) -> Vec<u8> {
        body.try_collect::<Vec<Bytes>>()
            .await
            .expect("body is valid")
            .concat()
    }

    #[test]
    fn get_streams_a_response_body() {
        let server = H3Server::start(&TestCa::new());
        block_on_test(async {
            let (_transport, mut connection) = h3_connection(&server).await;
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
        let server = H3Server::start(&TestCa::new());
        block_on_test(async {
            let (_transport, mut connection) = h3_connection(&server).await;
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
        let server = H3Server::start(&TestCa::new());
        block_on_test(async {
            let (_transport, mut connection) = h3_connection(&server).await;
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
                server.connection_count(),
                1,
                "two h3 requests on one H3Connection must multiplex over one QUIC connection"
            );
        });
    }

    #[test]
    fn headers_and_first_chunk_arrive_before_body_completes() {
        let server = H3Server::start(&TestCa::new());
        block_on_test(async {
            let (_transport, mut connection) = h3_connection(&server).await;
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
