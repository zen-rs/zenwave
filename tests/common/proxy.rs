//! An in-process HTTP forward proxy: absolute-form requests are forwarded,
//! `CONNECT` opens a tunnel. Every request is recorded so tests can assert
//! what the client actually sent to the proxy.
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread,
};

use async_net::{TcpListener, TcpStream};
use futures_util::{AsyncReadExt, AsyncWriteExt, future::select, io::copy};

/// One request as seen by the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxiedRequest {
    pub method: String,
    /// The request target: an absolute URI or, for `CONNECT`, `host:port`.
    pub target: String,
    pub proxy_authorization: Option<String>,
}

#[derive(Debug)]
pub struct HttpProxy {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<ProxiedRequest>>>,
}

impl HttpProxy {
    /// Start a proxy that lets everyone through.
    pub fn start() -> Self {
        Self::start_with(None)
    }

    /// Start a proxy that answers 407 unless `Proxy-Authorization` equals `required`.
    pub fn start_requiring(required: &str) -> Self {
        Self::start_with(Some(required.to_owned()))
    }

    fn start_with(required_authorization: Option<String>) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let (listener, addr) = smol::block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
            let addr = listener.local_addr().expect("proxy address");
            (listener, addr)
        });
        let worker_log = Arc::clone(&log);
        thread::spawn(move || {
            smol::block_on(async move {
                loop {
                    let (client, _) = listener.accept().await.expect("accept on proxy");
                    let log = Arc::clone(&worker_log);
                    let required = required_authorization.clone();
                    smol::spawn(async move {
                        serve(client, log, required).await;
                    })
                    .detach();
                }
            });
        });
        Self { addr, log }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn uri(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// `http://<user>:<password>@127.0.0.1:<port>`.
    pub fn uri_with_credentials(&self, user: &str, password: &str) -> String {
        format!("http://{user}:{password}@{}", self.addr)
    }

    pub fn requests(&self) -> Vec<ProxiedRequest> {
        self.log.lock().expect("proxy log").clone()
    }
}

async fn serve(
    mut client: TcpStream,
    log: Arc<Mutex<Vec<ProxiedRequest>>>,
    required: Option<String>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_len = loop {
        let Ok(read) = client.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    let Ok(httparse::Status::Complete(_)) = request.parse(&buffer[..head_len]) else {
        return;
    };
    let method = request.method.expect("method").to_owned();
    let target = request.path.expect("target").to_owned();
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| String::from_utf8_lossy(header.value).into_owned())
    };
    let proxy_authorization = header("proxy-authorization");
    log.lock().expect("proxy log").push(ProxiedRequest {
        method: method.clone(),
        target: target.clone(),
        proxy_authorization: proxy_authorization.clone(),
    });

    if let Some(required) = required
        && proxy_authorization.as_deref() != Some(required.as_str())
    {
        let _ = client
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"zenwave\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    }

    if method == "CONNECT" {
        let Ok(upstream) = TcpStream::connect(target.as_str()).await else {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        relay(client, upstream, &buffer[head_len..]).await;
        return;
    }

    // Absolute-form: connect to the origin, rewrite the request line, drop
    // the proxy header, forward everything else verbatim.
    let url = url::Url::parse(&target).expect("absolute-form target");
    let host = url.host_str().expect("host");
    let port = url.port_or_known_default().expect("port");
    let Ok(mut upstream) = TcpStream::connect((host, port)).await else {
        let _ = client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };
    let origin_form = url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    );
    let mut forwarded = format!("{method} {origin_form} HTTP/1.1\r\n").into_bytes();
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("proxy-authorization")
            || header.name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        forwarded.extend_from_slice(header.name.as_bytes());
        forwarded.extend_from_slice(b": ");
        forwarded.extend_from_slice(header.value);
        forwarded.extend_from_slice(b"\r\n");
    }
    forwarded.extend_from_slice(b"\r\n");
    if upstream.write_all(&forwarded).await.is_err() {
        return;
    }
    relay(client, upstream, &buffer[head_len..]).await;
}

/// Pump bytes both ways until either side closes.
async fn relay(client: TcpStream, mut upstream: TcpStream, pending: &[u8]) {
    if !pending.is_empty() && upstream.write_all(pending).await.is_err() {
        return;
    }
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let to_upstream = async {
        let _ = copy(&mut client_read, &mut upstream_write).await;
        let _ = upstream_write.close().await;
    };
    let to_client = async {
        let _ = copy(&mut upstream_read, &mut client_write).await;
        let _ = client_write.close().await;
    };
    let _ = select(Box::pin(to_upstream), Box::pin(to_client)).await;
}
