//! HTTP over unix domain sockets: `Transport::unix_socket` routes every
//! connection to the socket while request URIs stay ordinary `http` URIs.
#![cfg(all(unix, not(target_arch = "wasm32")))]

use std::path::PathBuf;

use zenwave::{Client as _, Transport};

/// The unix socket server side, for the backends that can dial one.
#[cfg(any(feature = "hyper-backend", feature = "curl-backend"))]
mod server {
    use std::{
        io::{self, Read as _, Write as _},
        os::unix::net::{UnixListener, UnixStream},
        path::PathBuf,
        thread,
    };

    pub const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong";

    /// Read one HTTP/1.1 request head, up to the blank line ending it.
    pub fn read_request(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
        let mut request = [0_u8; 4_096];
        let mut filled = 0_usize;
        loop {
            let read = socket.read(&mut request[filled..])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "test request ended before its HTTP header",
                ));
            }
            filled += read;
            if request[..filled]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                return Ok(request[..filled].to_vec());
            }
            assert!(
                filled < request.len(),
                "test request exceeded its explicit header bound"
            );
        }
    }

    /// Accept one connection, assert it carries an origin-form request with the
    /// URI's `Host` header, and answer it once.
    pub fn serve_once(socket_path: PathBuf) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let listener = UnixListener::bind(&socket_path).expect("test unix socket must bind");
            let (mut socket, _) = listener.accept().expect("test connection must arrive");
            let request = read_request(&mut socket).expect("test request must read");
            let head = String::from_utf8(request).expect("request head is ASCII");
            let request_line = head.lines().next().expect("request has a first line");
            assert_eq!(request_line, "GET /over-unix HTTP/1.1");
            assert!(
                head.lines()
                    .any(|line| line.eq_ignore_ascii_case("host: daemon.local")),
                "the request must carry the URI's host header, got:\n{head}"
            );
            socket.write_all(RESPONSE).expect("response must write");
        })
    }
}

fn unix_transport(socket_path: PathBuf) -> Transport {
    Transport::builder()
        .unix_socket(socket_path)
        .build()
        .expect("transport must build")
}

#[cfg(feature = "hyper-backend")]
mod hyper_backend {
    use std::{
        io::Write as _,
        os::unix::net::UnixListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use zenwave::{ResponseExt as _, StatusCode, backend::HyperBackend};

    use super::{
        server::{RESPONSE, read_request, serve_once},
        *,
    };

    #[test_executors::async_test]
    async fn requests_are_served_over_the_unix_socket() {
        let dir = tempfile::tempdir().expect("socket dir must be temporary");
        let socket_path = dir.path().join("zenwave.sock");
        let worker = serve_once(socket_path.clone());

        let mut client = HyperBackend::new(unix_transport(socket_path));
        let response = client
            .get("http://daemon.local/over-unix")
            .expect("request must build")
            .await
            .expect("request over the unix socket must succeed");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&*response.into_string().await.expect("body reads"), "pong");
        worker.join().expect("test server must finish");
    }

    #[test_executors::async_test]
    async fn pooled_connections_reuse_the_socket() {
        let dir = tempfile::tempdir().expect("socket dir must be temporary");
        let socket_path = dir.path().join("zenwave-pool.sock");
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        let path = socket_path.clone();
        let worker = thread::spawn(move || {
            let listener = UnixListener::bind(&path).expect("test unix socket must bind");
            let (mut first, _) = listener.accept().expect("first connection must arrive");
            counter.fetch_add(1, Ordering::SeqCst);
            first
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read deadline must set");
            read_request(&mut first).expect("first request must read");
            first
                .write_all(RESPONSE)
                .expect("first response must write");
            // A pooled connection serves the second request on the same
            // socket; without reuse it arrives on a fresh one — the read
            // deadline tells the two apart.
            if read_request(&mut first).is_ok() {
                first
                    .write_all(RESPONSE)
                    .expect("second response must write");
            } else {
                let (mut second, _) = listener.accept().expect("second connection must arrive");
                counter.fetch_add(1, Ordering::SeqCst);
                read_request(&mut second).expect("second request must read");
                second
                    .write_all(RESPONSE)
                    .expect("second response must write");
            }
        });

        let mut client = HyperBackend::new(unix_transport(socket_path));
        for _ in 0..2 {
            let response = client
                .get("http://daemon.local/pool")
                .expect("request must build")
                .await
                .expect("request over the unix socket must succeed");
            assert_eq!(response.status(), StatusCode::OK);
            // The lease returns to the pool with the body.
            drop(response);
        }
        worker.join().expect("test server must finish");
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "both requests must reuse the pooled connection"
        );
    }
}

#[cfg(feature = "curl-backend")]
mod curl_backend {
    use zenwave::{ResponseExt as _, StatusCode, backend::CurlBackend};

    use super::{server::serve_once, *};

    #[test_executors::async_test]
    async fn requests_are_served_over_the_unix_socket() {
        let dir = tempfile::tempdir().expect("socket dir must be temporary");
        let socket_path = dir.path().join("zenwave-curl.sock");
        let worker = serve_once(socket_path.clone());

        let mut client = CurlBackend::new(unix_transport(socket_path));
        let response = client
            .get("http://daemon.local/over-unix")
            .expect("request must build")
            .await
            .expect("request over the unix socket must succeed");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&*response.into_string().await.expect("body reads"), "pong");
        worker.join().expect("test server must finish");
    }
}

/// `URLSession` cannot dial unix domain sockets; the backend must say so.
#[cfg(all(target_vendor = "apple", feature = "apple-backend"))]
mod apple_backend {
    use zenwave::backend::AppleBackend;

    use super::*;

    #[test_executors::async_test]
    async fn unix_sockets_are_rejected() {
        let dir = tempfile::tempdir().expect("socket dir must be temporary");
        let mut client = AppleBackend::new(unix_transport(dir.path().join("zenwave.sock")));
        let error = client
            .get("http://daemon.local/over-unix")
            .expect("request must build")
            .await
            .expect_err("URLSession cannot serve unix sockets");
        assert!(
            error.to_string().contains("unix"),
            "the error must name unix sockets, got: {error}"
        );
    }
}
