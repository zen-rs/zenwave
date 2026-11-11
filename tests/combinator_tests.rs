//! Combinator chains on a real client: every combinator's result stays
//! `Clocked` and nameable, so `timeout` and `retry` compose in any order and
//! a combined client can sit in a struct field. A one-response server on
//! loopback answers each request; no external service is involved.
#![cfg(all(default_backend, not(target_arch = "wasm32")))]

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

use zenwave::{
    Client, DefaultClient, Timeout, client,
    clock::Clocked,
    endpoint::WithMiddleware,
    {BasicAuth, BearerAuth, Cache, CookieStore},
};

/// Serves `connections` HTTP/1.1 responses with `status` and closes each
/// connection, returning the base URI.
fn serve(status: &'static str, connections: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("http://{}/", listener.local_addr().unwrap());
    thread::spawn(move || {
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
            )
            .unwrap();
        }
    });
    uri
}

const fn assert_clocked<C: Clocked>(_: &C) {}

#[test_executors::async_test]
async fn timeout_then_retry_composes() {
    let uri = serve("200 OK", 1);
    let mut client = client().timeout(Duration::from_secs(30)).retry(2);
    let response = client.get(uri).unwrap().await.unwrap();
    assert_eq!(response.status(), 200);
}

#[test_executors::async_test]
async fn error_for_status_then_timeout_composes() {
    let uri = serve("404 Not Found", 1);
    let mut client = client().error_for_status().timeout(Duration::from_secs(30));
    assert!(client.get(uri).unwrap().await.is_err());
}

#[test]
fn every_combinator_keeps_the_clock() {
    assert_clocked(&client().with(zenwave::ErrorForStatus));
    assert_clocked(&client().enable_cache());
    assert_clocked(&client().enable_cookie());
    assert_clocked(&client().bearer_auth("token"));
    assert_clocked(&client().basic_auth("user", Some("password")));
    assert_clocked(&client().follow_redirect());
    assert_clocked(
        &client()
            .enable_cookie()
            .bearer_auth("token")
            .timeout(Duration::from_secs(1)),
    );
}

/// The case a caller hits when it stores the client it builds.
struct Held {
    client: WithMiddleware<DefaultClient, Timeout<<DefaultClient as Clocked>::Clock>>,
}

#[test_executors::async_test]
async fn a_combined_client_sits_in_a_struct_field() {
    let uri = serve("200 OK", 1);
    let mut held = Held {
        client: zenwave::client().timeout(Duration::from_secs(30)),
    };
    let response = held.client.get(uri).unwrap().await.unwrap();
    assert_eq!(response.status(), 200);
}

/// The middleware types a caller names are reachable from the crate root.
#[allow(dead_code)]
struct Named {
    bearer: WithMiddleware<DefaultClient, BearerAuth>,
    basic: WithMiddleware<DefaultClient, BasicAuth>,
    cache: WithMiddleware<DefaultClient, Cache>,
    cookies: WithMiddleware<DefaultClient, CookieStore>,
}
