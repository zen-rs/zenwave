//! Trust configuration through `Transport`: the system store rejects a locally
//! issued certificate, extra roots make it acceptable, on HTTP and websockets alike.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use zenwave::{Error, Transport};

#[test]
fn pem_without_a_certificate_is_rejected() {
    let error = Transport::builder()
        .extra_root_certificates_pem(b"-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n")
        .expect_err("PEM without a CERTIFICATE block must be refused");
    assert!(matches!(error, Error::Tls(_)), "{error:?}");
}

#[test]
fn garbage_pem_is_rejected() {
    let error = Transport::builder()
        .extra_root_certificates_pem(
            b"-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----\n",
        )
        .expect_err("malformed PEM must be refused");
    assert!(matches!(error, Error::Tls(_)), "{error:?}");
}

#[test]
fn system_transport_is_shared() {
    let first = format!("{:?}", Transport::system());
    let second = format!("{:?}", Transport::system());
    assert_eq!(first, second);
}

#[cfg(any(feature = "hyper-backend", feature = "curl-backend"))]
mod http {
    use zenwave::{Client, Error, ResponseExt as _, Transport, backend::DefaultBackend};

    use crate::common::tls::tls_fixture;

    #[test_executors::async_test]
    async fn system_roots_reject_a_locally_issued_certificate() {
        let fixture = tls_fixture();
        let mut client = DefaultBackend::default();
        let error = client
            .get(fixture.https_uri("/"))
            .expect("valid request")
            .await
            .expect_err("a certificate from an unknown CA must be rejected");
        assert!(matches!(error, Error::Tls(_)), "{error:?}");
    }

    #[test_executors::async_test]
    async fn extra_roots_trust_a_locally_issued_certificate() {
        let fixture = tls_fixture();
        let transport = Transport::builder()
            .extra_root_certificates_pem(&fixture.ca_pem)
            .expect("test CA parses")
            .build()
            .expect("transport builds");
        let mut client = DefaultBackend::new(transport);
        let response = client
            .get(fixture.https_uri("/"))
            .expect("valid request")
            .await
            .expect("the test CA is trusted");
        let body: serde_json::Value = response.into_json().await.expect("JSON body");
        assert_eq!(body["secure"], true);
    }
}

#[cfg(feature = "ws")]
mod websocket {
    use zenwave::{
        Error, Transport,
        websocket::{self, WebSocketConfig, WebSocketError, WebSocketMessage},
    };

    use crate::common::tls::tls_fixture;

    #[test_executors::async_test]
    async fn system_roots_reject_a_locally_issued_certificate() {
        let fixture = tls_fixture();
        let error = websocket::connect(fixture.wss_uri())
            .await
            .expect_err("a certificate from an unknown CA must be rejected");
        assert!(
            matches!(error, WebSocketError::Transport(ref inner) if matches!(**inner, Error::Tls(_))),
            "{error:?}"
        );
    }

    #[test_executors::async_test]
    async fn extra_roots_trust_a_locally_issued_certificate() {
        let fixture = tls_fixture();
        let transport = Transport::builder()
            .extra_root_certificates_pem(&fixture.ca_pem)
            .expect("test CA parses")
            .build()
            .expect("transport builds");
        let socket =
            websocket::connect_with(fixture.wss_uri(), &transport, WebSocketConfig::default())
                .await
                .expect("the test CA is trusted");
        socket.send_text("over tls").await.expect("send");
        let echoed = socket.recv().await.expect("recv").expect("message");
        assert_eq!(echoed, WebSocketMessage::Text("over tls".into()));
        socket.close().await.expect("close");
    }
}
