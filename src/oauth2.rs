//! `OAuth2` helpers and middleware.

use core::time::Duration;
use std::{sync::Arc, time::Instant};

use futures_util::lock::Mutex;
use http::StatusCode;
use http_kit::{
    BodyError, Endpoint, HttpError, Middleware, Request, Response, header,
    middleware::MiddlewareError,
};
use serde::Deserialize;
use url::form_urlencoded::Serializer;

use crate::{Client, DefaultBackend, client};

type TokenError = OAuth2Error<<DefaultBackend as Endpoint>::Error>;

/// Errors produced while performing `OAuth2` flows.
#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error<H: HttpError> {
    /// Network or backend failure while requesting a token.
    #[error("request failed: {0}")]
    Transport(#[source] H),

    /// The token endpoint responded with a non-success status code.
    #[error("OAuth2 token endpoint returned {status}: {message}")]
    Upstream {
        /// HTTP status returned by the token endpoint.
        status: StatusCode,
        /// Error details from the token endpoint.
        message: String,
    },

    /// The token response body could not be parsed.
    #[error("invalid token response: {0}")]
    InvalidResponse(BodyError),
}

impl<H: HttpError> HttpError for OAuth2Error<H> {
    fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Transport(err) => err.status(),
            Self::Upstream { status, .. } => Some(*status),
            Self::InvalidResponse(_) => Some(StatusCode::BAD_GATEWAY),
        }
    }
}

impl<T: HttpError> From<T> for OAuth2Error<T> {
    fn from(error: T) -> Self {
        Self::Transport(error)
    }
}

/// Middleware implementing the `OAuth2` client credentials flow.
///
/// It lazily acquires an access token from the configured token endpoint and automatically adds the
/// `Authorization: Bearer <token>` header to outgoing requests. Tokens are cached until they expire
/// (with a small safety window) and are refreshed on-demand before dispatching the next request.
#[derive(Debug, Clone)]
pub struct OAuth2ClientCredentials {
    config: Arc<Config>,
    token: Arc<Mutex<Option<TokenInfo>>>,
}

#[derive(Debug, Clone)]
struct Config {
    token_url: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
    audience: Option<String>,
    safety_window: Duration,
}

#[derive(Debug, Clone)]
struct TokenInfo {
    access_token: String,
    expires_at: Instant,
}

impl TokenInfo {
    fn is_valid(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

impl OAuth2ClientCredentials {
    /// Create a new middleware that exchanges client credentials for access tokens.
    pub fn new(
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            config: Arc::new(Config {
                token_url: token_url.into(),
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                scope: None,
                audience: None,
                safety_window: Duration::from_secs(30),
            }),
            token: Arc::new(Mutex::new(None)),
        }
    }

    /// Restrict the request to specific scopes.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        let mut cfg = (*self.config).clone();
        cfg.scope = Some(scope.into());
        self.config = Arc::new(cfg);
        self
    }

    /// Set a custom audience parameter if required by the provider.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        let mut cfg = (*self.config).clone();
        cfg.audience = Some(audience.into());
        self.config = Arc::new(cfg);
        self
    }

    async fn ensure_token(&self) -> Result<String, TokenError> {
        let now = Instant::now();
        {
            let token_guard = self.token.lock().await;
            if let Some(info) = token_guard.as_ref()
                && info.is_valid(now)
            {
                return Ok(info.access_token.clone());
            }
        }

        // Acquire a fresh token (only one concurrent refresh).
        let mut token_guard = self.token.lock().await;
        if let Some(info) = token_guard.as_ref()
            && info.is_valid(now)
        {
            return Ok(info.access_token.clone());
        }

        let fetched = self.fetch_token().await?;
        let token_value = fetched.access_token.clone();
        *token_guard = Some(fetched);
        Ok(token_value)
    }

    async fn fetch_token(&self) -> Result<TokenInfo, TokenError> {
        let body = self.build_body();
        let mut client = client();
        let response = client
            .post(&self.config.token_url)
            .header(
                header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .bytes_body(body.into_bytes())
            .await?;

        let status = response.status();
        let mut body = response.into_body();
        if !status.is_success() {
            let text = body
                .into_string()
                .await
                .unwrap_or_else(|_| http_kit::utils::ByteStr::new());
            return Err(OAuth2Error::Upstream {
                status,
                message: format!("OAuth2 token endpoint returned {status}: {text}"),
            });
        }
        let token: TokenEndpointResponse = body
            .into_json()
            .await
            .map_err(OAuth2Error::InvalidResponse)?;

        let expires_in = token.expires_in.unwrap_or(3600);
        let lifetime = Duration::from_secs(expires_in);
        let safety = self
            .config
            .safety_window
            .min(Duration::from_secs(expires_in / 2));
        let expires_at = Instant::now() + lifetime.saturating_sub(safety);

        Ok(TokenInfo {
            access_token: token.access_token,
            expires_at,
        })
    }

    fn build_body(&self) -> String {
        let mut serializer = Serializer::new(String::new());
        serializer.append_pair("grant_type", "client_credentials");
        serializer.append_pair("client_id", &self.config.client_id);
        serializer.append_pair("client_secret", &self.config.client_secret);
        if let Some(scope) = &self.config.scope {
            serializer.append_pair("scope", scope);
        }
        if let Some(audience) = &self.config.audience {
            serializer.append_pair("audience", audience);
        }
        serializer.finish()
    }
}

impl Middleware for OAuth2ClientCredentials {
    type Error = TokenError;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, http_kit::middleware::MiddlewareError<E::Error, Self::Error>> {
        if !request.headers().contains_key(header::AUTHORIZATION) {
            let token = self
                .ensure_token()
                .await
                .map_err(MiddlewareError::Middleware)?;
            let header_value = format!("Bearer {token}");
            request.headers_mut().insert(
                header::AUTHORIZATION,
                header_value
                    .parse()
                    .expect("Fail to create a bearer header"),
            );
        }

        next.respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)
    }
}

#[derive(Debug, Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use async_lock::Mutex;
    use async_net::{TcpListener, TcpStream};
    use async_std::task::{self, JoinHandle};
    use http::{Request as HttpRequest, Response as HttpResponse};
    use http_kit::utils::{AsyncReadExt, AsyncWriteExt};
    use http_kit::{Body, Method};
    use std::convert::Infallible;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn acquires_token_and_attaches_header() {
        let (url, handle, hits) =
            match async_io::block_on(async { spawn_token_server(vec!["token-one"]).await }) {
                Ok(values) => values,
                Err(err) => {
                    eprintln!("skipping oauth2 token test: {err}");
                    return;
                }
            };
        let mut middleware = OAuth2ClientCredentials::new(url, "abc", "xyz");
        let mut request = HttpRequest::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap();
        let mut endpoint = RecordingEndpoint::default();

        async_io::block_on(async {
            middleware
                .handle(&mut request, &mut endpoint)
                .await
                .unwrap();
            assert_eq!(endpoint.calls(), 1);
            assert_eq!(endpoint.last_auth(), Some("Bearer token-one".to_string()));
            assert_eq!(hits.load(Ordering::SeqCst), 1);

            let mut request = HttpRequest::builder()
                .method(Method::GET)
                .uri("https://example.com/2")
                .body(Body::empty())
                .unwrap();
            middleware
                .handle(&mut request, &mut endpoint)
                .await
                .unwrap();
            assert_eq!(endpoint.calls(), 2);
            assert_eq!(hits.load(Ordering::SeqCst), 1);

            handle.cancel().await;
        });
    }

    #[derive(Default)]
    struct RecordingEndpoint {
        calls: usize,
        last_auth: Option<String>,
    }

    impl RecordingEndpoint {
        const fn calls(&self) -> usize {
            self.calls
        }

        fn last_auth(&self) -> Option<String> {
            self.last_auth.clone()
        }
    }

    impl Endpoint for RecordingEndpoint {
        type Error = Infallible;
        async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
            self.calls += 1;
            self.last_auth = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);

            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        }
    }

    async fn spawn_token_server(
        tokens: Vec<&'static str>,
    ) -> std::io::Result<(String, JoinHandle<()>, Arc<AtomicUsize>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hit_counter = hits.clone();
        let tokens = Arc::new(Mutex::new(
            tokens
                .into_iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        ));

        let server = task::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let tokens = tokens.clone();
                let hit_counter = hit_counter.clone();
                task::spawn(async move {
                    handle_token_request(socket, tokens, hit_counter).await;
                });
            }
        });

        Ok((format!("http://{addr}"), server, hits))
    }

    async fn handle_token_request(
        mut socket: TcpStream,
        tokens: Arc<Mutex<Vec<String>>>,
        counter: Arc<AtomicUsize>,
    ) {
        let mut buf = vec![0u8; 2048];
        if socket.read(&mut buf).await.unwrap_or(0) == 0 {
            return;
        }
        counter.fetch_add(1, Ordering::SeqCst);
        let token = {
            let mut guard = tokens.lock().await;
            guard.pop().unwrap_or_else(|| "fallback-token".to_string())
        };
        let response_body =
            format!(r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":3600}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.close().await;
    }
}
