use std::mem::replace;

use futures_util::TryStreamExt;
use http::StatusCode;
use http_body_util::BodyDataStream;
use http_kit::{Endpoint, HttpError, Method, Request, Response};
use hyper::http;
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;

use crate::{ClientBackend, Proxy};

use self::proxy_support::ProxyConnector;

/// Hyper-based HTTP client backend.
#[derive(Debug)]
pub struct HyperBackend {
    client: HyperClient<HttpsConnector<ProxyConnector>, http_kit::Body>,
}

impl Default for HyperBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperBackend {
    /// Create a new `HyperBackend`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_proxy_impl(None)
    }

    /// Create a backend configured to honor the provided proxy matcher.
    #[must_use]
    pub fn with_proxy(proxy: Proxy) -> Self {
        Self::with_proxy_impl(Some(proxy))
    }

    /// Replace the internal client with one configured to use the supplied proxy.
    #[must_use]
    pub fn proxy(self, proxy: Proxy) -> Self {
        Self::with_proxy(proxy)
    }

    fn with_proxy_impl(proxy: Option<Proxy>) -> Self {
        let connector = ProxyConnector::from_proxy(proxy);
        let https = HttpsConnector::new_with_connector(connector);
        let client = HyperClient::builder(TokioExecutor::new()).build(https);

        Self { client }
    }
}

#[derive(Debug)]
pub struct HyperError {
    error: hyper_util::client::legacy::Error,
}

impl core::fmt::Display for HyperError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hyper error: {}", self.error)
    }
}

impl core::error::Error for HyperError {}

impl HttpError for HyperError {
    fn status(&self) -> Option<StatusCode> {
        None
    }
}

impl Endpoint for HyperBackend {
    type Error = HyperError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(http_kit::Body::empty())
            .unwrap();
        let request: http::Request<http_kit::Body> = replace(request, dummy_request);

        let response = self
            .client
            .request(request)
            .await
            .map_err(|error| HyperError { error })?;

        let response = response.map(|body| {
            let stream = BodyDataStream::new(body);
            let stream = stream.map_err(|error| {
                http_kit::BodyError::Other(Box::new(error)) // TODO: improve error conversion
            });
            http_kit::Body::from_stream(stream)
        });

        Ok(response)
    }
}

impl ClientBackend for HyperBackend {}

mod proxy_support {
    use std::{
        error::Error as StdError,
        fmt,
        future::Future,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use http::{Uri, header::HeaderValue};
    use hyper_util::client::{
        legacy::connect::{
            HttpConnector,
            proxy::{SocksV4, SocksV5, Tunnel},
        },
        proxy::matcher,
    };
    use tower_service::Service;

    use crate::proxy::Proxy;

    type ConnectorResponse = <HttpConnector as Service<Uri>>::Response;
    type ProxyFuture = Pin<Box<dyn Future<Output = Result<ConnectorResponse, ProxyError>> + Send>>;

    #[derive(Clone, Debug)]
    pub(super) struct ProxyConnector {
        http: HttpConnector,
        matcher: Option<Arc<matcher::Matcher>>,
    }

    impl ProxyConnector {
        pub(super) fn from_proxy(proxy: Option<Proxy>) -> Self {
            let matcher = proxy.map(crate::proxy::Proxy::into_matcher);
            let mut http = HttpConnector::new();
            http.enforce_http(false);

            Self { http, matcher }
        }
    }

    impl Service<Uri> for ProxyConnector {
        type Response = ConnectorResponse;
        type Error = ProxyError;
        type Future = ProxyFuture;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.http.poll_ready(cx).map_err(ProxyError::boxed)
        }

        fn call(&mut self, dst: Uri) -> Self::Future {
            let matcher = self.matcher.clone();
            let direct = self.http.clone();
            let proxied = direct.clone();

            Box::pin(async move {
                if let Some(matcher) = matcher
                    && let Some(intercept) = matcher.intercept(&dst)
                {
                    return connect_via_proxy(proxied, intercept, dst).await;
                }

                let mut connector = direct;
                connector.call(dst).await.map_err(ProxyError::boxed)
            })
        }
    }

    async fn connect_via_proxy(
        http: HttpConnector,
        intercept: matcher::Intercept,
        dst: Uri,
    ) -> Result<ConnectorResponse, ProxyError> {
        let proxy_uri = intercept.uri().clone();
        let scheme = proxy_uri
            .scheme_str()
            .map_or_else(|| "http".into(), str::to_ascii_lowercase);
        let basic_auth = intercept.basic_auth().cloned();
        let raw_auth = intercept
            .raw_auth()
            .map(|(user, pass)| (user.to_owned(), pass.to_owned()));

        match scheme.as_str() {
            "http" | "https" => connect_http_tunnel(http, proxy_uri, basic_auth, dst).await,
            "socks4" => connect_socks4(http, proxy_uri, dst, true).await,
            "socks4a" => connect_socks4(http, proxy_uri, dst, false).await,
            "socks5" => connect_socks5(http, proxy_uri, dst, raw_auth.clone(), true).await,
            "socks5h" => connect_socks5(http, proxy_uri, dst, raw_auth, false).await,
            other => Err(ProxyError::boxed(UnsupportedScheme {
                scheme: other.to_owned(),
            })),
        }
    }

    async fn connect_http_tunnel(
        http: HttpConnector,
        proxy_uri: Uri,
        auth: Option<HeaderValue>,
        dst: Uri,
    ) -> Result<ConnectorResponse, ProxyError> {
        let mut connector = Tunnel::new(proxy_uri, http);
        if let Some(header) = auth {
            connector = connector.with_auth(header);
        }
        connector.call(dst).await.map_err(ProxyError::boxed)
    }

    async fn connect_socks4(
        http: HttpConnector,
        proxy_uri: Uri,
        dst: Uri,
        local_dns: bool,
    ) -> Result<ConnectorResponse, ProxyError> {
        let mut connector = SocksV4::new(proxy_uri, http);
        connector = connector.local_dns(local_dns);
        connector.call(dst).await.map_err(ProxyError::boxed)
    }

    async fn connect_socks5(
        http: HttpConnector,
        proxy_uri: Uri,
        dst: Uri,
        auth: Option<(String, String)>,
        local_dns: bool,
    ) -> Result<ConnectorResponse, ProxyError> {
        let mut connector = SocksV5::new(proxy_uri, http);
        connector = connector.local_dns(local_dns);
        if let Some((username, password)) = auth {
            connector = connector.with_auth(username, password);
        }
        connector.call(dst).await.map_err(ProxyError::boxed)
    }

    #[derive(Debug)]
    pub(super) struct ProxyError(Box<dyn StdError + Send + Sync>);

    impl ProxyError {
        fn boxed<E>(err: E) -> Self
        where
            E: StdError + Send + Sync + 'static,
        {
            Self(Box::new(err))
        }
    }

    impl fmt::Display for ProxyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "proxy error: {}", self.0)
        }
    }

    impl StdError for ProxyError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&*self.0)
        }
    }

    #[derive(Debug)]
    struct UnsupportedScheme {
        scheme: String,
    }

    impl fmt::Display for UnsupportedScheme {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "unsupported proxy scheme `{}`", self.scheme)
        }
    }

    impl StdError for UnsupportedScheme {}
}
