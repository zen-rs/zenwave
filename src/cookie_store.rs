use crate::header;
use crate::{Endpoint, Middleware, Request, Response, Result};
use http_kit::cookie::{Cookie, CookieJar};
use http_kit::header::HeaderValue;
use http_kit::{ResultExt, StatusCode};

#[derive(Debug, Default)]
pub struct CookieStore {
    store: CookieJar,
}

impl Middleware for CookieStore {
    async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
        let cookie_header = self
            .store
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(";");

        request.insert_header(
            header::COOKIE,
            HeaderValue::from_maybe_shared(cookie_header).status(StatusCode::BAD_REQUEST)?,
        );

        let res = next.respond(request).await?;

        for set_cookie in res.get_headers(header::SET_COOKIE) {
            let set_cookie = set_cookie.to_str().status(StatusCode::BAD_REQUEST)?;
            let cookie = set_cookie
                .parse::<Cookie>()
                .status(StatusCode::BAD_REQUEST)?;
            self.store.add(cookie);
        }
        Ok(res)
    }
}
