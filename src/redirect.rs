use http_kit::{Endpoint, Method, ResultExt, header::LOCATION};

use crate::{Request, Response, Result, StatusCode, client::Client};

pub struct FollowRedirect<C: Client> {
    client: C,
}

impl<C: Client> Client for FollowRedirect<C> {}

impl<C: Client> FollowRedirect<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        let res = self.client.respond(request).await?;
        if res.status().is_redirection() {
            let location = request
                .get_header(LOCATION)
                .ok_or(http_kit::Error::msg("Missing Location header"))?
                .to_str()
                .status(StatusCode::BAD_REQUEST)?;
            // According to RFC 9110
            let method = match res.status() {
                StatusCode::MULTIPLE_CHOICES | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                    Method::GET
                }
                _ => request.method().clone(),
            };
            self.client.method(method, location).await
        } else {
            Ok(res)
        }
    }
}
