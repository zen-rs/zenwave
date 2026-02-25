use http_kit::{Body, BodyError, Response};

pub(crate) async fn capture_error_response(
    mut response: Response,
) -> Result<(Response, Option<String>), BodyError> {
    let body = core::mem::replace(response.body_mut(), Body::empty());
    let bytes = body.into_bytes().await?;
    let body_text = core::str::from_utf8(bytes.as_ref()).ok().map(str::to_owned);
    *response.body_mut() = Body::from(bytes);
    Ok((response, body_text))
}
