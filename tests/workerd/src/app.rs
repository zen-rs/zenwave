//! Three routes, each one an outbound zenwave request made from inside the
//! Worker, answering with whatever the echo server sent back. A failure
//! answers 502 with zenwave's error text so the assertion in
//! `scripts/test-workerd.sh` reads the reason rather than a status alone.

use serde_json::Value;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::utils::{Bytes, Json};
use skyzen::{Body, Response, StatusCode};
use zenwave::Client as _;

const ECHO: &str = "https://httpbingo.org";

/// httpbingo refuses requests that carry no `User-Agent` (402), and a Worker's
/// `fetch` sends none by itself, so every request names this test.
const USER_AGENT: &str = "zenwave-workerd-smoke";

async fn relay(outcome: Result<Value, zenwave::Error>) -> Response {
    match outcome {
        Ok(value) => {
            let mut response = Response::new(Body::from(value.to_string()));
            response.headers_mut().insert(
                skyzen::header::CONTENT_TYPE,
                skyzen::header::HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(error) => {
            let mut response = Response::new(Body::from(error.to_string()));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            response
        }
    }
}

/// `GET /get` — a bodiless request.
async fn get() -> Response {
    let outcome = async {
        let mut client = zenwave::client();
        let response = client
            .get(format!("{ECHO}/get"))?
            .header("User-Agent", USER_AGENT)?
            .await?;
        response.into_body().into_json::<Value>().await.map_err(Into::into)
    }
    .await;
    relay(outcome).await
}

/// `POST /post` — the JSON body received is sent on as a JSON body.
async fn post(Json(payload): Json<Value>) -> Response {
    let outcome = async {
        let mut client = zenwave::client();
        let response = client
            .post(format!("{ECHO}/post"))?
            .header("User-Agent", USER_AGENT)?
            .json_body(&payload)?
            .await?;
        response.into_body().into_json::<Value>().await.map_err(Into::into)
    }
    .await;
    relay(outcome).await
}

/// `PUT /bytes` — the raw body received is sent on as a bytes body.
async fn bytes(body: Bytes) -> Response {
    let outcome = async {
        let mut client = zenwave::client();
        let response = client
            .put(format!("{ECHO}/put"))?
            .header("User-Agent", USER_AGENT)?
            .header("Content-Type", "text/plain")?
            .bytes_body(body.to_vec())
            .await?;
        response.into_body().into_json::<Value>().await.map_err(Into::into)
    }
    .await;
    relay(outcome).await
}

pub fn router() -> Router {
    Route::new(("/get".at(get), "/post".post(post), "/bytes".put(bytes))).build()
}
