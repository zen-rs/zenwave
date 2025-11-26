//! A custom client example demonstrating middleware composition.

use serde::{Deserialize, Serialize};
use zenwave::{self, Client};

#[derive(Serialize)]
struct MessageRequest<'a> {
    message: &'a str,
}

#[derive(Debug, Deserialize)]
struct EchoResponse {
    json: Message,
    url: String,
}

#[derive(Debug, Deserialize)]
struct Message {
    message: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    async_io::block_on(async {
        let token = std::env::var("ZENWAVE_TOKEN").unwrap_or_else(|_| "demo-token".into());

        // Compose the middleware you need.
        let mut client = zenwave::client()
            .follow_redirect()
            .enable_cookie()
            .bearer_auth(token);

        let payload = MessageRequest {
            message: "zenwave says hi!",
        };

        let response: EchoResponse = client
            .post("https://httpbin.org/post")
            .header("x-request-id", "demo-request")
            .json_body(&payload)
            .json()
            .await?;

        println!("Server echoed '{}'", response.json.message);
        println!("Request URL     : {}", response.url);

        Ok(())
    })
}
