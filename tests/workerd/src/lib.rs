//! Cloudflare Worker entry: see `app` for the routes.
mod app;

use skyzen::routing::Router;

#[skyzen::main]
fn worker() -> Router {
    app::router()
}
