//! Native entry, so `skyzen dev -p native` also works while iterating.
mod app;

use skyzen::routing::Router;

#[skyzen::main]
fn main() -> Router {
    app::router()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
