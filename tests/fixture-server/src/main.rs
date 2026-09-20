//! Runs the shared httpbin fixture (`tests/common/fixture.rs`) as a
//! standalone server. The harness (`scripts/test-wasm.sh`,
//! `scripts/test-workerd.sh`) reads the one line this prints — the base URL —
//! to learn the bound port, then kills the process when the lane is done.

#[path = "../../common/fixture.rs"]
mod fixture;

use std::{io::Write as _, net::TcpListener};

fn main() {
    let port: u16 = std::env::var("PORT").map_or(0, |value| {
        value.parse().expect("PORT must be a port number")
    });
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind the fixture port");
    let base = format!("http://{}", listener.local_addr().expect("fixture address"));
    let _server = fixture::TestServer::serve(listener);

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{base}").expect("report the fixture URL");
    stdout.flush().expect("flush the fixture URL");

    loop {
        std::thread::park();
    }
}
