//! Runs the shared httpbin fixture (`zenwave-test-fixture`, the workspace
//! crate under `tests/fixture`) as a standalone process: the wasm and workerd
//! test lanes cannot share an in-process server, so they point
//! `ZENWAVE_TEST_BASE_URL` at the address this binary prints on stdout.

use std::io::Write as _;
use std::net::TcpListener;

use zenwave_test_fixture::TestServer;

fn main() {
    let port = std::env::var("ZENWAVE_TEST_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind the fixture port");
    let base = format!("http://{}", listener.local_addr().expect("fixture address"));
    let _server = TestServer::serve(listener);

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{base}").expect("report the fixture URL");
    stdout.flush().expect("flush the fixture URL");
}
