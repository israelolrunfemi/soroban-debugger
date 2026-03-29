use std::net::TcpListener;

/// Checks if the current environment allows binding to a local port.
/// Returns true if loopback networking is available.
pub fn can_bind_loopback() -> bool {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(_) => true,
        Err(e) => {
            eprintln!("⚠️ Loopback networking restricted: {}", e);
            false
        }
    }
}

/// Allocate an ephemeral available port by binding to 0 and reading the assigned value.
/// The temporary listener is dropped after determining the port so it can be re-used.
/// This reduces brittle fixed-port usage in integration tests.
pub fn allocate_ephemeral_port() -> Option<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    listener.local_addr().ok().map(|addr| addr.port())
}
