//! LocalSend Headless Daemon (`localsendd`)

#![deny(unsafe_code)]

fn main() {
    println!("localsendd v{}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_daemon_smoke() {
        assert!(true);
    }
}
