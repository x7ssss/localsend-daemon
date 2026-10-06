//! LocalSend Command-Line Utility (`lsend`)

#![deny(unsafe_code)]

fn main() {
    println!("lsend v{}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cli_smoke() {
        assert!(true);
    }
}
