# localsend-daemon (`localsendd` + `lsend`)

A robust, headless LocalSend v2 protocol implementation written in Rust with Tokio and zero C-dependencies.

## Architectural Overview

`localsend-daemon` provides a cross-platform headless daemon and command-line client compatible with official LocalSend clients (Android, iOS, macOS, Windows, Linux).

```
localsend-daemon/
├── crates/
│   ├── protocol/    # Wire formats, JSON schemas, cryptographic identity, path sanitization
│   ├── discovery/   # Dual-path discovery (Multicast UDP 224.0.0.167:53317 + HTTP subnet fallback)
│   ├── daemon/      # localsendd headless service, Axum HTTPS receiver, session coordinator, IPC server
│   └── cli/         # lsend CLI utility and IPC client
├── ROADMAP.md       # Architectural roadmap across all 6 phases
└── TASKLIST.md      # Granular deliverable tracking checklist
```

## Workspace Crates

| Crate | Binary / Library | Description |
|---|---|---|
| `localsend-protocol` | Library | Protocol models, DTOs, RSA-2048/SHA-256 TLS cert generator, filename sanitizer |
| `localsend-discovery` | Library | Multicast UDP announcer/listener, subnet HTTP fallback scanner, peer cache |
| `localsend-daemon` | `localsendd` | Headless HTTPS server, dynamic session coordinator, atomic disk writer, policy engine, IPC listener |
| `localsend-cli` | `lsend` | Scriptable CLI client for sending files, querying peers, and managing daemon |

## Building & Testing

```bash
# Check workspace
cargo check

# Run tests
cargo test
```

## Documentation

- [Roadmap](ROADMAP.md)
- [Task List](TASKLIST.md)
