# Task Checklist: `localsend-daemon`

Track engineering deliverables across all architecture phases. Completed items are checked `[x]`.

---

## Phase 0: Workspace Scaffolding & Engineering Foundation
- [x] Git repository initialized with default branch `main`
- [x] Tailored `.gitignore` created for Rust binaries, IDE artifacts, and `.part` files
- [x] Root workspace `Cargo.toml` configured with resolver v2 and shared package metadata
- [x] Initial stub crates created with clean zero-warning builds:
  - [x] `crates/protocol` (`localsend-protocol` library)
  - [x] `crates/discovery` (`localsend-discovery` library)
  - [x] `crates/daemon` (`localsendd` binary)
  - [x] `crates/cli` (`lsend` binary)
- [x] Architectural roadmap documented in `ROADMAP.md`
- [x] Granular tracking checklist established in `TASKLIST.md`
- [x] Private GitHub repository created via `gh` and synced to `origin main`

---

## Phase 1: Protocol Wire Formats, Cryptographic Identity & Path Sanitization
### Subsystem: Protocol Models (`crates/protocol`)
- [x] Implement `DeviceType` enum (`mobile`, `desktop`, `web`, `headless`, `server`) with serde string mapping
- [x] Implement `ProtocolVersion` compatibility checks
- [x] Implement `MulticastAnnouncement` model for UDP beacon packets
- [x] Implement `RegisterDto` model for direct HTTP peer registration
- [x] Implement `PrepareUploadRequest` and `PrepareUploadResponse` models
- [x] Implement `FileDto` / `FileMetadata` model (file ID, fileName, size, fileType, sha256 hash, preview metadata)
- [x] Implement `UploadParams` query parser (`sessionId`, `fileId`, `token`)
- [x] Implement `InfoResponseDto` device information model
- [x] Comprehensive unit tests for JSON serialization and deserialization against official LocalSend fixtures

### Subsystem: Cryptographic Engine (`crates/protocol`)
- [x] RSA-2048 keypair generation using pure-Rust crypto (`rcgen` / `rsa`)
- [x] Self-signed X.509 v3 certificate generation with customizable SANs and Apple ATS 825-day validity
- [x] Canonical uppercase 64-hex SHA-256 fingerprint derivation from DER certificate
- [x] Constant-time fingerprint verification against side-channel timing attacks
- [x] PEM and DER serialization for certificates and PKCS#8 private keys
- [x] Unit tests verifying fingerprint derivation reproducibility and constant-time verification

### Subsystem: Filesystem Path Sanitization (`crates/protocol`)
- [x] Basename extractor rejecting directory traversal sequences (`..`, `/`, `\`, null bytes)
- [x] Windows DOS device filtering (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`)
- [x] Sanitization of forbidden characters (`<>:"/\|?*` and ASCII control chars `0x00-0x1F`)
- [x] Filename length limiter (255 bytes max with UTF-8 byte boundary awareness)
- [x] Collision avoidance mechanism: non-overwriting incremental naming (`filename (1).ext`)
- [x] Unit tests for cross-platform malicious path vectors (Unix traversal, Windows traversal, DOS device names)

---

## Phase 2: Dual-Path Discovery & Peer Registry
### Subsystem: Multicast UDP Engine (`crates/discovery`)
- [x] Multicast UDP socket initialization with `SO_REUSEADDR` / `SO_REUSEPORT` via `socket2`
- [x] Join multicast group `224.0.0.167` (and IPv6 `ff12::fd3a:e420`) on port `53317`
- [x] Network interface scanning, physical adapter eligibility filtering, and per-NIC binding
- [x] Multi-datagram initial announcement burst (0ms, 100ms, 500ms) and periodic idle heartbeat broadcaster
- [x] Continuous inbound announcement listener with zero-allocation stack screening
- [x] Self-echo packet suppression (filtering own fingerprint bytes before serde deserialization)
- [x] Graceful shutdown announcement broadcast

### Subsystem: Subnet HTTP Fallback Scanner (`crates/discovery`)
- [x] Local interface IP and subnet mask resolution, excluding virtual/VPN adapters
- [x] CIDR `/24` host range generator (skipping local IP)
- [x] Bounded-concurrency HTTP probing worker pool (64 concurrent permits via `reqwest`)
- [x] Probe `/api/localsend/v2/register` and `/api/localsend/v2/info` with strict 750ms timeout
- [x] Fallback trigger logic and peer auto-registration

### Subsystem: In-Memory Peer Registry (`crates/discovery`)
- [x] Thread-safe concurrent `PeerRegistry` actor (`tokio::sync::RwLock` + `tokio::sync::broadcast`)
- [x] Peer entry caching with alias, IP, port, device model, type, fingerprint, and protocol version
- [x] Background TTL reaper task to evict peers inactive for > 120 seconds
- [x] Tokio broadcast channel emitting peer arrival (`Discovered`), update (`Updated`), and departure (`Evicted`) events
- [x] Unit and mock tests for registry concurrency, updating, and expiration

---

## Phase 3: Headless HTTPS Receiver, Session Coordinator & Atomic IO
### Subsystem: Axum HTTPS Server (`crates/daemon`)
- [ ] Configure `rustls` server acceptor using generated self-signed TLS certificate and private key
- [ ] Axum router setup for `/api/localsend/v2/*` routes
- [ ] Implement `GET /api/localsend/v2/info` returning daemon metadata and capabilities
- [ ] Implement `POST /api/localsend/v2/register` handling inbound peer registration
- [ ] Implement `POST /api/localsend/v2/prepare-upload` evaluating upload requests
- [ ] Implement `POST /api/localsend/v2/upload` with raw streaming body extraction
- [ ] Implement `POST /api/localsend/v2/cancel` terminating active transfer sessions

### Subsystem: Dynamic Session Coordinator (`crates/daemon`)
- [ ] Single-session concurrency lock (rejecting concurrent transfer attempts with HTTP 409 Conflict)
- [ ] Ephemeral upload token generator per file in manifest
- [ ] Session validation middleware verifying `sessionId` and `token` on `/upload`
- [ ] Session lifecycle state machine: `PendingApproval -> InProgress -> Completed | Aborted`
- [ ] Idle and timeout session cleanup handlers

### Subsystem: Atomic Disk Streamer (`crates/daemon`)
- [ ] Chunked async body streaming directly to disk (`tokio::fs::File`, `tokio::io::BufWriter`)
- [ ] Staging file format: `<destination>/<sanitized_name>.part.<session_id>`
- [ ] Real-time streaming SHA-256 calculation
- [ ] Post-transfer hash verification against manifest hash (if supplied by sender)
- [ ] Atomic rename (`tokio::fs::rename`) from staging path to final destination upon success
- [ ] Automatic deletion of incomplete `.part` files on abort or network error
- [ ] Disk space pre-allocation checks before transfer acceptance

---

## Phase 4: Deterministic Policy Engine & Inter-Process Communication (IPC)
### Subsystem: Deterministic Policy Engine (`crates/daemon`)
- [ ] Inbound request policy evaluator
- [ ] CIDR subnet allowlist/blocklist rule engine
- [ ] Pinned TLS SHA-256 fingerprint allowlist/blocklist
- [ ] Trust-On-First-Use (TOFU) SQLite or JSON persistent trust store
- [ ] Auto-accept mode toggle (`--auto-accept` or interactive approval)

### Subsystem: Local IPC Server (`crates/daemon`)
- [ ] Platform-specific IPC transport:
  - [ ] Unix Domain Socket (`/run/localsend/daemon.sock` / `$XDG_RUNTIME_DIR/localsend.sock`) on Linux/Unix
  - [ ] Windows Named Pipe (`\\.\pipe\localsend-daemon`) on Windows
- [ ] Framed JSON-RPC protocol definition
- [ ] Daemon commands:
  - [ ] `status`: Retrieve daemon uptime, listening interfaces, active session
  - [ ] `peers`: List current active peers from registry
  - [ ] `accept`: Authorize pending transfer session
  - [ ] `reject`: Decline pending transfer session
  - [ ] `shutdown`: Graceful service termination
- [ ] Push event streaming: notify connected CLI clients of transfer progress and discovery events

---

## Phase 5: Scriptable CLI (`lsend`) & Rustls Fingerprint Pinning
### Subsystem: CLI Utility (`crates/cli`)
- [ ] Argument parsing via `clap` (derive mode)
- [ ] Subcommand `lsend scan`: Discover and list nearby peers with formatting
- [ ] Subcommand `lsend peers`: Query cached peers from running daemon
- [ ] Subcommand `lsend send <target> <files...>`:
  - [ ] Resolve target (IP address, hostname, or discovered peer alias)
  - [ ] Prepare file manifest and metadata
  - [ ] POST `/api/localsend/v2/prepare-upload`
  - [ ] Stream files with chunked HTTP POST
  - [ ] Multi-file transfer progress visualization via `indicatif`
- [ ] Subcommand `lsend status`: Display daemon operational status and active jobs
- [ ] Subcommand `lsend accept` / `lsend reject`: Interactively manage pending inbound transfers
- [ ] Standalone mode: ability for `lsend send` to execute direct peer-to-peer sends without daemon running

### Subsystem: Custom Rustls Fingerprint Verifier (`crates/cli` & `crates/daemon`)
- [ ] Implement custom `rustls::client::danger::ServerCertVerifier`
- [ ] Extract DER certificate bytes during TLS handshake
- [ ] Calculate SHA-256 digest and compare against expected uppercase 64-hex peer fingerprint
- [ ] Fallback TOFU validation for outbound transfers

---

## Phase 6: Systemd Hardening, Integration Verification & CI/CD
### Subsystem: Systemd Service Hardening
- [ ] Production-ready `localsend.service` systemd unit file
- [ ] Hardened security sandbox directives:
  - [ ] `DynamicUser=yes` (or unprivileged user)
  - [ ] `ProtectSystem=strict`
  - [ ] `ProtectHome=read-only`
  - [ ] `PrivateTmp=yes`
  - [ ] `NoNewPrivileges=yes`
  - [ ] `CapabilityBoundingSet=`
  - [ ] `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
  - [ ] `ReadWritePaths=/var/lib/localsend /downloads`
- [ ] Socket activation support (`localsend.socket`)

### Subsystem: Compatibility & Stress Testing
- [ ] End-to-end integration test suite against official LocalSend v2 clients
- [ ] Multi-gigabyte file transfer streaming verification
- [ ] Interrupted transfer recovery and staging cleanup tests
- [ ] High packet loss / unstable network discovery resilience

### Subsystem: CI/CD & Build Pipeline
- [ ] GitHub Actions workflow for automated testing (`cargo test`, `cargo check`)
- [ ] Zero-warning `cargo clippy` and `cargo fmt` enforcement
- [ ] Multi-architecture binary releases (Linux x86_64, aarch64, armv7, Windows x86_64, macOS universal)
- [ ] Semantic versioning and changelog automation
