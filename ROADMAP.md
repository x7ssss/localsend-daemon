# Architecture Roadmap: `localsend-daemon`

`localsend-daemon` is a headless, native Rust implementation of the [LocalSend v2 Protocol](https://github.com/localsend/localsend). It provides a background daemon (`localsendd`) and an ergonomic, scriptable CLI tool (`lsend`) designed for servers, headless workstations, and embedded Linux/BSD/Windows systems.

---

## 1. Architectural Philosophy & Constraints

1. **Zero C-Dependencies (Pure Rust)**:
   - Networking, TLS, and crypto primitives rely strictly on native Rust implementations (`tokio`, `rustls`, `rcgen`, `sha2`, `ring` / `aws-lc-rs`).
   - Ensures frictionless cross-compilation across x86_64, aarch64, armv7, and musl targets without external C library (`OpenSSL`, `glibc`) runtime dependencies.

2. **Strict Adherence to LocalSend Protocol v2**:
   - Bit-level and JSON-schema compatibility with official LocalSend iOS, Android, macOS, Windows, and Linux clients.
   - Dual-path peer discovery (Multicast UDP primary, HTTP subnet sweep fallback).
   - Self-signed RSA-2048 / SHA-256 TLS certificate exchange and fingerprint validation.

3. **Daemon / CLI Split with Local IPC**:
   - Headless background service (`localsendd`) manages long-lived UDP sockets, HTTPS listeners, active transfer state machines, and filesystem IO.
   - User-facing client (`lsend`) communicates with `localsendd` via local Unix Domain Sockets (`/run/localsend/daemon.sock`) or Windows Named Pipes (`\\.\pipe\localsend-daemon`).

4. **Security by Default & Hardened File IO**:
   - Zero-trust path sanitization: strict stripping of directory traversal characters (`..`, `/`, `\`), null bytes, Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), and hidden file prefixes.
   - Safe atomic writing: incoming files are streamed into isolated `.part` files, verified with rolling SHA-256 hashes, and atomically renamed only upon complete integrity verification.
   - Conflict resolution avoiding data overwrite (`filename (1).ext`).
   - Granular inbound policy engine (TOFU, subnet CIDR allowlists, fingerprint pinning, or manual interactive authorization).

---

## 2. Workspace Crate Architecture

```
                                    +--------------------+
                                    |     lsend (CLI)    |
                                    +---------+----------+
                                              |
                                     (Local IPC / UDS)
                                              |
                                              v
+-----------------------+           +---------+----------+
|  localsend-discovery  |<--------->| localsendd (Daemon)|
|  - Multicast 53317    |           | - Axum HTTPS Engine|
|  - Subnet HTTP Probe  |           | - Session State    |
|  - Peer Cache         |           | - Policy / Storage |
+-----------+-----------+           +---------+----------+
            |                                 |
            +----------------+  +-------------+
                             |  |
                             v  v
                    +--------+-----------+
                    | localsend-protocol |
                    | - Wire DTOs        |
                    | - TLS & Crypto     |
                    | - Path Sanitation  |
                    +--------------------+
```

### Crate Responsibilities

1. **`localsend-protocol`** (`crates/protocol`):
   - LocalSend v2 wire formats, JSON serialization/deserialization DTOs.
   - Cryptographic engine: RSA-2048 keypair generation, self-signed X.509 v3 certificate generation, and canonical SHA-256 uppercase 64-hex fingerprint derivation.
   - Path traversal prevention, reserved filename stripping, and filename disambiguation algorithms.

2. **`localsend-discovery`** (`crates/discovery`):
   - Multicast UDP engine on `224.0.0.167:53317` with `SO_REUSEADDR` / `SO_REUSEPORT`.
   - Outbound multicast beacon broadcast and continuous inbound announcement listener.
   - Self-packet suppression filtering own node ID and fingerprints.
   - Network interface enumeration and binding.
   - Fallback HTTP subnet scanner: bounded concurrency sweep of local subnets (`/24`) probing `/api/localsend/v2/info` or `register`.
   - In-memory thread-safe peer registry with TTL expiration and update events.

3. **`localsend-daemon`** (`crates/daemon` - `localsendd`):
   - Axum-based HTTPS server running on port `53317` powered by `rustls`.
   - Implements `/api/localsend/v2/info`, `/api/localsend/v2/register`, `/api/localsend/v2/prepare-upload`, `/api/localsend/v2/upload`, and `/api/localsend/v2/cancel`.
   - Session coordinator: single-session concurrency lock, session ID validation, file token tracking.
   - Streaming disk writer: chunked body streaming to `.part` files, streaming SHA-256 hashing, atomic rename.
   - Policy engine: CIDR filter, fingerprint allowlist/denylist, Trust-On-First-Use (TOFU) database.
   - IPC server: Unix Domain Socket / Named Pipe handling CLI commands and streaming transfer progress.

4. **`localsend-cli`** (`crates/cli` - `lsend`):
   - Command-line interface with subcommands: `scan`, `peers`, `send`, `status`, `accept`, `reject`, `config`.
   - Custom `rustls` certificate verifier for outbound file transfers that validates the receiver's TLS certificate strictly against their announced SHA-256 fingerprint.
   - Dynamic terminal progress bars (via `indicatif`) for multi-file transfers.

---

## 3. Implementation Phases

### Phase 1: Protocol Wire Formats, Self-Signed RSA-2048/SHA-256 TLS, and Basename Sanitization
- **LocalSend v2 DTOs**:
  - `MulticastAnnouncement`: JSON payload for UDP broadcasts (`alias`, `version`, `deviceModel`, `deviceType`, `fingerprint`, `port`, `protocol`, `download`, `announcement`).
  - `RegisterDto`: Direct HTTP registration exchange payload.
  - `PrepareUploadRequest`: Manifest metadata detailing files to be sent (`info`, `files`).
  - `FileDto`: Unique file ID, file name, size, file type, SHA-256 hash (optional preview/metadata).
  - `PrepareUploadResponse`: Acceptance state and per-file upload tokens.
  - `InfoResponseDto`: Server capabilities and identity information.
- **TLS & Cryptographic Engine**:
  - Generation of ephemeral or persistent RSA-2048 private keys and self-signed X.509 v3 certificates valid for 10+ years using `rcgen`.
  - Canonical SHA-256 fingerprint generation: SHA-256 digest of DER-encoded certificate formatted as uppercase hexadecimal string with no separators (64 characters).
- **Basename Sanitization & Path Defense**:
  - Strip directory paths (`../`, `..\`, `/`, `\`).
  - Sanitize illegal filesystem characters (`<>:"/\|?*` and ASCII control chars `0x00-0x1F`).
  - Normalize Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`).
  - Truncate long filenames within OS limits (255 bytes).
  - Auto-disambiguate collisions: generate `sample (1).txt`, `sample (2).txt` if target exists.

### Phase 2: Dual-Path Discovery & Peer Registry
- **Multicast Discovery**:
  - Bind UDP socket to `0.0.0.0:53317` (IPv4) with multicast group join `224.0.0.167`.
  - Platform-specific socket configuration (`SO_REUSEADDR`, `SO_REUSEPORT` via `socket2`).
  - Periodic announcement emission and on-demand trigger upon startup/network change.
  - Inbound packet parsing and self-echo suppression.
- **Fallback HTTP Subnet Sweep**:
  - Inspect active local network interfaces (e.g., `192.168.1.0/24`).
  - Bounded concurrency worker pool (e.g., 32-64 workers) issuing fast HTTP `GET /api/localsend/v2/info` or `POST /api/localsend/v2/register` with low timeout (500ms).
- **Peer Registry**:
  - `PeerRegistry` actor storing active peers keyed by fingerprint/IP.
  - Time-to-Live (TTL) eviction for stale peers (default: 60s).
  - Broadcast channel for peer discovery/departure notifications to CLI and daemon.

### Phase 3: Headless HTTPS Receiver, Dynamic Session Coordinator, and Atomic Stream-to-Disk
- **HTTPS Axum Receiver**:
  - Rustls server configuration using generated self-signed certificate and private key.
  - Endpoints:
    - `GET /api/localsend/v2/info`: Device metadata, alias, fingerprint.
    - `POST /api/localsend/v2/register`: Peer registration.
    - `POST /api/localsend/v2/prepare-upload`: Manifest evaluation, auto-accept or prompt trigger, token issuance.
    - `POST /api/localsend/v2/upload`: Token-authenticated binary stream receiver.
    - `POST /api/localsend/v2/cancel`: Abort in-flight transfer.
- **Dynamic Session Coordinator**:
  - Concurrency lock: allow one active session at a time (or queue configurable sessions).
  - Generate ephemeral upload tokens for each file listed in `PrepareUploadRequest`.
  - Session timeout and cleanup handling on disconnect or idle state.
- **Atomic Disk Writer**:
  - Stream chunks directly to staging files named `<target>.part.<session-id>`.
  - Compute running SHA-256 hash in parallel with writing chunks.
  - Upon upload completion, compare hash against manifest (if provided).
  - Atomically rename staging file to final sanitized destination path.
  - Automatic cleanup of leftover `.part` files on abort or failure.

### Phase 4: Deterministic Policy Engine & IPC
- **Policy Engine**:
  - Deterministic evaluation order:
    1. Subnet CIDR whitelist/blacklist (e.g., allow `192.168.1.0/24`, deny others).
    2. Pinned TLS SHA-256 fingerprint whitelist.
    3. Trust-On-First-Use (TOFU) trust store.
    4. Auto-accept flag (`--auto-accept` or interactive IPC prompt).
- **Inter-Process Communication (IPC)**:
  - Unix Domain Socket at `/run/localsend/daemon.sock` (or `$XDG_RUNTIME_DIR/localsend.sock`).
  - Windows Named Pipe: `\\.\pipe\localsend-daemon`.
  - Length-delimited JSON-RPC framing for commands (`status`, `peers`, `send`, `accept-session`, `reject-session`, `shutdown`).
  - Event streaming from daemon to connected CLI sessions.

### Phase 5: Scriptable CLI (`lsend`) & Rustls Fingerprint Pinning
- **Command-Line Interface**:
  - `lsend scan`: Display discovered peers with alias, IP, device type, fingerprint, and latency.
  - `lsend send <target-ip-or-alias> <files...>`: Prepare upload, initiate HTTPS requests, stream files with progress bars.
  - `lsend status`: Check daemon health, listening ports, active downloads/uploads.
  - `lsend config`: Inspect and modify daemon runtime parameters.
- **Custom Rustls Certificate Verifier**:
  - Custom `ServerCertVerifier` implementation in Rustls.
  - Matches the DER certificate's SHA-256 fingerprint against the target peer's announced fingerprint.
  - Bypasses traditional public WebPKI roots without disabling cryptographic verification.

### Phase 6: Systemd Hardening, Verification, and CI/CD
- **Systemd Unit Hardening**:
  - Production service definition `localsend.service`.
  - Security hardening directives:
    - `DynamicUser=yes`
    - `ProtectSystem=strict`
    - `ProtectHome=read-only`
    - `PrivateTmp=yes`
    - `NoNewPrivileges=yes`
    - `CapabilityBoundingSet=`
    - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
- **End-to-End Compatibility Testing**:
  - Integration testing with real LocalSend clients across network configurations.
  - Multi-gigabyte file transfer streaming tests.
  - High concurrency stress tests.
- **Automated CI/CD**:
  - GitHub Actions matrix testing (Linux x86_64/aarch64, Windows, macOS).
  - Clippy and formatting checks with zero warnings tolerance.
  - Release binaries built with LTO, stripped symbols, and minimal size.
