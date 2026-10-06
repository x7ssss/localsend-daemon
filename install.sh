#!/usr/bin/env sh
set -eu

# Color output helpers (if terminal attached)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    BLUE=''
    YELLOW=''
    BOLD=''
    RESET=''
fi

info() {
    printf "${BLUE}${BOLD}[INFO]${RESET} %s\n" "$*"
}

success() {
    printf "${GREEN}${BOLD}[OK]${RESET} %s\n" "$*"
}

warn() {
    printf "${YELLOW}${BOLD}[WARN]${RESET} %s\n" "$*"
}

error() {
    printf "${RED}${BOLD}[ERROR]${RESET} %s\n" "$*" >&2
}

fatal() {
    error "$*"
    exit 1
}

# Privilege escalation helper
run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        fatal "Root privileges required to execute: $*"
    fi
}

info "Installing LocalSend Headless Transfer Daemon (localsendd) and CLI (lsend)..."

# 1. Detect Host OS
OS_RAW="$(uname -s)"
case "$OS_RAW" in
    Linux*)
        OS="linux"
        ;;
    Darwin*)
        OS="apple-darwin"
        ;;
    *)
        fatal "Unsupported operating system: $OS_RAW. Supported systems: Linux, macOS."
        ;;
esac

# 2. Detect Host Architecture
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64)
        ARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
    *)
        fatal "Unsupported CPU architecture: $ARCH_RAW. Supported architectures: x86_64, aarch64/arm64."
        ;;
esac

# 3. Determine target triple
if [ "$OS" = "linux" ]; then
    TARGET="${ARCH}-unknown-linux-musl"
else
    TARGET="${ARCH}-apple-darwin"
fi

info "Detected environment: OS=$OS, Arch=$ARCH, Target=$TARGET"

# 4. Resolve Release Version/Tag
REPO="x7ssss/localsend-daemon"
VERSION="${1:-}"

if [ -n "$VERSION" ]; then
    case "$VERSION" in
        v*) TAG="$VERSION" ;;
        *)  TAG="v$VERSION" ;;
    esac
    info "Using requested release version: $TAG"
else
    info "Resolving latest release tag from GitHub..."
    LATEST_JSON=$(curl -sSL -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)
    TAG=$(printf '%s' "$LATEST_JSON" | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d '"' -f 4 || true)
    if [ -z "$TAG" ]; then
        TAG="v0.1.0"
        warn "Could not resolve latest release via GitHub API (likely rate limited). Falling back to $TAG."
    else
        info "Latest release identified: $TAG"
    fi
fi

# 5. Download Release Archive
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'localsend-install')"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/localsend-daemon-${TARGET}.tar.gz"
info "Downloading release from $DOWNLOAD_URL ..."

if ! curl -fSL "$DOWNLOAD_URL" -o "$TMP_DIR/archive.tar.gz" 2>/dev/null; then
    # Fallback to alternate archive naming patterns if needed
    ALT_URL="https://github.com/${REPO}/releases/download/${TAG}/localsendd-${TARGET}.tar.gz"
    info "Trying alternate asset path: $ALT_URL ..."
    if ! curl -fSL "$ALT_URL" -o "$TMP_DIR/archive.tar.gz"; then
        fatal "Failed to download release archive for target $TARGET from $DOWNLOAD_URL."
    fi
fi

# 6. Extract Binaries
info "Extracting binaries..."
tar -xzf "$TMP_DIR/archive.tar.gz" -C "$TMP_DIR"

LOCAL_LOCALSENDD="$(find "$TMP_DIR" -type f -name "localsendd" | head -n 1)"
LOCAL_LSEND="$(find "$TMP_DIR" -type f -name "lsend" | head -n 1)"

if [ -z "$LOCAL_LOCALSENDD" ]; then
    fatal "Archive does not contain 'localsendd' binary."
fi

# 7. Install to /usr/local/bin
INSTALL_DIR="/usr/local/bin"
info "Installing executables to $INSTALL_DIR/ ..."
run_as_root install -d -m 755 "$INSTALL_DIR"
run_as_root install -m 755 "$LOCAL_LOCALSENDD" "$INSTALL_DIR/localsendd"

if [ -n "$LOCAL_LSEND" ]; then
    run_as_root install -m 755 "$LOCAL_LSEND" "$INSTALL_DIR/lsend"
fi

success "Installed localsendd and lsend to $INSTALL_DIR"

# 8. Configure Systemd Service on Linux (if applicable)
if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    info "Detected systemd init system. Configuring localsendd.service..."

    # Ensure unprivileged system user exists
    if ! id -u localsend >/dev/null 2>&1; then
        info "Creating system user 'localsend'..."
        run_as_root useradd -r -s /usr/sbin/nologin -d /var/lib/localsend localsend || true
    fi

    # Ensure state and config directories exist
    run_as_root mkdir -p /var/lib/localsend /etc/localsendd /run/localsend
    run_as_root chown -R localsend:localsend /var/lib/localsend /run/localsend || true

    # Fetch and install service file
    SERVICE_URL="https://raw.githubusercontent.com/${REPO}/${TAG}/packaging/systemd/localsendd.service"
    SERVICE_DEST="/etc/systemd/system/localsendd.service"
    
    if curl -fsSL "$SERVICE_URL" -o "$TMP_DIR/localsendd.service" 2>/dev/null; then
        run_as_root cp "$TMP_DIR/localsendd.service" "$SERVICE_DEST"
        run_as_root chmod 644 "$SERVICE_DEST"
        run_as_root systemctl daemon-reload
        success "Installed systemd unit to $SERVICE_DEST"
    else
        warn "Could not fetch localsendd.service from repository. Skipping systemd service installation."
    fi
fi

# 9. Quick Start Banner
printf "\n"
printf "${GREEN}${BOLD}================================================================${RESET}\n"
printf "${GREEN}${BOLD}   LocalSend Daemon & CLI installed successfully (${TAG})       ${RESET}\n"
printf "${GREEN}${BOLD}================================================================${RESET}\n"
printf "\n"
printf "Binaries installed:\n"
printf "  • %s/localsendd (Headless Transfer Daemon)\n" "$INSTALL_DIR"
if [ -n "$LOCAL_LSEND" ]; then
    printf "  • %s/lsend      (Command-Line Interface)\n" "$INSTALL_DIR"
fi
printf "\n"
printf "${BOLD}Quick Start Guide:${RESET}\n"
if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    printf "  1. Start daemon via systemd: sudo systemctl enable --now localsendd\n"
    printf "  2. Or run manually:          localsendd --save-dir /srv/incoming --auto-accept trusted-only\n"
else
    printf "  1. Start daemon manually:    localsendd --save-dir ~/Downloads --auto-accept trusted-only\n"
fi
printf "  2. Discover peers on LAN:    lsend scan\n"
printf "  3. Send files to a peer:     lsend send <PEER_IP> <FILE_PATH>\n"
printf "  4. Stream real-time events:  lsend watch\n"
printf "\n"
