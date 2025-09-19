#!/usr/bin/env bash

set -euo pipefail

die() {
  echo "Error: $*" >&2
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

usage() {
  cat <<EOF
Usage: $0 [-v VERSION] [-f] [-V]

Downloads the run-mcp prebuilt binary archive for your OS/architecture,
verifies its checksum and signature using cosign, extracts the archive,
and installs the binary to /usr/local/bin.

Options:
  --version VERSION       Version to install (required, or set VERSION env var).
  -v, --verbose           Enable verbose debug logs (or set VERBOSE=1).
  -h, --help              Show this help.

Requirements:
  - wget or curl
  - cosign (optional; recommended for signature verification)
  - sha256sum (or shasum on macOS)
  - tar (for .tar.gz) or unzip (for .zip)

Example:
  $0                    # install latest
  $0 -v 0.0.3           # install specific version
EOF
}

VERSION_ARG=""
VERBOSE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION_ARG="$2"; shift 2;;
    -v|--verbose)
      VERBOSE=1; shift;;
    -h|--help)
      usage; exit 0;;
    *)
      die "Unknown argument: $1";;
  esac
done

VERSION="${VERSION_ARG:-}"

# Logging helpers.
log_debug() {
  if [[ "$VERBOSE" == "1" ]]; then
    echo "[DEBUG] $*" >&2
  fi
}
log_info() {
  echo "$*"
}

# Resolve latest version if not explicitly provided.
resolve_latest_version() {
  local latest="" json url headers loc
  if have_cmd curl; then
    json=$(curl -fsSL "https://api.github.com/repos/ensigniasec/run-mcp/releases/latest" || true)
    if [[ -n "$json" ]]; then
      latest=$(printf "%s" "$json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"v[^"]*"' | head -n1 | sed -E 's/.*"v([^\"]*)".*/\1/')
    fi
    if [[ -z "$latest" ]]; then
      url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/ensigniasec/run-mcp/releases/latest" || true)
      if [[ "$url" =~ /tag/v([0-9][^/]*)$ ]]; then
        latest="${BASH_REMATCH[1]}"
      fi
    fi
  elif have_cmd wget; then
    json=$(wget -qO- "https://api.github.com/repos/ensigniasec/run-mcp/releases/latest" || true)
    if [[ -n "$json" ]]; then
      latest=$(printf "%s" "$json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"v[^"]*"' | head -n1 | sed -E 's/.*"v([^\"]*)".*/\1/')
    fi
    if [[ -z "$latest" ]]; then
      headers=$(wget -q --server-response --max-redirect=0 "https://github.com/ensigniasec/run-mcp/releases/latest" -O /dev/null 2>&1 || true)
      loc=$(printf "%s" "$headers" | awk '/^  Location:|^Location:/ {print $2}' | tail -n1)
      if [[ "$loc" =~ /tag/v([0-9][^/]*)$ ]]; then
        latest="${BASH_REMATCH[1]}"
      fi
    fi
  fi
  if [[ -z "$latest" ]]; then
    die "Failed to resolve latest version. Specify with -v."
  fi
  printf "%s" "$latest"
}

if [[ -z "$VERSION" ]]; then
  VERSION="$(resolve_latest_version)"
fi
log_debug "Target version: v${VERSION}"

# Determine OS name.
wos=$(uname -s)
case "$wos" in
  Darwin)   OS=Darwin;  EXT=tar.gz ;;
  Linux)    OS=Linux;   EXT=tar.gz ;;
  MINGW*|MSYS*|CYGWIN*) OS=Windows; EXT=zip ;;
  *) die "Unsupported OS: $wos" ;;
esac

# Determine architecture.
warch=$(uname -m)
case "$warch" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  i386|i686) ARCH=i386 ;;
  *) die "Unsupported architecture: $warch" ;;
esac

ASSET="run-mcp_${OS}_${ARCH}.${EXT}"
BASE="https://github.com/ensigniasec/run-mcp/releases/download/v${VERSION}"
log_debug "Computed OS=$OS ARCH=$ARCH EXT=$EXT"
log_debug "Asset name: $ASSET"
log_debug "Base URL: $BASE"

# Check for cosign (optional).
if have_cmd cosign; then
  COSIGN_AVAILABLE=1
  log_debug "cosign found; will verify signatures."
else
  COSIGN_AVAILABLE=0
  log_info "cosign not found; skipping signature verification."
  log_info "Install cosign for verification: brew install cosign (macOS) or see https://docs.sigstore.dev/system_config/installation/."
fi

# Pick downloader.
download() {
  local url="$1" out="$2"
  if have_cmd wget; then
    log_debug "Downloading with wget: $url -> $out"
    wget -q -O "$out" "$url"
  elif have_cmd curl; then
    log_debug "Downloading with curl: $url -> $out"
    curl -fsSL "$url" -o "$out"
  else
    die "Neither wget nor curl is available."
  fi
}

log_info "Version: v${VERSION}"
log_info "OS: ${OS}"
log_info "Arch: ${ARCH}"
log_info "Asset: ${ASSET}"

log_info "Downloading ${ASSET} and checksums.txt ..."
download "${BASE}/${ASSET}" "${ASSET}"
download "${BASE}/checksums.txt" "checksums.txt"
log_debug "Downloaded files present: $(ls -1 ${ASSET} checksums.txt 2>/dev/null | tr '\n' ' ')"

if [[ "$COSIGN_AVAILABLE" == "1" ]]; then
  log_info "Verifying checksums.txt signature ..."
  log_debug "Cert: ${BASE}/checksums.txt.pem"
  log_debug "Sig:  ${BASE}/checksums.txt.sig"
  cosign verify-blob \
    --certificate-identity "https://github.com/ensigniasec/run-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --cert "${BASE}/checksums.txt.pem" \
    --signature "${BASE}/checksums.txt.sig" \
    ./checksums.txt
else
  log_debug "Skipping checksums.txt signature verification (cosign not available)."
fi

log_info "Validating archive checksum ..."
if have_cmd sha256sum; then
  # GNU coreutils style.
  sha256sum --ignore-missing -c checksums.txt
elif have_cmd shasum; then
  # macOS/BSD style: check only the target asset's line.
  grep -E "[[:space:]]${ASSET}$" checksums.txt | shasum -a 256 -c -
else
  die "Neither sha256sum nor shasum found. Install coreutils (macOS: 'brew install coreutils')."
fi

if [[ "$COSIGN_AVAILABLE" == "1" ]]; then
  log_info "Verifying ${ASSET} signature ..."
  log_debug "Cert: ${BASE}/${ASSET}.pem"
  log_debug "Sig:  ${BASE}/${ASSET}.sig"
  cosign verify-blob \
    --certificate-identity "https://github.com/ensigniasec/run-mcp/.github/workflows/release.yml@refs/tags/v${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --cert "${BASE}/${ASSET}.pem" \
    --signature "${BASE}/${ASSET}.sig" \
    "./${ASSET}"
  log_info "Signature verified for ${ASSET}."
else
  log_debug "Skipping ${ASSET} signature verification (cosign not available)."
fi

log_info "Extracting archive ..."
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
log_debug "Temporary directory: $tmpdir"

if [[ "$EXT" == "tar.gz" ]]; then
  have_cmd tar || die "tar is required to extract .tar.gz archives."
  log_debug "tar -xzf $ASSET -C $tmpdir"
  tar -xzf "$ASSET" -C "$tmpdir"
elif [[ "$EXT" == "zip" ]]; then
  have_cmd unzip || die "unzip is required to extract .zip archives."
  log_debug "unzip -o $ASSET -d $tmpdir"
  unzip -o "$ASSET" -d "$tmpdir" >/dev/null
else
  die "Unknown archive extension: $EXT"
fi

if [[ "$OS" == "Windows" ]]; then
  log_info "Windows archive extracted to $tmpdir. Please install manually on Windows."
  exit 0
fi

# Locate the run-mcp binary in the extracted contents.
BIN_PATH=""
if [[ -f "$tmpdir/run-mcp" ]]; then
  BIN_PATH="$tmpdir/run-mcp"
else
  BIN_PATH=$(find "$tmpdir" -type f -name 'run-mcp' | head -n 1 || true)
fi
[[ -n "$BIN_PATH" ]] || die "run-mcp binary not found in archive."
log_debug "Found binary at: $BIN_PATH"

chmod +x "$BIN_PATH" || true

DEST_DIR="/usr/local/bin"
DEST_BIN="$DEST_DIR/run-mcp"

log_info "Installing to $DEST_BIN ..."
if [[ -w "$DEST_DIR" ]]; then
  if have_cmd install; then
    log_debug "install -m 0755 $BIN_PATH $DEST_BIN"
    install -m 0755 "$BIN_PATH" "$DEST_BIN"
  else
    log_debug "cp $BIN_PATH $DEST_BIN && chmod 0755 $DEST_BIN"
    cp "$BIN_PATH" "$DEST_BIN"
    chmod 0755 "$DEST_BIN"
  fi
else
  if have_cmd sudo; then
    if have_cmd install; then
      log_debug "sudo install -m 0755 $BIN_PATH $DEST_BIN"
      sudo install -m 0755 "$BIN_PATH" "$DEST_BIN"
    else
      log_debug "sudo cp $BIN_PATH $DEST_BIN && sudo chmod 0755 $DEST_BIN"
      sudo cp "$BIN_PATH" "$DEST_BIN"
      sudo chmod 0755 "$DEST_BIN"
    fi
  else
    log_info "No write permission to $DEST_DIR and sudo not available."
    log_info "Leaving binary at: $BIN_PATH"
    log_info "Install manually, e.g.: sudo mv '$BIN_PATH' '$DEST_BIN'"
    exit 0
  fi
fi

log_info "Installed: $DEST_BIN"
if command -v run-mcp >/dev/null 2>&1; then
  printf "run-mcp version: "
  run-mcp --version || true
else
  log_info "Note: run-mcp not found on PATH. Ensure $DEST_DIR is in your PATH."
fi
