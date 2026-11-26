#!/usr/bin/env bash
# BrokenApp installer — curl -fsSL https://raw.githubusercontent.com/BrokenAppio/brokenapp/main/install.sh | bash
set -euo pipefail

REPO="${BROKENAPP_REPO:-BrokenAppio/brokenapp}"
BINARY="brokenapp"
INSTALL_DIR="${BROKENAPP_INSTALL_DIR:-/usr/local/bin}"

info()  { printf '\033[1;34m%s\033[0m\n' "$*"; }
error() { printf '\033[1;31mError: %s\033[0m\n' "$*" >&2; exit 1; }

# Detect OS
case "$(uname -s)" in
  Linux*)  OS="unknown-linux-gnu" ;;
  Darwin*) OS="apple-darwin" ;;
  MINGW*|MSYS*|CYGWIN*) error "Windows archives (.zip) are available on GitHub Releases, or build from source with 'cargo install --git https://github.com/${REPO}'" ;;
  *) error "Unsupported OS: $(uname -s)" ;;
esac

# Detect architecture
case "$(uname -m)" in
  x86_64|amd64)  ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *) error "Unsupported architecture: $(uname -m)" ;;
esac

TARGET="${ARCH}-${OS}"

# Resolve release tag (override with BROKENAPP_VERSION=vX.Y.Z)
TAG=""
if [ -n "${BROKENAPP_VERSION:-}" ]; then
  TAG="${BROKENAPP_VERSION}"
else
  info "Fetching latest release..."
  if command -v curl &>/dev/null; then
    LATEST_URL=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)
    if [[ "${LATEST_URL}" == */releases/tag/* ]]; then
      TAG="${LATEST_URL##*/releases/tag/}"
      TAG="${TAG%%\?*}"
    else
      TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4 || true)
    fi
  elif command -v wget &>/dev/null; then
    TAG=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4 || true)
  else
    error "curl or wget is required"
  fi
fi

if [ -z "${TAG:-}" ]; then
  error "Could not determine release tag. Check https://github.com/${REPO}/releases"
fi

ASSET="${BINARY}-${TAG}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

info "Downloading ${BINARY} ${TAG} for ${TARGET}..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

if command -v curl &>/dev/null; then
  curl -fsSL "${DOWNLOAD_URL}" -o "${TMPDIR}/${ASSET}"
  curl -fsSL "${CHECKSUM_URL}" -o "${TMPDIR}/${ASSET}.sha256" \
    || error "Could not download published checksum (${CHECKSUM_URL}); refusing to install unverified archive"
else
  wget -q "${DOWNLOAD_URL}" -O "${TMPDIR}/${ASSET}"
  wget -q "${CHECKSUM_URL}" -O "${TMPDIR}/${ASSET}.sha256" \
    || error "Could not download published checksum (${CHECKSUM_URL}); refusing to install unverified archive"
fi

info "Verifying SHA-256 checksum..."
EXPECTED_SHA=$(awk '{print $1}' "${TMPDIR}/${ASSET}.sha256" | head -n 1 | tr '[:upper:]' '[:lower:]')
if ! printf '%s' "${EXPECTED_SHA}" | grep -Eq '^[0-9a-f]{64}$'; then
  error "Invalid SHA-256 checksum format in ${CHECKSUM_URL}"
fi
if command -v sha256sum &>/dev/null; then
  ACTUAL_SHA=$(sha256sum "${TMPDIR}/${ASSET}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
elif command -v shasum &>/dev/null; then
  ACTUAL_SHA=$(shasum -a 256 "${TMPDIR}/${ASSET}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
else
  error "sha256sum or shasum is required to verify the release archive"
fi
if [ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]; then
  error "SHA-256 checksum mismatch for ${ASSET} (expected ${EXPECTED_SHA}, got ${ACTUAL_SHA})"
fi

info "Extracting..."
tar -xzf "${TMPDIR}/${ASSET}" -C "${TMPDIR}"

BIN_PATH=$(find "${TMPDIR}" -name "${BINARY}" -type f | head -1)
if [ -z "${BIN_PATH}" ]; then
  error "Binary not found in archive"
fi
chmod +x "${BIN_PATH}"

info "Installing to ${INSTALL_DIR}/${BINARY}..."
if mkdir -p "${INSTALL_DIR}" 2>/dev/null && [ -w "${INSTALL_DIR}" ]; then
  mv "${BIN_PATH}" "${INSTALL_DIR}/${BINARY}"
elif command -v sudo &>/dev/null; then
  sudo mkdir -p "${INSTALL_DIR}"
  sudo mv "${BIN_PATH}" "${INSTALL_DIR}/${BINARY}"
else
  error "Cannot write to ${INSTALL_DIR} and sudo is unavailable. Re-run with BROKENAPP_INSTALL_DIR=\"\$HOME/.local/bin\""
fi

info "Installed ${BINARY} ${TAG} to ${INSTALL_DIR}/${BINARY}"
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) info "Note: ${INSTALL_DIR} is not in your PATH. Add: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
echo ""
"${INSTALL_DIR}/${BINARY}" --version 2>/dev/null || true
echo ""
info "Run 'brokenapp doctor' to verify Chrome and your install, or 'brokenapp --help' to get started."
