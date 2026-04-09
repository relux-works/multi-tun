#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST_OS="$(uname -s)"
HOST_ARCH_RAW="$(uname -m)"

PROJECT_NAME="multi-tun"
VLESS_CLI_NAME="vless-tun"
OPENCONNECT_CLI_NAME="openconnect-tun"
DUMP_CLI_NAME="dump"
CISCO_DUMP_COMPAT_NAME="cisco-dump"
VPN_CORE_CLI_NAME="vpn-core"
ANDROID_RELEASE_CLI_NAME="android-release"
VPN_AUTH_CLI_NAME="vpn-auth"
VPN_AUTH_PACKAGE_DIR="$PROJECT_ROOT/desktop/cmd/vpn-auth"

BIN_DIR="$HOME/.local/bin"
GLOBAL_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/vless-tun"
GLOBAL_CONFIG_PATH="$GLOBAL_CONFIG_DIR/config.json"
LEGACY_CONFIG_PATH="$PROJECT_ROOT/configs/local.json"
EXAMPLE_CONFIG_PATH="$PROJECT_ROOT/configs/local.example.json"
RELEASES_DIR="$PROJECT_ROOT/artifacts/releases"

usage() {
  cat <<'EOF'
Usage: ./scripts/setup.sh [--mac-arch host|arm64|amd64]

Defaults to a full host-native setup on macOS.

Options:
  --mac-arch host     Build for the current macOS host architecture (default)
  --mac-arch arm64    Build macOS Apple Silicon artifacts
  --mac-arch amd64    Build macOS Intel artifacts

When a non-host macOS architecture is requested, setup switches to artifact-only
cross-build mode:
  - desktop binaries are written to artifacts/releases/
  - ~/.local/bin links are not changed
  - tool installation and config wiring are skipped
EOF
}

normalize_mac_arch() {
  local value="$1"
  case "$value" in
    host|auto)
      printf '%s\n' "$HOST_MAC_ARCH"
      ;;
    arm64|aarch64)
      printf 'arm64\n'
      ;;
    amd64|x86_64)
      printf 'amd64\n'
      ;;
    *)
      return 1
      ;;
  esac
}

build_output_path() {
  local binary_name="$1"
  if [[ "$CROSS_BUILD_ONLY" == "1" ]]; then
    printf '%s/%s-%s\n' "$RELEASES_DIR" "$binary_name" "$TARGET_TRIPLE"
  else
    printf '%s/%s\n' "$PROJECT_ROOT" "$binary_name"
  fi
}

go_build_desktop_binary() {
  local output_path="$1"
  local package_path="$2"
  if [[ "$HOST_OS" == "Darwin" && -n "${TARGET_GOARCH:-}" ]]; then
    if [[ "$CROSS_BUILD_ONLY" == "1" ]]; then
      CGO_ENABLED=0 GOOS=darwin GOARCH="$TARGET_GOARCH" go build -o "$output_path" "$package_path"
    else
      GOOS=darwin GOARCH="$TARGET_GOARCH" go build -o "$output_path" "$package_path"
    fi
  else
    go build -o "$output_path" "$package_path"
  fi
}

HOST_MAC_ARCH=""
if [[ "$HOST_OS" == "Darwin" ]]; then
  case "$HOST_ARCH_RAW" in
    arm64|aarch64)
      HOST_MAC_ARCH="arm64"
      ;;
    x86_64|amd64)
      HOST_MAC_ARCH="amd64"
      ;;
    *)
      echo "  ERROR: unsupported macOS host architecture: $HOST_ARCH_RAW"
      exit 1
      ;;
  esac
fi

REQUESTED_MAC_ARCH="host"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mac-arch)
      if [[ $# -lt 2 ]]; then
        echo "  ERROR: --mac-arch requires one of: host, arm64, amd64"
        usage
        exit 1
      fi
      REQUESTED_MAC_ARCH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "  ERROR: unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

TARGET_MAC_ARCH=""
TARGET_GOARCH=""
TARGET_TRIPLE=""
CROSS_BUILD_ONLY="0"
if [[ "$HOST_OS" == "Darwin" ]]; then
  TARGET_MAC_ARCH="$(normalize_mac_arch "$REQUESTED_MAC_ARCH")" || {
    echo "  ERROR: unsupported --mac-arch value: $REQUESTED_MAC_ARCH"
    usage
    exit 1
  }
  TARGET_GOARCH="$TARGET_MAC_ARCH"
  TARGET_TRIPLE="darwin-$TARGET_GOARCH"
  if [[ "$TARGET_MAC_ARCH" != "$HOST_MAC_ARCH" ]]; then
    CROSS_BUILD_ONLY="1"
  fi
elif [[ "$REQUESTED_MAC_ARCH" != "host" && "$REQUESTED_MAC_ARCH" != "auto" ]]; then
  echo "  ERROR: --mac-arch is only supported on macOS hosts for now"
  exit 1
fi

echo "=== $PROJECT_NAME Setup ==="
if [[ "$HOST_OS" == "Darwin" ]]; then
  echo "  Host macOS arch   -> $HOST_MAC_ARCH"
  echo "  Target macOS arch -> $TARGET_MAC_ARCH"
  if [[ "$CROSS_BUILD_ONLY" == "1" ]]; then
    echo "  Mode              -> cross-build artifacts only"
  else
    echo "  Mode              -> full host-native setup"
  fi
fi

ensure_brew_formula() {
  local formula="$1"
  local binary="${2:-$1}"
  if command -v "$binary" >/dev/null 2>&1; then
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    echo "Installing $formula..."
    brew install "$formula"
  else
    echo "  WARNING: $binary is not installed and Homebrew was not found"
  fi
}

ensure_pipx_package() {
  local package="$1"
  local binary="${2:-$1}"
  if command -v "$binary" >/dev/null 2>&1; then
    return 0
  fi
  if command -v pipx >/dev/null 2>&1; then
    echo "Installing $package..."
    pipx install "$package" || pipx upgrade "$package" || true
  else
    echo "  WARNING: $binary is not installed because pipx is unavailable"
  fi
}

require_swift() {
  if command -v swift >/dev/null 2>&1; then
    return 0
  fi
  echo "  ERROR: swift is not installed; install Xcode Command Line Tools before running setup so vpn-auth can be built"
  exit 1
}

resolve_swift_release_binary() {
  local package_dir="$1"
  local binary_name="$2"
  local release_path="$package_dir/.build/release/$binary_name"
  if [[ -x "$release_path" ]]; then
    printf '%s\n' "$release_path"
    return 0
  fi

  release_path="$(find "$package_dir/.build" -path "*/release/$binary_name" -type f -perm -111 2>/dev/null | head -n 1 || true)"
  if [[ -n "$release_path" ]]; then
    printf '%s\n' "$release_path"
    return 0
  fi

  return 1
}

if [[ "$CROSS_BUILD_ONLY" != "1" ]]; then
  ensure_brew_formula ripgrep rg
  ensure_brew_formula pipx pipx
  ensure_brew_formula sing-box sing-box
  ensure_brew_formula openconnect openconnect
  ensure_brew_formula oath-toolkit oathtool
  ensure_brew_formula totp-cli totp-cli

  require_swift

  if ! command -v python3 >/dev/null 2>&1; then
    ensure_brew_formula python python3
  fi

  ensure_pipx_package vpn-slice vpn-slice

  if ! command -v security >/dev/null 2>&1; then
    echo "  WARNING: macOS security CLI is not available; keychain-backed openconnect setup will not work"
  fi
fi

echo "Building $VLESS_CLI_NAME binary..."
cd "$PROJECT_ROOT"
VLESS_OUTPUT_PATH="$(build_output_path "$VLESS_CLI_NAME")"
OPENCONNECT_OUTPUT_PATH="$(build_output_path "$OPENCONNECT_CLI_NAME")"
DUMP_OUTPUT_PATH="$(build_output_path "$DUMP_CLI_NAME")"
VPN_CORE_OUTPUT_PATH="$(build_output_path "$VPN_CORE_CLI_NAME")"
ANDROID_RELEASE_OUTPUT_PATH="$(build_output_path "$ANDROID_RELEASE_CLI_NAME")"
VPN_AUTH_OUTPUT_PATH="$(build_output_path "$VPN_AUTH_CLI_NAME")"
if [[ "$CROSS_BUILD_ONLY" == "1" ]]; then
  mkdir -p "$RELEASES_DIR"
fi

go_build_desktop_binary "$VLESS_OUTPUT_PATH" ./desktop/cmd/vless-tun/
echo "Building $OPENCONNECT_CLI_NAME binary..."
go_build_desktop_binary "$OPENCONNECT_OUTPUT_PATH" ./desktop/cmd/openconnect-tun/
echo "Building $DUMP_CLI_NAME binary..."
go_build_desktop_binary "$DUMP_OUTPUT_PATH" ./desktop/cmd/dump/
echo "Building $VPN_CORE_CLI_NAME binary..."
go_build_desktop_binary "$VPN_CORE_OUTPUT_PATH" ./desktop/cmd/vpn-core/
echo "Building $ANDROID_RELEASE_CLI_NAME binary..."
go_build_desktop_binary "$ANDROID_RELEASE_OUTPUT_PATH" ./android/ops/cmd/android-release/

if [[ "$CROSS_BUILD_ONLY" == "1" ]]; then
  cp "$DUMP_OUTPUT_PATH" "$(build_output_path "$CISCO_DUMP_COMPAT_NAME")"
  echo "Cross-build artifacts:"
  echo "  $VLESS_OUTPUT_PATH"
  echo "  $OPENCONNECT_OUTPUT_PATH"
  echo "  $DUMP_OUTPUT_PATH"
  echo "  $(build_output_path "$CISCO_DUMP_COMPAT_NAME")"
  echo "  $VPN_CORE_OUTPUT_PATH"
  echo "  $ANDROID_RELEASE_OUTPUT_PATH"
  echo
  echo "Cross-arch mode intentionally skips:"
  echo "  ~/.local/bin installation"
  echo "  config wiring"
  echo "  vpn-auth Swift helper build"
  echo
  echo "Use host-native setup on the destination Mac to install the full toolchain there."
  exit 0
fi

echo "Building $VPN_AUTH_CLI_NAME binary..."
swift build -c release --package-path "$VPN_AUTH_PACKAGE_DIR"
VPN_AUTH_RELEASE_BIN="$(resolve_swift_release_binary "$VPN_AUTH_PACKAGE_DIR" "$VPN_AUTH_CLI_NAME")" || {
  echo "  ERROR: built $VPN_AUTH_CLI_NAME binary was not found under $VPN_AUTH_PACKAGE_DIR/.build"
  exit 1
}
cp "$VPN_AUTH_RELEASE_BIN" "$VPN_AUTH_OUTPUT_PATH"
chmod +x "$VPN_AUTH_OUTPUT_PATH"

mkdir -p "$BIN_DIR"
ln -sf "$VLESS_OUTPUT_PATH" "$BIN_DIR/$VLESS_CLI_NAME"
ln -sf "$OPENCONNECT_OUTPUT_PATH" "$BIN_DIR/$OPENCONNECT_CLI_NAME"
ln -sf "$DUMP_OUTPUT_PATH" "$BIN_DIR/$DUMP_CLI_NAME"
ln -sf "$DUMP_OUTPUT_PATH" "$BIN_DIR/$CISCO_DUMP_COMPAT_NAME"
ln -sf "$VPN_CORE_OUTPUT_PATH" "$BIN_DIR/$VPN_CORE_CLI_NAME"
ln -sf "$ANDROID_RELEASE_OUTPUT_PATH" "$BIN_DIR/$ANDROID_RELEASE_CLI_NAME"
ln -sf "$VPN_AUTH_OUTPUT_PATH" "$BIN_DIR/$VPN_AUTH_CLI_NAME"
echo "  Binary -> $BIN_DIR/$VLESS_CLI_NAME"
echo "  Binary -> $BIN_DIR/$OPENCONNECT_CLI_NAME"
echo "  Binary -> $BIN_DIR/$DUMP_CLI_NAME"
echo "  Alias  -> $BIN_DIR/$CISCO_DUMP_COMPAT_NAME"
echo "  Binary -> $BIN_DIR/$VPN_CORE_CLI_NAME"
echo "  Binary -> $BIN_DIR/$ANDROID_RELEASE_CLI_NAME"
echo "  Binary -> $BIN_DIR/$VPN_AUTH_CLI_NAME"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "  WARNING: $BIN_DIR is not in your PATH"
fi

mkdir -p "$GLOBAL_CONFIG_DIR"
if [[ -f "$LEGACY_CONFIG_PATH" && ! -f "$GLOBAL_CONFIG_PATH" ]]; then
  mv "$LEGACY_CONFIG_PATH" "$GLOBAL_CONFIG_PATH"
  echo "  Moved config -> $GLOBAL_CONFIG_PATH"
elif [[ ! -f "$GLOBAL_CONFIG_PATH" ]]; then
  cp "$EXAMPLE_CONFIG_PATH" "$GLOBAL_CONFIG_PATH"
  echo "  Created example config -> $GLOBAL_CONFIG_PATH"
else
  echo "  Config -> $GLOBAL_CONFIG_PATH"
fi

echo
echo "Done. Installed $(git -C "$PROJECT_ROOT" describe --tags --always 2>/dev/null || echo 'unknown')"
echo
echo "Next steps:"
echo "  edit $GLOBAL_CONFIG_PATH"
echo "  $VLESS_CLI_NAME setup --source-url 'vless://...'"
echo "  $VLESS_CLI_NAME refresh"
echo "  $VLESS_CLI_NAME render"
echo "  $VPN_CORE_CLI_NAME install"
echo "  $ANDROID_RELEASE_CLI_NAME setup"
echo "  $OPENCONNECT_CLI_NAME setup --vpn-name 'Corp VPN'"
echo "  $OPENCONNECT_CLI_NAME inspect-profiles"
echo "  $DUMP_CLI_NAME start"
