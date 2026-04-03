#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SKILL_NAME="vpn-config"
PROJECT_NAME="multi-tun"
SKILL_CONTENT_DIR="$PROJECT_ROOT/agents/skills/$SKILL_NAME"
VLESS_CLI_NAME="vless-tun"
OPENCONNECT_CLI_NAME="openconnect-tun"
DUMP_CLI_NAME="dump"
CISCO_DUMP_COMPAT_NAME="cisco-dump"
VPN_CORE_CLI_NAME="vpn-core"
VPN_AUTH_CLI_NAME="vpn-auth"
VPN_AUTH_PACKAGE_DIR="$PROJECT_ROOT/cmd/vpn-auth"

AGENTS_DIR="$HOME/.agents/skills"
GLOBAL_SKILL_DIR="$AGENTS_DIR/$SKILL_NAME"
CLAUDE_DIR="$HOME/.claude/skills"
CODEX_DIR="$HOME/.codex/skills"
BIN_DIR="$HOME/.local/bin"
GLOBAL_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/vless-tun"
GLOBAL_CONFIG_PATH="$GLOBAL_CONFIG_DIR/config.json"
LEGACY_CONFIG_PATH="$PROJECT_ROOT/configs/local.json"
EXAMPLE_CONFIG_PATH="$PROJECT_ROOT/configs/local.example.json"
LOCAL_AGENTS_DIR="$PROJECT_ROOT/.agents"
LOCAL_AGENTS_INSTRUCTIONS_DIR="$LOCAL_AGENTS_DIR/.instructions"
LOCAL_AGENTS_SKILLS_DIR="$LOCAL_AGENTS_DIR/skills"
LOCAL_CLAUDE_DIR="$PROJECT_ROOT/.claude"
LOCAL_CODEX_DIR="$PROJECT_ROOT/.codex"
PROJECT_INSTRUCTIONS_SRC="$PROJECT_ROOT/agents/instructions/INSTRUCTIONS_PROJECT.md"
PROJECT_INSTRUCTIONS_DST="$LOCAL_AGENTS_INSTRUCTIONS_DIR/INSTRUCTIONS_PROJECT.md"
PROJECT_MANAGEMENT_SKILL_SRC="$HOME/.agents/skills/project-management"

echo "=== $PROJECT_NAME Setup ==="

ensure_include() {
  local file="$1"
  local include_line="$2"
  if [[ -f "$file" ]] && ! grep -Fxq "$include_line" "$file"; then
    printf '\n%s\n' "$include_line" >>"$file"
  fi
}

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

ensure_brew_formula ripgrep rg
ensure_brew_formula pipx pipx
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

echo "Building $VLESS_CLI_NAME binary..."
cd "$PROJECT_ROOT"
go build -o "$VLESS_CLI_NAME" ./cmd/vless-tun/
echo "Building $OPENCONNECT_CLI_NAME binary..."
go build -o "$OPENCONNECT_CLI_NAME" ./cmd/openconnect-tun/
echo "Building $DUMP_CLI_NAME binary..."
go build -o "$DUMP_CLI_NAME" ./cmd/dump/
echo "Building $VPN_CORE_CLI_NAME binary..."
go build -o "$VPN_CORE_CLI_NAME" ./cmd/vpn-core/
echo "Building $VPN_AUTH_CLI_NAME binary..."
swift build -c release --package-path "$VPN_AUTH_PACKAGE_DIR"
VPN_AUTH_RELEASE_BIN="$(resolve_swift_release_binary "$VPN_AUTH_PACKAGE_DIR" "$VPN_AUTH_CLI_NAME")" || {
  echo "  ERROR: built $VPN_AUTH_CLI_NAME binary was not found under $VPN_AUTH_PACKAGE_DIR/.build"
  exit 1
}
cp "$VPN_AUTH_RELEASE_BIN" "$PROJECT_ROOT/$VPN_AUTH_CLI_NAME"
chmod +x "$PROJECT_ROOT/$VPN_AUTH_CLI_NAME"

mkdir -p "$BIN_DIR"
ln -sf "$PROJECT_ROOT/$VLESS_CLI_NAME" "$BIN_DIR/$VLESS_CLI_NAME"
ln -sf "$PROJECT_ROOT/$OPENCONNECT_CLI_NAME" "$BIN_DIR/$OPENCONNECT_CLI_NAME"
ln -sf "$PROJECT_ROOT/$DUMP_CLI_NAME" "$BIN_DIR/$DUMP_CLI_NAME"
ln -sf "$PROJECT_ROOT/$DUMP_CLI_NAME" "$BIN_DIR/$CISCO_DUMP_COMPAT_NAME"
ln -sf "$PROJECT_ROOT/$VPN_CORE_CLI_NAME" "$BIN_DIR/$VPN_CORE_CLI_NAME"
ln -sf "$PROJECT_ROOT/$VPN_AUTH_CLI_NAME" "$BIN_DIR/$VPN_AUTH_CLI_NAME"
rm -f "$BIN_DIR/vpn-config"
echo "  Binary -> $BIN_DIR/$VLESS_CLI_NAME"
echo "  Binary -> $BIN_DIR/$OPENCONNECT_CLI_NAME"
echo "  Binary -> $BIN_DIR/$DUMP_CLI_NAME"
echo "  Alias  -> $BIN_DIR/$CISCO_DUMP_COMPAT_NAME"
echo "  Binary -> $BIN_DIR/$VPN_CORE_CLI_NAME"
echo "  Binary -> $BIN_DIR/$VPN_AUTH_CLI_NAME"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "  WARNING: $BIN_DIR is not in your PATH"
fi

echo "Installing skill payload: $SKILL_NAME"
if [ -L "$GLOBAL_SKILL_DIR" ]; then
  rm -f "$GLOBAL_SKILL_DIR"
fi
mkdir -p "$GLOBAL_SKILL_DIR"
rsync -a --delete "$SKILL_CONTENT_DIR/" "$GLOBAL_SKILL_DIR/" --exclude='.git'
echo "  Copied -> $GLOBAL_SKILL_DIR/"

mkdir -p "$CLAUDE_DIR"
rm -f "$CLAUDE_DIR/$SKILL_NAME"
ln -s "$GLOBAL_SKILL_DIR" "$CLAUDE_DIR/$SKILL_NAME"
echo "  Symlink -> $CLAUDE_DIR/$SKILL_NAME"

mkdir -p "$CODEX_DIR"
rm -f "$CODEX_DIR/$SKILL_NAME"
ln -s "$GLOBAL_SKILL_DIR" "$CODEX_DIR/$SKILL_NAME"
echo "  Symlink -> $CODEX_DIR/$SKILL_NAME"

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

if command -v agents-infra >/dev/null 2>&1; then
  echo "Refreshing repo-local agents runtime..."
  agents-infra setup local "$PROJECT_ROOT"

  mkdir -p "$LOCAL_AGENTS_INSTRUCTIONS_DIR" "$LOCAL_AGENTS_SKILLS_DIR"
  if [[ -f "$PROJECT_INSTRUCTIONS_SRC" ]]; then
    cp "$PROJECT_INSTRUCTIONS_SRC" "$PROJECT_INSTRUCTIONS_DST"
    ensure_include "$LOCAL_AGENTS_INSTRUCTIONS_DIR/AGENTS.md" "@$PROJECT_INSTRUCTIONS_DST"
    ensure_include "$LOCAL_AGENTS_INSTRUCTIONS_DIR/INSTRUCTIONS.md" "@$PROJECT_INSTRUCTIONS_DST"
    echo "  Project instructions -> $PROJECT_INSTRUCTIONS_DST"
  fi

  mkdir -p "$LOCAL_CLAUDE_DIR/skills" "$LOCAL_CODEX_DIR/skills"
  rm -rf "$LOCAL_AGENTS_SKILLS_DIR/$SKILL_NAME"
  ln -sfn "$GLOBAL_SKILL_DIR" "$LOCAL_AGENTS_SKILLS_DIR/$SKILL_NAME"
  ln -sfn "$LOCAL_AGENTS_SKILLS_DIR/$SKILL_NAME" "$LOCAL_CLAUDE_DIR/skills/$SKILL_NAME"
  ln -sfn "$LOCAL_AGENTS_SKILLS_DIR/$SKILL_NAME" "$LOCAL_CODEX_DIR/skills/$SKILL_NAME"
  echo "  Local skill -> $LOCAL_AGENTS_SKILLS_DIR/$SKILL_NAME"

  if [[ -d "$PROJECT_MANAGEMENT_SKILL_SRC" ]]; then
    ln -sfn "$PROJECT_MANAGEMENT_SKILL_SRC" "$LOCAL_AGENTS_SKILLS_DIR/project-management"
    ln -sfn "$LOCAL_AGENTS_SKILLS_DIR/project-management" "$LOCAL_CLAUDE_DIR/skills/project-management"
    ln -sfn "$LOCAL_AGENTS_SKILLS_DIR/project-management" "$LOCAL_CODEX_DIR/skills/project-management"
    echo "  Local skill -> $LOCAL_AGENTS_SKILLS_DIR/project-management"
  fi
else
  echo "  WARNING: agents-infra is not installed; repo-local instructions and skill links were not refreshed"
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
echo "  $OPENCONNECT_CLI_NAME setup --vpn-name 'Corp VPN'"
echo "  $OPENCONNECT_CLI_NAME inspect-profiles"
echo "  $DUMP_CLI_NAME start"
