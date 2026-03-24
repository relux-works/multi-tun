#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SKILL_NAME="vpn-config"
SKILL_CONTENT_DIR="$PROJECT_ROOT/agents/skills/$SKILL_NAME"
CLI_NAME="vless-tun"

AGENTS_DIR="$HOME/.agents/skills"
CLAUDE_DIR="$HOME/.claude/skills"
CODEX_DIR="$HOME/.codex/skills"
BIN_DIR="$HOME/.local/bin"
GLOBAL_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/vless-tun"
GLOBAL_CONFIG_PATH="$GLOBAL_CONFIG_DIR/config.json"
LEGACY_CONFIG_PATH="$PROJECT_ROOT/configs/local.json"
EXAMPLE_CONFIG_PATH="$PROJECT_ROOT/configs/local.example.json"

echo "=== $SKILL_NAME Setup ==="

if ! command -v rg >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installing ripgrep..."
    brew install ripgrep
  else
    echo "  WARNING: rg (ripgrep) is not installed and Homebrew was not found"
  fi
fi

echo "Building $CLI_NAME binary..."
cd "$PROJECT_ROOT"
go build -o "$CLI_NAME" ./cmd/vpn-config/

mkdir -p "$BIN_DIR"
ln -sf "$PROJECT_ROOT/$CLI_NAME" "$BIN_DIR/$CLI_NAME"
rm -f "$BIN_DIR/vpn-config"
echo "  Binary -> $BIN_DIR/$CLI_NAME"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "  WARNING: $BIN_DIR is not in your PATH"
fi

echo "Installing skill payload: $SKILL_NAME"
if [ -L "$AGENTS_DIR/$SKILL_NAME" ]; then
  rm -f "$AGENTS_DIR/$SKILL_NAME"
fi
mkdir -p "$AGENTS_DIR/$SKILL_NAME"
rsync -a --delete "$SKILL_CONTENT_DIR/" "$AGENTS_DIR/$SKILL_NAME/" --exclude='.git'
echo "  Copied -> $AGENTS_DIR/$SKILL_NAME/"

mkdir -p "$CLAUDE_DIR"
rm -f "$CLAUDE_DIR/$SKILL_NAME"
ln -s "$AGENTS_DIR/$SKILL_NAME" "$CLAUDE_DIR/$SKILL_NAME"
echo "  Symlink -> $CLAUDE_DIR/$SKILL_NAME"

mkdir -p "$CODEX_DIR"
rm -f "$CODEX_DIR/$SKILL_NAME"
ln -s "$AGENTS_DIR/$SKILL_NAME" "$CODEX_DIR/$SKILL_NAME"
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

echo
echo "Done. Installed $(git -C "$PROJECT_ROOT" describe --tags --always 2>/dev/null || echo 'unknown')"
echo
echo "Next steps:"
echo "  edit $GLOBAL_CONFIG_PATH"
echo "  $CLI_NAME refresh"
echo "  $CLI_NAME render"
