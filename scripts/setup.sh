#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SKILL_NAME="vpn-config"
PROJECT_NAME="multi-tun"
SKILL_CONTENT_DIR="$PROJECT_ROOT/agents/skills/$SKILL_NAME"
VLESS_CLI_NAME="vless-tun"
OPENCONNECT_CLI_NAME="openconnect-tun"
CISCO_DUMP_CLI_NAME="cisco-dump"

AGENTS_DIR="$HOME/.agents/skills"
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

if ! command -v rg >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installing ripgrep..."
    brew install ripgrep
  else
    echo "  WARNING: rg (ripgrep) is not installed and Homebrew was not found"
  fi
fi

if ! command -v pipx >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installing pipx..."
    brew install pipx
  else
    echo "  WARNING: pipx is not installed and Homebrew was not found"
  fi
fi

if ! command -v vpn-slice >/dev/null 2>&1; then
  if command -v pipx >/dev/null 2>&1; then
    echo "Installing vpn-slice..."
    pipx install vpn-slice || true
  else
    echo "  WARNING: vpn-slice is not installed because pipx is unavailable"
  fi
fi

echo "Building $VLESS_CLI_NAME binary..."
cd "$PROJECT_ROOT"
go build -o "$VLESS_CLI_NAME" ./cmd/vless-tun/
echo "Building $OPENCONNECT_CLI_NAME binary..."
go build -o "$OPENCONNECT_CLI_NAME" ./cmd/openconnect-tun/
echo "Building $CISCO_DUMP_CLI_NAME binary..."
go build -o "$CISCO_DUMP_CLI_NAME" ./cmd/cisco-dump/

mkdir -p "$BIN_DIR"
ln -sf "$PROJECT_ROOT/$VLESS_CLI_NAME" "$BIN_DIR/$VLESS_CLI_NAME"
ln -sf "$PROJECT_ROOT/$OPENCONNECT_CLI_NAME" "$BIN_DIR/$OPENCONNECT_CLI_NAME"
ln -sf "$PROJECT_ROOT/$CISCO_DUMP_CLI_NAME" "$BIN_DIR/$CISCO_DUMP_CLI_NAME"
rm -f "$BIN_DIR/vpn-config"
echo "  Binary -> $BIN_DIR/$VLESS_CLI_NAME"
echo "  Binary -> $BIN_DIR/$OPENCONNECT_CLI_NAME"
echo "  Binary -> $BIN_DIR/$CISCO_DUMP_CLI_NAME"

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
  ln -sfn "$SKILL_CONTENT_DIR" "$LOCAL_AGENTS_SKILLS_DIR/$SKILL_NAME"
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
echo "  $VLESS_CLI_NAME refresh"
echo "  $VLESS_CLI_NAME render"
echo "  $OPENCONNECT_CLI_NAME inspect-profiles"
echo "  $CISCO_DUMP_CLI_NAME start"
