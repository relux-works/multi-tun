#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE_DIR="$PROJECT_ROOT/agents/skills/vpn-config"
INSTALL_DIR="$HOME/.agents/skills/vpn-config"

if [[ ! -f "$SOURCE_DIR/SKILL.md" ]]; then
  echo "ERROR: vpn-config skill source is missing: $SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete "$SOURCE_DIR/" "$INSTALL_DIR/"
else
  find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  cp -R "$SOURCE_DIR/." "$INSTALL_DIR/"
fi

for agent_dir in "$HOME/.claude/skills" "$HOME/.codex/skills"; do
  mkdir -p "$agent_dir"
  link_path="$agent_dir/vpn-config"
  if [[ -e "$link_path" && ! -L "$link_path" ]]; then
    echo "ERROR: refusing to replace non-symlink path: $link_path" >&2
    exit 1
  fi
  ln -sfn "$INSTALL_DIR" "$link_path"
done

echo "Installed vpn-config skill -> $INSTALL_DIR"
echo "Linked Claude skill -> $HOME/.claude/skills/vpn-config"
echo "Linked Codex skill -> $HOME/.codex/skills/vpn-config"
