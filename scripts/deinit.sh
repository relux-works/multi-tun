#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SKILL_NAME="vpn-config"
SERVICE_NAME="multi-tun"

GLOBAL_SKILL_DIR="$HOME/.agents/skills/$SKILL_NAME"
GLOBAL_CLAUDE_LINK="$HOME/.claude/skills/$SKILL_NAME"
GLOBAL_CODEX_LINK="$HOME/.codex/skills/$SKILL_NAME"

LOCAL_SKILL_LINK="$PROJECT_ROOT/.agents/skills/$SKILL_NAME"
LOCAL_CLAUDE_LINK="$PROJECT_ROOT/.claude/skills/$SKILL_NAME"
LOCAL_CODEX_LINK="$PROJECT_ROOT/.codex/skills/$SKILL_NAME"

GLOBAL_BIN_DIR="$HOME/.local/bin"
BIN_NAMES=(
  "vless-tun"
  "openconnect-tun"
  "dump"
  "cisco-dump"
  "vpn-core"
  "vpn-auth"
)

CONFIG_DIRS=(
  "${XDG_CONFIG_HOME:-$HOME/.config}/vless-tun"
  "${XDG_CONFIG_HOME:-$HOME/.config}/openconnect-tun"
)

CACHE_DIRS=(
  "${XDG_CACHE_HOME:-$HOME/.cache}/vless-tun"
  "${XDG_CACHE_HOME:-$HOME/.cache}/openconnect-tun"
  "${XDG_CACHE_HOME:-$HOME/.cache}/cisco-dump"
)

BUILD_ARTIFACTS=(
  "$PROJECT_ROOT/vless-tun"
  "$PROJECT_ROOT/openconnect-tun"
  "$PROJECT_ROOT/dump"
  "$PROJECT_ROOT/cisco-dump"
  "$PROJECT_ROOT/vpn-core"
  "$PROJECT_ROOT/vpn-auth"
)

PURGE_CONFIG=false
PURGE_CACHE=false
PURGE_KEYCHAIN=false
PURGE_BUILDS=false
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: ./scripts/deinit.sh [options]

Removes the managed multi-tun skill links and installed binary symlinks.
Config, cache, keychain secrets, and repo build artifacts are preserved by default.

Options:
  --purge-config    Remove ~/.config/vless-tun and ~/.config/openconnect-tun
  --purge-cache     Remove ~/.cache/vless-tun, ~/.cache/openconnect-tun, ~/.cache/cisco-dump
  --purge-keychain  Delete openconnect auth accounts referenced by the current config
  --purge-builds    Remove repo-local built binaries (./vless-tun, ./openconnect-tun, ./dump, ./cisco-dump, ./vpn-core, ./vpn-auth)
  --dry-run         Print actions without deleting anything
  -h, --help        Show this help
EOF
}

log() {
  printf '%s\n' "$1"
}

run_rm() {
  local path="$1"
  if [[ "$DRY_RUN" == true ]]; then
    log "DRY-RUN rm -rf $path"
    return 0
  fi
  rm -rf "$path"
}

remove_managed_path() {
  local path="$1"
  local label="$2"
  if [[ -L "$path" || -e "$path" ]]; then
    run_rm "$path"
    log "removed $label: $path"
  else
    log "skip $label: $path"
  fi
}

delete_keychain_account() {
  local account="$1"
  if [[ -z "$account" ]]; then
    return 0
  fi
  if ! command -v security >/dev/null 2>&1; then
    log "warning: security CLI not found; cannot delete keychain account $account"
    return 0
  fi
  if [[ "$DRY_RUN" == true ]]; then
    log "DRY-RUN security delete-generic-password -a $account -s $SERVICE_NAME"
    return 0
  fi
  security delete-generic-password -a "$account" -s "$SERVICE_NAME" >/dev/null 2>&1 || true
  log "removed keychain account: $account"
}

collect_openconnect_keychain_accounts() {
  local config_path="${XDG_CONFIG_HOME:-$HOME/.config}/openconnect-tun/config.json"
  if [[ ! -f "$config_path" ]]; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    log "warning: python3 not found; cannot parse $config_path for keychain accounts"
    return 0
  fi
  python3 - "$config_path" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
auth = data.get("auth") or {}
for key in ("username_keychain_account", "password_keychain_account", "totp_secret_keychain_account"):
    value = auth.get(key)
    if value:
        print(value)
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-config)
      PURGE_CONFIG=true
      ;;
    --purge-cache)
      PURGE_CACHE=true
      ;;
    --purge-keychain)
      PURGE_KEYCHAIN=true
      ;;
    --purge-builds)
      PURGE_BUILDS=true
      ;;
    --dry-run)
      DRY_RUN=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

log "=== multi-tun deinit ==="

for bin_name in "${BIN_NAMES[@]}"; do
  remove_managed_path "$GLOBAL_BIN_DIR/$bin_name" "global bin"
done

remove_managed_path "$GLOBAL_CODEX_LINK" "global codex skill link"
remove_managed_path "$GLOBAL_CLAUDE_LINK" "global claude skill link"
remove_managed_path "$GLOBAL_SKILL_DIR" "global skill payload"

remove_managed_path "$LOCAL_CODEX_LINK" "repo-local codex skill link"
remove_managed_path "$LOCAL_CLAUDE_LINK" "repo-local claude skill link"
remove_managed_path "$LOCAL_SKILL_LINK" "repo-local skill link"

if [[ "$PURGE_CONFIG" == true ]]; then
  for path in "${CONFIG_DIRS[@]}"; do
    remove_managed_path "$path" "config dir"
  done
else
  log "preserved config dirs"
fi

if [[ "$PURGE_CACHE" == true ]]; then
  for path in "${CACHE_DIRS[@]}"; do
    remove_managed_path "$path" "cache dir"
  done
else
  log "preserved cache dirs"
fi

if [[ "$PURGE_KEYCHAIN" == true ]]; then
  while IFS= read -r account; do
    delete_keychain_account "$account"
  done < <(collect_openconnect_keychain_accounts)
else
  log "preserved keychain accounts"
fi

if [[ "$PURGE_BUILDS" == true ]]; then
  for path in "${BUILD_ARTIFACTS[@]}"; do
    remove_managed_path "$path" "repo build artifact"
  done
else
  log "preserved repo build artifacts"
fi

log ""
log "done"
