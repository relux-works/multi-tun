#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi
if shopt -qo posix 2>/dev/null; then
  exec /usr/bin/env bash "$0" "$@"
fi
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

REPO_URL="${MULTI_TUN_REPO_URL:-https://github.com/relux-works/multi-tun.git}"
BRANCH="${MULTI_TUN_BRANCH:-main}"
CHECKOUT_DIR="${MULTI_TUN_CHECKOUT_DIR:-$HOME/src/multi-tun}"
CONFIG_BUNDLE="${MULTI_TUN_CONFIG_BUNDLE:-}"

DRY_RUN=0
SKIP_CONFIG=0
SKIP_PULL=0
ALLOW_DIRTY=0
INSTALL_VPN_CORE=1
REFRESH_VLESS=0
CLEAN_LEGACY_MULTI_TUN_CONFIG=1
SETUP_ARGS=()

usage() {
  cat <<'EOF'
Usage: deploy-multi-tun.sh [options]

Install or update the multi-tun macOS toolchain from git, then optionally apply
an adjacent local config bundle.

Options:
  --repo-url URL          Git remote to clone from or fetch (default: origin repo)
  --branch NAME          Branch to checkout/update (default: main)
  --checkout-dir PATH    Destination checkout (default: ~/src/multi-tun)
  --config-bundle PATH   Directory with vless-tun/openconnect-tun configs
  --skip-config          Do not copy local tunnel configs
  --skip-pull            Do not fetch/pull an existing checkout
  --allow-dirty          Allow update when checkout has local changes
  --keep-legacy-config   Keep old ~/.config/multi-tun directory if it exists
  --skip-vpn-core        Do not run vpn-core install after setup
  --refresh-vless        Run vless-tun refresh/render after config installation
  --setup-arg VALUE      Forward one argument to scripts/setup.sh; may repeat
  --dry-run              Print planned actions without changing the machine
  -h, --help             Show this help

Default config bundle discovery:
  1. --config-bundle PATH
  2. ./config next to this script
  3. ./configs next to this script

Expected bundle layout:
  config/
    vless-tun/config.json
    openconnect-tun/config.json

Config files may use these placeholders; they are expanded during install:
  __HOME__
  __XDG_CONFIG_HOME__
  __XDG_CACHE_HOME__

Keychain secrets are not exported by this script. If openconnect-tun configs
reference Keychain accounts, seed those values on the target Mac separately.
EOF
}

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARNING: %s\n' "$*" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

run() {
  log "+ $*"
  if [[ "$DRY_RUN" == "0" ]]; then
    "$@"
  fi
}

abs_path() {
  local path="$1"
  if [[ -d "$path" ]]; then
    (cd "$path" && pwd)
  elif [[ "$path" == /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$(pwd)" "$path"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo-url)
        [[ $# -ge 2 ]] || die "--repo-url requires a value"
        REPO_URL="$2"
        shift 2
        ;;
      --branch)
        [[ $# -ge 2 ]] || die "--branch requires a value"
        BRANCH="$2"
        shift 2
        ;;
      --checkout-dir)
        [[ $# -ge 2 ]] || die "--checkout-dir requires a value"
        CHECKOUT_DIR="$2"
        shift 2
        ;;
      --config-bundle)
        [[ $# -ge 2 ]] || die "--config-bundle requires a value"
        CONFIG_BUNDLE="$2"
        shift 2
        ;;
      --skip-config)
        SKIP_CONFIG=1
        shift
        ;;
      --skip-pull)
        SKIP_PULL=1
        shift
        ;;
      --allow-dirty)
        ALLOW_DIRTY=1
        shift
        ;;
      --keep-legacy-config)
        CLEAN_LEGACY_MULTI_TUN_CONFIG=0
        shift
        ;;
      --skip-vpn-core)
        INSTALL_VPN_CORE=0
        shift
        ;;
      --refresh-vless)
        REFRESH_VLESS=1
        shift
        ;;
      --setup-arg)
        [[ $# -ge 2 ]] || die "--setup-arg requires a value"
        SETUP_ARGS+=("$2")
        shift 2
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  CHECKOUT_DIR="${CHECKOUT_DIR/#\~/$HOME}"
  CHECKOUT_DIR="$(abs_path "$CHECKOUT_DIR")"
  if [[ -n "$CONFIG_BUNDLE" ]]; then
    CONFIG_BUNDLE="${CONFIG_BUNDLE/#\~/$HOME}"
    CONFIG_BUNDLE="$(abs_path "$CONFIG_BUNDLE")"
  fi
}

ensure_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || die "this deploy script is for macOS"
}

load_brew_env() {
  local brew_bin
  for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [[ -x "$brew_bin" ]]; then
      eval "$("$brew_bin" shellenv)"
      return 0
    fi
  done
  if command -v brew >/dev/null 2>&1; then
    eval "$(brew shellenv)"
  fi
}

ensure_xcode_clt() {
  if xcode-select -p >/dev/null 2>&1; then
    return 0
  fi

  warn "Xcode Command Line Tools are not installed."
  if [[ "$DRY_RUN" == "1" ]]; then
    log "+ xcode-select --install"
    return 0
  fi

  xcode-select --install || true
  die "finish the Command Line Tools installer, then rerun this script"
}

install_homebrew() {
  if command -v brew >/dev/null 2>&1; then
    return 0
  fi

  local install_url="https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
  warn "Homebrew is not installed; installing it from $install_url"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "+ NONINTERACTIVE=1 /bin/bash -c \"\$(curl -fsSL $install_url)\""
    return 0
  fi

  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL "$install_url")"
  load_brew_env
}

ensure_brew_formula() {
  local formula="$1"
  local binary="${2:-$1}"
  if command -v "$binary" >/dev/null 2>&1; then
    return 0
  fi
  command -v brew >/dev/null 2>&1 || die "brew is unavailable; cannot install $formula"
  run brew install "$formula"
}

ensure_base_tools() {
  ensure_xcode_clt
  load_brew_env
  install_homebrew
  load_brew_env

  ensure_brew_formula git git
  ensure_brew_formula go go
}

ensure_checkout() {
  if [[ -d "$CHECKOUT_DIR/.git" ]]; then
    log "Using existing checkout: $CHECKOUT_DIR"
    if [[ "$ALLOW_DIRTY" != "1" ]]; then
      local dirty
      dirty="$(git -C "$CHECKOUT_DIR" status --porcelain)"
      [[ -z "$dirty" ]] || die "checkout has local changes; commit/stash them or pass --allow-dirty"
    fi

    local current_origin
    current_origin="$(git -C "$CHECKOUT_DIR" remote get-url origin 2>/dev/null || true)"
    if [[ -z "$current_origin" ]]; then
      run git -C "$CHECKOUT_DIR" remote add origin "$REPO_URL"
    elif [[ "$current_origin" != "$REPO_URL" ]]; then
      warn "existing origin is $current_origin, requested $REPO_URL; keeping existing origin"
    fi

    if [[ "$SKIP_PULL" == "0" ]]; then
      run git -C "$CHECKOUT_DIR" fetch --prune origin
      run git -C "$CHECKOUT_DIR" checkout "$BRANCH"
      run git -C "$CHECKOUT_DIR" pull --ff-only origin "$BRANCH"
    else
      log "Skipping git pull by request."
    fi
    return 0
  fi

  if [[ -e "$CHECKOUT_DIR" ]]; then
    die "$CHECKOUT_DIR exists but is not a git checkout"
  fi

  run mkdir -p "$(dirname "$CHECKOUT_DIR")"
  run git clone --branch "$BRANCH" "$REPO_URL" "$CHECKOUT_DIR"
}

run_repo_setup() {
  local setup_script="$CHECKOUT_DIR/scripts/setup.sh"
  if [[ "$DRY_RUN" == "1" && ! -f "$setup_script" ]]; then
    local setup_display="$setup_script"
    if [[ "${#SETUP_ARGS[@]}" -gt 0 ]]; then
      setup_display="$setup_display ${SETUP_ARGS[*]}"
    fi
    log "+ $setup_display"
    return 0
  fi
  [[ -x "$setup_script" || -f "$setup_script" ]] || die "missing setup script: $setup_script"
  if [[ "${#SETUP_ARGS[@]}" -gt 0 ]]; then
    run "$setup_script" "${SETUP_ARGS[@]}"
  else
    run "$setup_script"
  fi
}

discover_config_bundle() {
  if [[ "$SKIP_CONFIG" == "1" ]]; then
    return 0
  fi
  if [[ -n "$CONFIG_BUNDLE" ]]; then
    [[ -d "$CONFIG_BUNDLE" ]] || die "config bundle not found: $CONFIG_BUNDLE"
    return 0
  fi
  if [[ -d "$SCRIPT_DIR/config" ]]; then
    CONFIG_BUNDLE="$SCRIPT_DIR/config"
  elif [[ -d "$SCRIPT_DIR/configs" ]]; then
    CONFIG_BUNDLE="$SCRIPT_DIR/configs"
  fi
}

backup_and_copy() {
  local source_path="$1"
  local target_path="$2"
  local target_dir
  target_dir="$(dirname "$target_path")"

  if [[ ! -f "$source_path" ]]; then
    return 0
  fi

  run mkdir -p "$target_dir"
  if [[ -f "$target_path" ]]; then
    if cmp -s "$source_path" "$target_path"; then
      log "Config unchanged: $target_path"
      return 0
    fi
    local backup_path
    backup_path="$target_path.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    run cp -p "$target_path" "$backup_path"
    log "Backup -> $backup_path"
  fi

  run cp -p "$source_path" "$target_path"
  run chmod 600 "$target_path"
  log "Installed config -> $target_path"
}

render_and_install_config() {
  local source_path="$1"
  local target_path="$2"
  if [[ ! -f "$source_path" ]]; then
    return 0
  fi

  local temp_path
  temp_path="$(mktemp "${TMPDIR:-/tmp}/multi-tun-config.XXXXXX")"
  cp -p "$source_path" "$temp_path"
  HOME="$HOME" \
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}" \
    XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}" \
    perl -0pi -e 's#__HOME__#$ENV{HOME}#g; s#__XDG_CONFIG_HOME__#$ENV{XDG_CONFIG_HOME}#g; s#__XDG_CACHE_HOME__#$ENV{XDG_CACHE_HOME}#g' "$temp_path"
  backup_and_copy "$temp_path" "$target_path"
  rm -f "$temp_path"
}

install_configs() {
  if [[ "$SKIP_CONFIG" == "1" ]]; then
    log "Skipping config installation by request."
    return 0
  fi
  if [[ -z "$CONFIG_BUNDLE" ]]; then
    warn "no config bundle found next to script; skipping config installation"
    return 0
  fi

  log "Applying config bundle: $CONFIG_BUNDLE"
  local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
  render_and_install_config "$CONFIG_BUNDLE/vless-tun/config.json" "$config_home/vless-tun/config.json"
  render_and_install_config "$CONFIG_BUNDLE/openconnect-tun/config.json" "$config_home/openconnect-tun/config.json"

  if [[ -d "$CONFIG_BUNDLE/keychain" ]]; then
    warn "keychain directory is present but automatic secret import is intentionally not implemented"
  fi
}

archive_legacy_multi_tun_config() {
  if [[ "$CLEAN_LEGACY_MULTI_TUN_CONFIG" != "1" ]]; then
    log "Keeping legacy ~/.config/multi-tun by request."
    return 0
  fi

  local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
  local legacy_dir="$config_home/multi-tun"
  if [[ ! -e "$legacy_dir" ]]; then
    return 0
  fi

  local backup_dir
  backup_dir="$config_home/multi-tun.legacy-bak-$(date -u +%Y%m%dT%H%M%SZ)"
  run mv "$legacy_dir" "$backup_dir"
  log "Archived legacy config -> $backup_dir"
}

install_vpn_core() {
  if [[ "$INSTALL_VPN_CORE" != "1" ]]; then
    log "Skipping vpn-core install by request."
    return 0
  fi
  if ! command -v vpn-core >/dev/null 2>&1; then
    warn "vpn-core is not in PATH after setup; skipping vpn-core install"
    return 0
  fi
  run vpn-core install
}

verify_tool() {
  local binary="$1"
  if ! command -v "$binary" >/dev/null 2>&1; then
    warn "$binary is not in PATH"
    return 0
  fi
  run "$binary" --help >/dev/null
  log "Verified -> $(command -v "$binary")"
}

verify_install() {
  verify_tool vless-tun
  verify_tool openconnect-tun
  verify_tool vpn-core
  verify_tool dump

  if [[ "$REFRESH_VLESS" == "1" ]]; then
    run vless-tun refresh
    run vless-tun render
  fi
}

print_summary() {
  log
  log "multi-tun deploy finished."
  log "Checkout: $CHECKOUT_DIR"
  if [[ -d "$CHECKOUT_DIR/.git" ]]; then
    log "Revision: $(git -C "$CHECKOUT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
  fi
  if [[ -n "$CONFIG_BUNDLE" && "$SKIP_CONFIG" == "0" ]]; then
    log "Config bundle: $CONFIG_BUNDLE"
  fi
  log
  log "Useful checks:"
  log "  vless-tun status"
  log "  vless-tun list"
  log "  openconnect-tun status"
  log "  vpn-core status"
}

main() {
  parse_args "$@"
  ensure_macos
  discover_config_bundle
  export PATH="$HOME/.local/bin:$PATH"
  ensure_base_tools
  ensure_checkout
  run_repo_setup
  install_configs
  archive_legacy_multi_tun_config
  install_vpn_core
  verify_install
  print_summary
}

main "$@"
