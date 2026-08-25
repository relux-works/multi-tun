#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_SCRIPT="$PROJECT_ROOT/scripts/setup.sh"
SKILL_INSTALLER="$PROJECT_ROOT/scripts/install-vpn-config-skill.sh"
SKILL_SOURCE="$PROJECT_ROOT/agents/skills/vpn-config"
SYSTEM_PATH="/usr/bin:/bin"
FIXTURE_DIRS=()

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local fixture_dir
  for fixture_dir in "${FIXTURE_DIRS[@]}"; do
    rm -rf "$fixture_dir"
  done
}

make_fixture() {
  local prefix="$1"
  CURRENT_FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/$prefix.XXXXXX")"
  FIXTURE_DIRS+=("$CURRENT_FIXTURE_DIR")
}

assert_contains() {
  local path="$1"
  local expected="$2"
  grep -Fqx -- "$expected" "$path" >/dev/null || fail "expected $path to contain: $expected"
}

assert_not_contains() {
  local path="$1"
  local unexpected="$2"
  if grep -Fqx -- "$unexpected" "$path" >/dev/null; then
    fail "expected $path not to contain: $unexpected"
  fi
}

assert_appears_before() {
  local path="$1"
  local first="$2"
  local second="$3"
  awk -v first="$first" -v second="$second" '
    $0 == first && first_line == 0 { first_line = NR }
    $0 == second && second_line == 0 { second_line = NR }
    END { exit !(first_line > 0 && second_line > 0 && first_line < second_line) }
  ' "$path" || fail "expected $first before $second in $path"
}

make_fake_brew() {
  local fixture_dir="$1"
  mkdir -p "$fixture_dir/bin" "$fixture_dir/prefix/bin"

  cat > "$fixture_dir/bin/brew" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$BREW_LOG"
case "$*" in
  '--prefix openconnect')
    printf '%s\n' "$FAKE_BREW_PREFIX"
    ;;
  'reinstall openconnect')
    : > "$FAKE_REPAIRED_MARKER"
    ;;
  *)
    exit 1
    ;;
esac
EOF
  chmod +x "$fixture_dir/bin/brew"
}

make_fake_openconnect() {
  local fixture_dir="$1"
  local launch_mode="$2"

  cat > "$fixture_dir/prefix/bin/openconnect" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "$launch_mode" == "healthy" || -f "\$FAKE_REPAIRED_MARKER" ]]; then
  printf '%s\\n' 'OpenConnect v9.21'
  exit 0
fi
printf '%s\\n' 'dyld: Library not loaded: libhogweed.6.dylib' >&2
exit 134
EOF
  chmod +x "$fixture_dir/prefix/bin/openconnect"
}

run_linkage_check() {
  local fixture_dir="$1"
  env \
    PATH="$fixture_dir/bin:$SYSTEM_PATH" \
    HOME="$fixture_dir/home" \
    BREW_LOG="$fixture_dir/brew.log" \
    FAKE_BREW_PREFIX="$fixture_dir/prefix" \
    FAKE_REPAIRED_MARKER="$fixture_dir/reinstalled" \
    "$SETUP_SCRIPT" --check-homebrew-openconnect
}

test_healthy_homebrew_openconnect_is_not_reinstalled() {
  local fixture_dir
  make_fixture multi-tun-healthy-openconnect
  fixture_dir="$CURRENT_FIXTURE_DIR"
  make_fake_brew "$fixture_dir"
  make_fake_openconnect "$fixture_dir" healthy
  ln -s "$fixture_dir/prefix/bin/openconnect" "$fixture_dir/bin/openconnect"
  : > "$fixture_dir/brew.log"

  run_linkage_check "$fixture_dir"

  assert_contains "$fixture_dir/brew.log" '--prefix openconnect'
  assert_not_contains "$fixture_dir/brew.log" 'reinstall openconnect'
  [[ ! -e "$fixture_dir/reinstalled" ]] || fail 'healthy Homebrew openconnect was reinstalled'
}

test_stale_homebrew_openconnect_is_reinstalled() {
  local fixture_dir
  make_fixture multi-tun-stale-openconnect
  fixture_dir="$CURRENT_FIXTURE_DIR"
  make_fake_brew "$fixture_dir"
  make_fake_openconnect "$fixture_dir" stale
  ln -s "$fixture_dir/prefix/bin/openconnect" "$fixture_dir/bin/openconnect"
  : > "$fixture_dir/brew.log"

  run_linkage_check "$fixture_dir"

  assert_contains "$fixture_dir/brew.log" '--prefix openconnect'
  assert_contains "$fixture_dir/brew.log" 'reinstall openconnect'
  [[ -e "$fixture_dir/reinstalled" ]] || fail 'stale Homebrew openconnect was not reinstalled'
}

test_non_homebrew_openconnect_is_not_reinstalled() {
  local fixture_dir
  make_fixture multi-tun-external-openconnect
  fixture_dir="$CURRENT_FIXTURE_DIR"
  make_fake_brew "$fixture_dir"
  make_fake_openconnect "$fixture_dir" stale
  cat > "$fixture_dir/bin/openconnect" <<'EOF'
#!/usr/bin/env bash
exit 134
EOF
  chmod +x "$fixture_dir/bin/openconnect"
  : > "$fixture_dir/brew.log"

  run_linkage_check "$fixture_dir"

  assert_contains "$fixture_dir/brew.log" '--prefix openconnect'
  assert_not_contains "$fixture_dir/brew.log" 'reinstall openconnect'
  [[ ! -e "$fixture_dir/reinstalled" ]] || fail 'non-Homebrew openconnect was reinstalled'
}

test_missing_homebrew_skips_check() {
  local fixture_dir
  make_fixture multi-tun-no-homebrew-openconnect
  fixture_dir="$CURRENT_FIXTURE_DIR"
  mkdir -p "$fixture_dir/bin"
  cat > "$fixture_dir/bin/openconnect" <<'EOF'
#!/usr/bin/env bash
exit 134
EOF
  chmod +x "$fixture_dir/bin/openconnect"

  run_linkage_check "$fixture_dir"

  [[ ! -e "$fixture_dir/reinstalled" ]] || fail 'missing Homebrew path attempted a reinstall'
}

test_full_setup_repairs_after_all_brew_dependencies() {
  local fixture_dir
  make_fixture multi-tun-full-setup-openconnect
  fixture_dir="$CURRENT_FIXTURE_DIR"
  mkdir -p "$fixture_dir/project/scripts" "$fixture_dir/project/configs" "$fixture_dir/project/agents/skills" "$fixture_dir/bin" "$fixture_dir/prefix/bin"
  cp "$SETUP_SCRIPT" "$fixture_dir/project/scripts/setup.sh"
  cp "$SKILL_INSTALLER" "$fixture_dir/project/scripts/install-vpn-config-skill.sh"
  cp -R "$SKILL_SOURCE" "$fixture_dir/project/agents/skills/vpn-config"
  : > "$fixture_dir/project/configs/local.example.json"
  : > "$fixture_dir/project/configs/ssh-proxy.example.json"
  chmod +x "$fixture_dir/project/scripts/setup.sh" "$fixture_dir/project/scripts/install-vpn-config-skill.sh"

  cat > "$fixture_dir/bin/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' Darwin ;;
  -m) printf '%s\n' arm64 ;;
  *) exit 1 ;;
esac
EOF
  cat > "$fixture_dir/bin/brew" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$BREW_LOG"
case "$*" in
  '--prefix openconnect')
    printf '%s\n' "$FAKE_BREW_PREFIX"
    ;;
  'reinstall openconnect')
    : > "$FAKE_REPAIRED_MARKER"
    ;;
  install\ *)
    ;;
  *)
    exit 1
    ;;
esac
EOF
  cat > "$fixture_dir/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == build ]] || exit 1
[[ "$2" == -o ]] || exit 1
mkdir -p "$(dirname "$3")"
: > "$3"
chmod +x "$3"
EOF
  cat > "$fixture_dir/bin/swift" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
package_dir=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == --package-path ]]; then
    package_dir="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$package_dir" ]] || exit 1
mkdir -p "$package_dir/.build/release"
: > "$package_dir/.build/release/vpn-auth"
chmod +x "$package_dir/.build/release/vpn-auth"
EOF
  cat > "$fixture_dir/bin/pipx" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$fixture_dir/bin/uname" "$fixture_dir/bin/brew" "$fixture_dir/bin/go" "$fixture_dir/bin/swift" "$fixture_dir/bin/pipx"
  make_fake_openconnect "$fixture_dir" stale
  ln -s "$fixture_dir/prefix/bin/openconnect" "$fixture_dir/bin/openconnect"
  : > "$fixture_dir/brew.log"

  env \
    PATH="$fixture_dir/bin:$SYSTEM_PATH" \
    HOME="$fixture_dir/home" \
    BREW_LOG="$fixture_dir/brew.log" \
    FAKE_BREW_PREFIX="$fixture_dir/prefix" \
    FAKE_REPAIRED_MARKER="$fixture_dir/reinstalled" \
    "$fixture_dir/project/scripts/setup.sh"

  assert_contains "$fixture_dir/brew.log" 'install totp-cli'
  assert_contains "$fixture_dir/brew.log" 'install zbar'
  assert_appears_before "$fixture_dir/brew.log" 'install totp-cli' 'reinstall openconnect'
  [[ -e "$fixture_dir/reinstalled" ]] || fail 'full setup did not repair stale Homebrew openconnect'
  [[ -f "$fixture_dir/home/.agents/skills/vpn-config/SKILL.md" ]] || fail 'full setup did not install vpn-config skill'
  [[ -L "$fixture_dir/home/.claude/skills/vpn-config" ]] || fail 'full setup did not link Claude vpn-config skill'
  [[ -L "$fixture_dir/home/.codex/skills/vpn-config" ]] || fail 'full setup did not link Codex vpn-config skill'
}

test_cross_build_skips_brew_repair() {
  local fixture_dir
  make_fixture multi-tun-cross-build-openconnect
  fixture_dir="$CURRENT_FIXTURE_DIR"
  mkdir -p "$fixture_dir/project/scripts" "$fixture_dir/bin"
  cp "$SETUP_SCRIPT" "$fixture_dir/project/scripts/setup.sh"
  chmod +x "$fixture_dir/project/scripts/setup.sh"

  cat > "$fixture_dir/bin/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' Darwin ;;
  -m) printf '%s\n' x86_64 ;;
  *) exit 1 ;;
esac
EOF
  cat > "$fixture_dir/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == build ]] || exit 1
[[ "$2" == -o ]] || exit 1
mkdir -p "$(dirname "$3")"
: > "$3"
chmod +x "$3"
EOF
  cat > "$fixture_dir/bin/brew" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$BREW_LOG"
exit 99
EOF
  chmod +x "$fixture_dir/bin/uname" "$fixture_dir/bin/go" "$fixture_dir/bin/brew"
  : > "$fixture_dir/brew.log"

  env \
    PATH="$fixture_dir/bin:$SYSTEM_PATH" \
    HOME="$fixture_dir/home" \
    BREW_LOG="$fixture_dir/brew.log" \
    "$fixture_dir/project/scripts/setup.sh" --mac-arch arm64

  [[ ! -s "$fixture_dir/brew.log" ]] || fail 'cross-build invoked Homebrew repair'
}

test_cross_build_check_only_skips_brew_repair() {
  local fixture_dir
  make_fixture multi-tun-cross-build-check-openconnect
  fixture_dir="$CURRENT_FIXTURE_DIR"
  mkdir -p "$fixture_dir/project/scripts" "$fixture_dir/bin"
  cp "$SETUP_SCRIPT" "$fixture_dir/project/scripts/setup.sh"
  chmod +x "$fixture_dir/project/scripts/setup.sh"

  cat > "$fixture_dir/bin/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' Darwin ;;
  -m) printf '%s\n' x86_64 ;;
  *) exit 1 ;;
esac
EOF
  cat > "$fixture_dir/bin/brew" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$BREW_LOG"
exit 99
EOF
  chmod +x "$fixture_dir/bin/uname" "$fixture_dir/bin/brew"
  : > "$fixture_dir/brew.log"

  env \
    PATH="$fixture_dir/bin:$SYSTEM_PATH" \
    HOME="$fixture_dir/home" \
    BREW_LOG="$fixture_dir/brew.log" \
    "$fixture_dir/project/scripts/setup.sh" --mac-arch arm64 --check-homebrew-openconnect

  [[ ! -s "$fixture_dir/brew.log" ]] || fail 'cross-build check-only mode invoked Homebrew repair'
}

trap cleanup EXIT
test_healthy_homebrew_openconnect_is_not_reinstalled
test_stale_homebrew_openconnect_is_reinstalled
test_non_homebrew_openconnect_is_not_reinstalled
test_missing_homebrew_skips_check
test_full_setup_repairs_after_all_brew_dependencies
test_cross_build_skips_brew_repair
test_cross_build_check_only_skips_brew_repair
printf '%s\n' 'setup OpenConnect linkage regression tests passed'
