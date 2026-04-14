#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SMOKE_SCRIPT="$ROOT_DIR/scripts/android/run-device-smoke.sh"

SERIAL="${ANDROID_SERIAL:-}"
SOURCE_ARGS=()
OBSERVER_ARGS=()
NO_RUNTIME=false

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Runs the stable real-device Android regression suite in layers:
  1. TunnelHomeSmokeTest#tunnelHomeLoads
  2. TunnelHomeEditorStateTest
  3. TunnelConnectSmokeTest
  4. TunnelInlineXhttpBypassSmokeTest
  5. TunnelInlineXhttpObserverVisibilitySmokeTest
  6. TunnelEgressSmokeTest

Runtime checks (3-5) require a tunnel source. If none is provided, only
the UI-only subset (1-2) runs.

Options:
  --serial <id>          adb serial to target
  --source-url <url>     pass local source URL to runtime checks
  --source-url-from-desktop-config
                         read source.url from ~/.config/vless-tun/config.json
  --source-inline-vless-from-desktop-config
                         resolve the first inline VLESS URI from desktop config/subscription
  --observer-bootstrap-ip <ipv4>
                         pass a pinned bootstrap IPv4 for observer whoami resolution
  --no-runtime           run only home/editor UI checks
  -h, --help             show this help

Examples:
  $(basename "$0") --serial 535a1632
  $(basename "$0") --serial 535a1632 --source-url-from-desktop-config
  $(basename "$0") --serial 535a1632 --source-inline-vless-from-desktop-config
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --serial)
            SERIAL="${2:-}"
            shift 2
            ;;
        --source-url)
            SOURCE_ARGS=(--source-url "${2:-}")
            shift 2
            ;;
        --source-url-from-desktop-config)
            SOURCE_ARGS=(--source-url-from-desktop-config)
            shift
            ;;
        --source-inline-vless-from-desktop-config)
            SOURCE_ARGS=(--source-inline-vless-from-desktop-config)
            shift
            ;;
        --observer-bootstrap-ip)
            OBSERVER_ARGS=(--observer-bootstrap-ip "${2:-}")
            shift 2
            ;;
        --no-runtime)
            NO_RUNTIME=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[device-suite] Unknown arg: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -n "$SERIAL" ]]; then
    COMMON_ARGS=(--serial "$SERIAL")
else
    COMMON_ARGS=()
fi

run_case() {
    local label="$1"
    local test_class="$2"
    shift 2

    echo "[device-suite] Running $label -> $test_class"
    "$SMOKE_SCRIPT" \
        "${COMMON_ARGS[@]}" \
        "$@" \
        --test-class "$test_class"
}

run_case "home smoke" "works.relux.vless_tun_app.TunnelHomeSmokeTest#tunnelHomeLoads"
run_case "editor regression" "works.relux.vless_tun_app.TunnelHomeEditorStateTest" --skip-build --skip-install

if $NO_RUNTIME; then
    echo "[device-suite] Skipping runtime checks by request."
    exit 0
fi

if [[ "${#SOURCE_ARGS[@]}" -eq 0 ]]; then
    echo "[device-suite] No tunnel source provided. Runtime checks skipped." >&2
    echo "[device-suite] Pass --source-url, --source-url-from-desktop-config, or --source-inline-vless-from-desktop-config." >&2
    exit 0
fi

RUNTIME_ARGS=(--skip-build --skip-install "${SOURCE_ARGS[@]}")
if [[ "${#OBSERVER_ARGS[@]}" -gt 0 ]]; then
    RUNTIME_ARGS+=("${OBSERVER_ARGS[@]}")
fi

run_case \
    "connect smoke" \
    "works.relux.vless_tun_app.TunnelConnectSmokeTest" \
    "${RUNTIME_ARGS[@]}"

run_case \
    "xhttp bypass smoke" \
    "works.relux.vless_tun_app.TunnelInlineXhttpBypassSmokeTest" \
    "${RUNTIME_ARGS[@]}"

run_case \
    "observer visibility smoke" \
    "works.relux.vless_tun_app.TunnelInlineXhttpObserverVisibilitySmokeTest" \
    "${RUNTIME_ARGS[@]}"

run_case \
    "egress smoke" \
    "works.relux.vless_tun_app.TunnelEgressSmokeTest" \
    "${RUNTIME_ARGS[@]}"

echo "[device-suite] All requested checks passed."
