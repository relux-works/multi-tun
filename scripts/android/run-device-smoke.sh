#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ANDROID_DIR="$ROOT_DIR/android"
ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
GRADLE="./gradlew"

APP_PACKAGE="works.relux.android.vlesstun.app"
TEST_PACKAGE="${APP_PACKAGE}.test"
TEST_CLASS_DEFAULT="works.relux.vless_tun_app.TunnelHomeSmokeTest"
RUNNER="${TEST_PACKAGE}/androidx.test.runner.AndroidJUnitRunner"
SCREENSHOT_ROOT="/sdcard/Pictures/Screenshots/UITests"

SERIAL="${ANDROID_SERIAL:-}"
TEST_CLASS="$TEST_CLASS_DEFAULT"
SKIP_BUILD=false
SKIP_INSTALL=false
PULL_SCREENSHOTS=true
SOURCE_URL=""
SOURCE_URL_FROM_DESKTOP_CONFIG=false
SOURCE_INLINE_VLESS_FROM_DESKTOP_CONFIG=false
OBSERVER_BOOTSTRAP_IP=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --serial <id>          adb serial to target
  --test-class <name>    instrumentation test class (default: $TEST_CLASS_DEFAULT)
  --source-url <url>     pass local source URL to instrumentation as vless_source_url
  --source-url-from-desktop-config
                         read source.url from ~/.config/vless-tun/config.json and pass it to instrumentation
  --source-inline-vless-from-desktop-config
                         resolve the first VLESS URI from the desktop config/subscription and pass it inline
  --observer-bootstrap-ip <ipv4>
                         pass a pinned bootstrap IPv4 for observer whoami resolution
  --skip-build           skip Gradle assemble steps
  --skip-install         skip adb install of app and androidTest APKs
  --no-pull-screenshots  do not copy screenshot artifacts from the device
  -h, --help             show this help

Examples:
  $(basename "$0")
  $(basename "$0") --serial 535a1632
  $(basename "$0") --skip-install --test-class works.relux.vless_tun_app.TunnelHomeSmokeTest
  $(basename "$0") --serial 535a1632 --test-class works.relux.vless_tun_app.TunnelConnectSmokeTest --source-url-from-desktop-config
  $(basename "$0") --serial 535a1632 --test-class works.relux.vless_tun_app.TunnelConnectSmokeTest --source-inline-vless-from-desktop-config
  $(basename "$0") --serial 535a1632 --test-class works.relux.vless_tun_app.TunnelEgressSmokeTest --source-inline-vless-from-desktop-config
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --serial)
            SERIAL="${2:-}"
            shift 2
            ;;
        --test-class)
            TEST_CLASS="${2:-}"
            shift 2
            ;;
        --source-url)
            SOURCE_URL="${2:-}"
            shift 2
            ;;
        --source-url-from-desktop-config)
            SOURCE_URL_FROM_DESKTOP_CONFIG=true
            shift
            ;;
        --source-inline-vless-from-desktop-config)
            SOURCE_INLINE_VLESS_FROM_DESKTOP_CONFIG=true
            shift
            ;;
        --observer-bootstrap-ip)
            OBSERVER_BOOTSTRAP_IP="${2:-}"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-install)
            SKIP_INSTALL=true
            shift
            ;;
        --no-pull-screenshots)
            PULL_SCREENSHOTS=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[device-smoke] Unknown arg: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[device-smoke] Missing command: $cmd" >&2
        exit 1
    fi
}

require_cmd "$ADB"
require_cmd python3

resolve_source_url_from_desktop_config() {
    python3 - <<'PY'
import json, os, sys
path = os.path.expanduser("~/.config/vless-tun/config.json")
if not os.path.exists(path):
    sys.exit(1)
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
source = ((data.get("source") or {}).get("url") or "").strip()
if not source:
    sys.exit(1)
print(source)
PY
}

resolve_inline_vless_from_desktop_config() {
    python3 - <<'PY'
import base64
import json
import os
import urllib.request

def first_uri(raw: str) -> str:
    compact = "".join(raw.split())
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(compact + "=" * (-len(compact) % 4)).decode("utf-8").strip()
            if "://" in decoded:
                raw = decoded
                break
        except Exception:
            pass
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "://" in line:
            return line
    raise RuntimeError("no inline VLESS URI found")

cache_path = os.path.expanduser("~/.cache/vless-tun/subscription.txt")
if os.path.exists(cache_path):
    cached = open(cache_path, "r", encoding="utf-8").read().strip()
    if cached:
        try:
            print(first_uri(cached))
            raise SystemExit(0)
        except Exception:
            pass

path = os.path.expanduser("~/.config/vless-tun/config.json")
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
url = ((data.get("source") or {}).get("url") or "").strip()
if not url:
    raise SystemExit(1)
raw = urllib.request.urlopen(url, timeout=20).read().decode("utf-8").strip()
print(first_uri(raw))
PY
}

resolve_observer_bootstrap_ip() {
    python3 - <<'PY'
import socket
infos = socket.getaddrinfo("api.ipify.org", 443, socket.AF_INET, socket.SOCK_STREAM)
for info in infos:
    addr = info[4][0].strip()
    if addr:
        print(addr)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

resolve_serial() {
    if [[ -n "$SERIAL" ]]; then
        echo "$SERIAL"
        return
    fi

    mapfile -t physical_devices < <(
        "$ADB" devices |
            tail -n +2 |
            awk '$2 == "device" {print $1}' |
            grep -v '^emulator-' || true
    )

    if [[ "${#physical_devices[@]}" -eq 1 ]]; then
        echo "${physical_devices[0]}"
        return
    fi

    echo "[device-smoke] Could not infer a single physical device. Pass --serial." >&2
    "$ADB" devices -l >&2
    exit 1
}

SERIAL="$(resolve_serial)"

if ! "$ADB" -s "$SERIAL" get-state >/dev/null 2>&1; then
    echo "[device-smoke] Device $SERIAL is not reachable." >&2
    exit 1
fi

mkdir -p "$ANDROID_DIR/app/build/reports/device-smoke"
RUN_STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$ANDROID_DIR/app/build/reports/device-smoke/$RUN_STAMP"
mkdir -p "$RUN_DIR"

APP_APK="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
TEST_APK="$ANDROID_DIR/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
OBSERVER_APK="$ANDROID_DIR/observer/build/outputs/apk/debug/observer-debug.apk"

if $SOURCE_URL_FROM_DESKTOP_CONFIG; then
    SOURCE_URL="$(resolve_source_url_from_desktop_config)" || {
        echo "[device-smoke] Failed to resolve source.url from ~/.config/vless-tun/config.json" >&2
        exit 1
    }
fi

if $SOURCE_INLINE_VLESS_FROM_DESKTOP_CONFIG; then
    SOURCE_URL="$(resolve_inline_vless_from_desktop_config)" || {
        echo "[device-smoke] Failed to resolve inline VLESS URI from ~/.config/vless-tun/config.json" >&2
        exit 1
    }
fi

if [[ -z "$OBSERVER_BOOTSTRAP_IP" ]]; then
    OBSERVER_BOOTSTRAP_IP="$(resolve_observer_bootstrap_ip)" || {
        echo "[device-smoke] Failed to resolve observer bootstrap IP for api.myip.com" >&2
        exit 1
    }
fi

echo "[device-smoke] Target serial: $SERIAL"
echo "[device-smoke] Test class: $TEST_CLASS"
echo "[device-smoke] Report dir: $RUN_DIR"
if [[ -n "$SOURCE_URL" ]]; then
    echo "[device-smoke] Instrumentation source URL: provided"
fi
echo "[device-smoke] Observer bootstrap IP: $OBSERVER_BOOTSTRAP_IP"

if ! $SKIP_BUILD; then
    echo "[device-smoke] Building debug APKs..."
    (
        cd "$ANDROID_DIR"
        ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}" "$GRADLE" \
            :observer:assembleDebug \
            :app:assembleDebug \
            :app:assembleAndroidTest
    )
fi

if [[ ! -f "$APP_APK" || ! -f "$TEST_APK" || ! -f "$OBSERVER_APK" ]]; then
    echo "[device-smoke] APK outputs not found. Build first or drop --skip-build." >&2
    exit 1
fi

install_apk() {
    local apk_path="$1"
    local label="$2"

    echo "[device-smoke] Installing $label..."
    if ! "$ADB" -s "$SERIAL" install -r -t "$apk_path" >"$RUN_DIR/${label}.install.log" 2>&1; then
        cat "$RUN_DIR/${label}.install.log" >&2
        echo "[device-smoke] Install failed for $label. On MIUI this usually means a device-side USB install gate." >&2
        exit 1
    fi
}

if ! $SKIP_INSTALL; then
    install_apk "$OBSERVER_APK" "observer-debug"
    install_apk "$APP_APK" "app-debug"
    install_apk "$TEST_APK" "app-debug-androidTest"
fi

echo "[device-smoke] Waking device and dismissing keyguard if possible..."
"$ADB" -s "$SERIAL" shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
"$ADB" -s "$SERIAL" shell wm dismiss-keyguard >/dev/null 2>&1 || true

echo "[device-smoke] Running instrumentation..."
INSTRUMENT_ARGS=(-e class "$TEST_CLASS")
if [[ -n "$SOURCE_URL" ]]; then
    SOURCE_URL_B64="$(printf '%s' "$SOURCE_URL" | base64 | tr -d '\n')"
    INSTRUMENT_ARGS+=(-e vless_source_url_b64 "$SOURCE_URL_B64")
fi
INSTRUMENT_ARGS+=(-e observer_bootstrap_ip "$OBSERVER_BOOTSTRAP_IP")
INSTRUMENTATION_LOG="$RUN_DIR/instrumentation.log"

set +e
"$ADB" -s "$SERIAL" shell am instrument -w \
    "${INSTRUMENT_ARGS[@]}" \
    "$RUNNER" | tee "$INSTRUMENTATION_LOG"
STATUS=${PIPESTATUS[0]}
set -e

if [[ "$STATUS" -ne 0 ]]; then
    echo "[device-smoke] Instrumentation failed with exit code $STATUS" >&2
    exit "$STATUS"
fi

if rg -q 'shortMsg=Process crashed|INSTRUMENTATION_FAILED|FAILURES!!!|Process crashed' "$INSTRUMENTATION_LOG"; then
    echo "[device-smoke] Instrumentation reported a crash or failure. See $INSTRUMENTATION_LOG" >&2
    exit 1
fi

if ! rg -q '^OK \([0-9]+ test' "$INSTRUMENTATION_LOG"; then
    echo "[device-smoke] Instrumentation did not report a successful OK result. See $INSTRUMENTATION_LOG" >&2
    exit 1
fi

if $PULL_SCREENSHOTS; then
    echo "[device-smoke] Pulling latest screenshot run..."
    LATEST_RUN="$("$ADB" -s "$SERIAL" shell ls -1 "$SCREENSHOT_ROOT" 2>/dev/null | tr -d '\r' | sort | tail -n 1)"
    if [[ -n "$LATEST_RUN" ]]; then
        "$ADB" -s "$SERIAL" pull "$SCREENSHOT_ROOT/$LATEST_RUN" "$RUN_DIR/" >/dev/null
        echo "[device-smoke] Screenshots copied to $RUN_DIR/$LATEST_RUN"
    else
        echo "[device-smoke] No screenshot runs found on device."
    fi
fi

echo "[device-smoke] Success."
echo "[device-smoke] Instrumentation log: $INSTRUMENTATION_LOG"
