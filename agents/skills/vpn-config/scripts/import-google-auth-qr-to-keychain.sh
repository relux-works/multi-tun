#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_PATH=""
KEYCHAIN_ACCOUNT=""
KEYCHAIN_SERVICE="multi-tun"
SELECTOR_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  import-google-auth-qr-to-keychain.sh \
    --image /absolute/path/to/export.png \
    --keychain-account ACCOUNT \
    [--service SERVICE] \
    [--entry-index N | --issuer NAME | --account NAME]

The QR payload and derived TOTP secret are never printed or written to disk.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      IMAGE_PATH="$2"
      shift 2
      ;;
    --keychain-account)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      KEYCHAIN_ACCOUNT="$2"
      shift 2
      ;;
    --service)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      KEYCHAIN_SERVICE="$2"
      shift 2
      ;;
    --entry-index|--issuer|--account)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      if [[ ${#SELECTOR_ARGS[@]} -ne 0 ]]; then
        echo "error: use only one entry selector" >&2
        exit 2
      fi
      SELECTOR_ARGS=("$1" "$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$IMAGE_PATH" ]] || { echo "error: --image is required" >&2; exit 2; }
[[ -n "$KEYCHAIN_ACCOUNT" ]] || { echo "error: --keychain-account is required" >&2; exit 2; }
[[ -n "$KEYCHAIN_SERVICE" ]] || { echo "error: --service must not be empty" >&2; exit 2; }
[[ -f "$IMAGE_PATH" && -r "$IMAGE_PATH" ]] || { echo "error: image is not a readable regular file" >&2; exit 2; }

QR_READER="${VPN_CONFIG_QR_READER:-$(command -v zbarimg || true)}"
PYTHON_BIN="${VPN_CONFIG_PYTHON:-$(command -v python3 || true)}"
MIGRATION_DECODER="${VPN_CONFIG_MIGRATION_DECODER:-$SCRIPT_DIR/decode-google-auth-migration.py}"
KEYCHAIN_WRITER="${VPN_CONFIG_KEYCHAIN_WRITER:-$SCRIPT_DIR/store-secret-in-keychain.swift}"

[[ -n "$QR_READER" && -x "$QR_READER" ]] || { echo "error: zbarimg is required; install it with 'brew install zbar'" >&2; exit 2; }
[[ -n "$PYTHON_BIN" && -x "$PYTHON_BIN" ]] || { echo "error: python3 is required" >&2; exit 2; }
[[ -f "$MIGRATION_DECODER" ]] || { echo "error: migration decoder is missing" >&2; exit 2; }
[[ -x "$KEYCHAIN_WRITER" ]] || { echo "error: Keychain writer is missing or not executable" >&2; exit 2; }

qr_payload="$($QR_READER --quiet --raw "$IMAGE_PATH")"
[[ -n "$qr_payload" ]] || { echo "error: no QR payload found in image" >&2; exit 2; }
if [[ "$qr_payload" == *$'\n'* ]]; then
  unset qr_payload
  echo "error: image contains multiple QR payloads; provide an image with one export QR" >&2
  exit 2
fi

if [[ ${#SELECTOR_ARGS[@]} -eq 0 ]]; then
  secret="$(printf '%s' "$qr_payload" | "$PYTHON_BIN" "$MIGRATION_DECODER")"
else
  secret="$(printf '%s' "$qr_payload" | "$PYTHON_BIN" "$MIGRATION_DECODER" "${SELECTOR_ARGS[@]}")"
fi
unset qr_payload
[[ "$secret" =~ ^[A-Z2-7]+$ ]] || { unset secret; echo "error: decoder returned an invalid base32 secret" >&2; exit 2; }

printf '%s' "$secret" | "$KEYCHAIN_WRITER" "$KEYCHAIN_ACCOUNT" "$KEYCHAIN_SERVICE"
unset secret
