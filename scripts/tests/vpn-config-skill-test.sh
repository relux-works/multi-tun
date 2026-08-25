#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SKILL_DIR="$PROJECT_ROOT/agents/skills/vpn-config"
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vpn-config-skill.XXXXXX")"
EXPECTED_SECRET="JBSWY3DPEHPK3PXP"
MIGRATION_URL='otpauth-migration://offline?data=CjAKCkhlbGxvId6tvu8SEnBlcnNvbkBleGFtcGxlLmNvbRoORXhhbXBsZSBJc3N1ZXI%3D'

cleanup() {
  rm -rf "$FIXTURE_DIR"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

jq empty "$SKILL_DIR/assets/openconnect-tun-config.template.json"
jq empty "$SKILL_DIR/assets/vless-tun-config.template.json"

if rg -ni 'mts|мтс|dance|dense|fortinetz|freedom|ural|msk' "$SKILL_DIR" >/dev/null; then
  fail 'skill contains a forbidden provider-specific name'
fi

decoded="$(printf '%s' "$MIGRATION_URL" | python3 "$SKILL_DIR/scripts/decode-google-auth-migration.py" --issuer 'Example Issuer')"
[[ "$decoded" == "$EXPECTED_SECRET" ]] || fail 'migration decoder returned an unexpected secret'
unset decoded

cat > "$FIXTURE_DIR/qr-reader" <<EOF
#!/usr/bin/env bash
printf '%s\n' '$MIGRATION_URL'
EOF
cat > "$FIXTURE_DIR/keychain-writer" <<EOF
#!/usr/bin/env bash
set -euo pipefail
secret="\$(cat)"
[[ "\$secret" == '$EXPECTED_SECRET' ]]
[[ "\$1" == 'example-vpn/totp-secret' ]]
[[ "\$2" == 'multi-tun' ]]
printf '%s\n' 'Stored synthetic test secret without disclosure.'
EOF
printf '%s\n' 'synthetic image fixture' > "$FIXTURE_DIR/export.png"
chmod +x "$FIXTURE_DIR/qr-reader" "$FIXTURE_DIR/keychain-writer"

VPN_CONFIG_QR_READER="$FIXTURE_DIR/qr-reader" \
VPN_CONFIG_KEYCHAIN_WRITER="$FIXTURE_DIR/keychain-writer" \
  "$SKILL_DIR/scripts/import-google-auth-qr-to-keychain.sh" \
    --image "$FIXTURE_DIR/export.png" \
    --keychain-account 'example-vpn/totp-secret' \
    > "$FIXTURE_DIR/import.log" 2>&1

if rg -F "$EXPECTED_SECRET" "$FIXTURE_DIR/import.log" >/dev/null; then
  fail 'importer disclosed the decoded secret'
fi
if rg -F 'otpauth-migration://' "$FIXTURE_DIR/import.log" >/dev/null; then
  fail 'importer disclosed the migration payload'
fi

swiftc -typecheck "$SKILL_DIR/scripts/store-secret-in-keychain.swift"
printf '%s\n' 'vpn-config skill regression tests passed'
