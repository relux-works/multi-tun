# Safe TOTP Import

## User Handoff

Ask the user to:

1. Open Google Authenticator and choose the account transfer/export flow.
2. Select only the account needed for this VPN when possible.
3. Save a screenshot or photo of the displayed export QR as a local image.
4. Give the agent only the absolute local image path.

The image is secret material. Do not attach it to a ticket, commit it, move it into the repository, or upload it to a web decoder.

## Agent Procedure

1. Read the OpenConnect config and resolve the exact `totp_secret_keychain_account` referenced by the selected server/profile.
2. Confirm that the supplied path is a readable image without opening it through vision or OCR.
3. Ensure `zbarimg`, `python3`, and Swift are available. On macOS, `brew install zbar` provides `zbarimg`.
4. Run `scripts/import-google-auth-qr-to-keychain.sh` with the image path and Keychain account.
5. If multiple entries are reported, rerun with `--entry-index`, `--issuer`, or `--account`; do not list decoded entries because listing would expose secrets.
6. Report only that the secret was stored under the configured account. Do not read it back for display.

Example account lookup for the bundled asset:

```bash
jq -er '.servers[.default.server_url].auth.second_factor.totp_secret_keychain_account' \
  ~/.config/openconnect-tun/config.json
```

Example import:

```bash
"$VPN_CONFIG_SKILL_DIR/scripts/import-google-auth-qr-to-keychain.sh" \
  --image '/absolute/path/to/export.png' \
  --keychain-account 'example-vpn/totp-secret' \
  --service 'multi-tun'
```

## Security Properties

- The image is read in place and never modified.
- The QR payload remains inside process memory and is passed through stdin.
- The migration payload is never placed in argv, a temporary file, logs, or stdout.
- The derived base32 secret is passed through stdin to Security.framework.
- The Keychain writer never receives the secret as a command argument.
- Success output contains only the non-secret service and account names.
- The original image is left untouched; deletion requires a separate explicit user request.
