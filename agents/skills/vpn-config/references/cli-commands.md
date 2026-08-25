# CLI Commands

## Install the skill only

```bash
./scripts/setup.sh --install-vpn-config-skill
```

## VLESS

```bash
vless-tun setup --source-url 'https://vpn-provider.example/connect?key=REPLACE_WITH_SUBSCRIPTION_KEY'
vless-tun refresh
vless-tun list
vless-tun set-current example-subscription default
vless-tun render
vless-tun diagnose config
vless-tun start
vless-tun reconnect
vless-tun status
vless-tun stop
```

Passing a real source URL on the command line can expose it in shell history and process metadata. Prefer editing the mode-`600` local config with a secret-aware tool when the source URL contains a key.

## OpenConnect

```bash
openconnect-tun setup --vpn-name 'Example Engineering VPN' --server-url 'vpn.example.com/engineering'
openconnect-tun profiles
openconnect-tun inspect-profiles
openconnect-tun set-current example-corp engineering
openconnect-tun start example-corp engineering --dry-run
openconnect-tun status
openconnect-tun reconnect example-corp engineering
openconnect-tun stop
```

## Safe TOTP Image Import

```bash
"$VPN_CONFIG_SKILL_DIR/scripts/import-google-auth-qr-to-keychain.sh" \
  --image '/absolute/path/to/google-auth-export.png' \
  --keychain-account 'example-vpn/totp-secret'
```

For a multi-account export, add exactly one selector:

```bash
--entry-index 2
--issuer 'Example Issuer'
--account 'person@example.com'
```
