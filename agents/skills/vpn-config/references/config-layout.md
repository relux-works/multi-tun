# Config Layout

## `vless-tun`

`~/.config/vless-tun/config.json` uses this preferred shape:

```json
{
  "cache_dir": "~/.cache/vless-tun",
  "source": {
    "mode": "proxy",
    "url": "https://key.vpn.dance/connect?key=REPLACE_ME"
  },
  "default": {
    "profile_selector": ""
  },
  "network": {
    "mode": "tun",
    "tun": {
      "interface_name": "utun233",
      "addresses": [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126"
      ]
    },
    "system_proxy": {
      "listen_address": "127.0.0.1",
      "listen_port": 2080
    }
  },
  "routing": {
    "bypass_suffixes": [
      ".ru",
      ".xn--p1ai"
    ]
  },
  "dns": {
    "proxy_resolver": {
      "address": "1.1.1.1",
      "port": 853,
      "tls_server_name": "cloudflare-dns.com"
    }
  },
  "logging": {
    "level": "info"
  },
  "artifacts": {
    "singbox_config_path": "~/.config/vless-tun/generated/sing-box.json"
  }
}
```

Notes:

- `source.mode=proxy` means `source.url` is fetched over HTTP and should resolve to one or more `vless://` entries.
- `source.mode=direct` means `source.url` is already a literal `vless://...` URI.
- `default.profile_selector` is optional. Empty means "first matching profile".
- `network.mode=tun` is the default scaffolded mode; switch to `system_proxy` only when you explicitly want a lighter non-TUN macOS session.
- `reconnect` should be used after changing `network.mode`, `default.profile_selector`, `routing.bypass_suffixes`, `dns.proxy_resolver`, or other render-time settings.
- `cache_dir` stores refresh snapshots, session logs, and the current runtime pointer.
- `artifacts.singbox_config_path` should normally stay under `~/.config/vless-tun/generated/`.
- Omit `launch` in the happy path. `vless-tun` now resolves to the shared `vpn-core` backend automatically when it is available.

## `openconnect-tun`

`~/.config/openconnect-tun/config.json` uses this preferred shape:

```json
{
  "cache_dir": "~/.cache/openconnect-tun",
  "default": {
    "server_url": "vpn.example.com/engineering",
    "profile": "Corp VPN"
  },
  "servers": {
    "vpn.example.com/engineering": {
      "profiles": {
        "Corp VPN": {
          "mode": "full"
        }
      }
    }
  },
  "auth": {
    "username_keychain_account": "corp-vpn/username",
    "password_keychain_account": "corp-vpn/password",
    "totp_secret_keychain_account": "corp-vpn/totp_secret"
  }
}
```

Notes:

- `openconnect-tun setup --vpn-name ...` scaffolds this config in `full` mode with no bypasses.
- `setup` also seeds placeholder keychain entries for username, password, and TOTP secret so the user can review and replace them later.
- The config stores account names, not raw secrets. The actual values should live in the macOS Keychain service `multi-tun`.
- Split-routing policy lives under `servers.<url>.profiles.<profile>.split_include` when the profile is moved from `full` to `split-include`.

Populate or update auth values like this:

```bash
security add-generic-password -U -a 'corp-vpn/username' -s multi-tun -w 'alice'
security add-generic-password -U -a 'corp-vpn/password' -s multi-tun -w 'correct-horse-battery-staple'
security add-generic-password -U -a 'corp-vpn/totp_secret' -s multi-tun -w 'BASE32SECRET'
```

If the user starts from a Google Authenticator export QR, the important distinction is:

- the QR export payload is usually an `otpauth-migration://offline?...` URL
- `data=` inside that URL is URL-encoded base64 protobuf
- the final TOTP secret for Keychain, `oathtool`, and `vpn-auth --totp-secret` is base32

In other words: decode `data=` as URL-encoded base64, parse the protobuf, extract the raw secret bytes, then base32-encode those bytes before storing them.

Verify them like this:

```bash
security find-generic-password -a 'corp-vpn/username' -s multi-tun -w
security find-generic-password -a 'corp-vpn/password' -s multi-tun -w
security find-generic-password -a 'corp-vpn/totp_secret' -s multi-tun -w
```

Generate a current TOTP code from the stored secret with:

```bash
oathtool --totp -b "$(security find-generic-password -a 'corp-vpn/totp_secret' -s multi-tun -w)"
```
