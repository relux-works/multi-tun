# Config Layout

## VLESS

Start from `assets/vless-tun-config.template.json`.

- `current.server` selects a key under `servers`.
- `current.profile` selects a key under that server's `profiles`.
- `source.mode=proxy` fetches a subscription whose response contains one or more `vless://` entries.
- `source.mode=direct` treats `source.url` as a literal `vless://` URI.
- `profiles.<name>.selector` optionally selects one entry from a subscription. An empty selector uses the first matching entry.
- `network.mode` should be `tun`.
- `routing.bypass_suffixes`, `routing.bypass_exclude_suffixes`, and `routing.routes` control direct routing.
- `dns.proxy_resolver` configures DNS through the tunnel.
- `artifacts.singbox_config_path` points to generated runtime JSON, never to a committed artifact.

The following values are sensitive even when embedded inside a URL: subscription keys, UUIDs, hostnames, ports, Reality public keys, short IDs, SNI values, and endpoint labels. Replace all of them before sharing.

## OpenConnect

Start from `assets/openconnect-tun-config.template.json`.

- `default.server_url` selects a key under `servers`.
- `default.profile` selects a key under that server's `profiles`.
- `servers.<alias>.server_url` is the real gateway host or host/path.
- `servers.<alias>.profiles.<alias>.name` is the profile label passed to OpenConnect.
- `mode=full` sends all traffic through the tunnel.
- `mode=split-include` uses the profile's `split_include` routes and domains.
- `auth.*_keychain_account` fields contain Keychain account names, not values.
- `auth.second_factor.mode=totp_auto` enables automatic TOTP retrieval from the configured Keychain account.

The default macOS Keychain service used by this project is `multi-tun`. An account name such as `example-vpn/totp-secret` is safe to keep in config; the secret stored under that account is not.

## Constructing a Shareable File

1. Copy the matching asset rather than copying a live config.
2. Replace placeholder labels only when the replacement itself is non-sensitive.
3. Keep all secret-bearing URL components as `REPLACE_WITH_*` placeholders.
4. Use reserved example domains and documentation IP ranges in published examples.
5. Run `jq empty` and the relevant CLI diagnostic.
6. Compare against the live config without printing values and assert that no live source URL appears in the shareable file.
