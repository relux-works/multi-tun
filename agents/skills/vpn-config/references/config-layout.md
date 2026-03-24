# Config Layout

`~/.config/vless-tun/config.json` uses this shape:

```json
{
  "subscription_url": "https://key.vpn.dance/connect?key=REPLACE_ME",
  "selected_profile": "",
  "cache_dir": "~/.cache/vless-tun",
  "render": {
    "mode": "system_proxy",
    "output_path": "~/.config/vless-tun/generated/dancevpn-sing-box.json",
    "interface_name": "utun233",
    "tun_addresses": [
      "172.19.0.1/30",
      "fdfe:dcba:9876::1/126"
    ],
    "proxy_listen_address": "127.0.0.1",
    "proxy_listen_port": 2080,
    "log_level": "info",
    "bypass_suffixes": [
      ".ru",
      ".xn--p1ai"
    ],
    "proxy_dns": {
      "address": "1.1.1.1",
      "port": 853,
      "tls_server_name": "cloudflare-dns.com"
    }
  }
}
```

Notes:

- `selected_profile` is optional. Empty means "first profile in cache".
- `render.mode=system_proxy` is the current macOS-safe default for unprivileged bring-up.
- `reconnect` should be used after changing `render.mode`, `selected_profile`, or `bypass_suffixes`.
- `bypass_suffixes` is intentionally explicit and small; start there before adding heavier rule-set logic.
- `cache_dir` also stores per-session logs in `sessions/` and the current runtime pointer in `runtime/current-session.json`.
- `render.output_path` should normally stay under `~/.config/vless-tun/generated/`.
