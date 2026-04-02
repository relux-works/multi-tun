# CLI Commands

## Scaffold local config

```bash
vless-tun setup --source-url "https://key.vpn.dance/connect?key=..."
vless-tun setup --source-url "vless://uuid@example.com:443?security=reality#demo"
openconnect-tun setup --vpn-name "Corp VPN"
openconnect-tun setup --vpn-name "Corp VPN" --server-url "vpn.example.com/engineering"
```

`vless-tun init` remains available as a compatibility alias for the older bootstrap flow.

## Refresh subscription cache

```bash
vless-tun refresh
vless-tun refresh --config ~/.config/vless-tun/config.json
```

## List cached profiles

```bash
vless-tun list
vless-tun list --refresh
openconnect-tun profiles
openconnect-tun inspect-profiles
```

## Start a background tunnel session

```bash
vless-tun run
vless-tun run --refresh
vless-tun run --profile finland

openconnect-tun start --profile "Corp VPN"
openconnect-tun start --server "vpn.example.com/engineering"
```

## Reconnect with latest config

```bash
vless-tun reconnect
vless-tun reconnect --refresh=false
vless-tun reconnect --profile finland
vless-tun reconnect --force --timeout 10s

openconnect-tun reconnect --profile "Corp VPN"
openconnect-tun reconnect --server "vpn.example.com/engineering"
```

## Show current status

```bash
vless-tun status
vless-tun status --refresh

openconnect-tun status
```

## Stop the current session

```bash
vless-tun stop
vless-tun stop --force
vless-tun stop --timeout 10s

openconnect-tun stop
```

## Render sing-box config

```bash
vless-tun render
vless-tun render --profile finland
vless-tun render --output ~/.config/vless-tun/generated/custom.json
```
