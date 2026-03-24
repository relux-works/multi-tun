# CLI Commands

## Initialize local config

```bash
vless-tun init
vless-tun init --subscription-url "https://key.vpn.dance/connect?key=..."
```

## Refresh subscription cache

```bash
vless-tun refresh
vless-tun refresh --config ~/.config/vless-tun/config.json
```

## List cached profiles

```bash
vless-tun list
vless-tun list --refresh
```

## Start a background tunnel session

```bash
vless-tun run
vless-tun run --refresh
vless-tun run --profile 144.31.90.46:8444
```

## Reconnect with latest config

```bash
vless-tun reconnect
vless-tun reconnect --refresh=false
vless-tun reconnect --profile 144.31.90.46:8444
vless-tun reconnect --force --timeout 10s
```

## Show current status

```bash
vless-tun status
vless-tun status --refresh
```

## Stop the current session

```bash
vless-tun stop
vless-tun stop --force
vless-tun stop --timeout 10s
```

## Render sing-box config

```bash
vless-tun render
vless-tun render --profile finland
vless-tun render --profile 144.31.90.46:8443
vless-tun render --output ~/.config/vless-tun/generated/custom.json
```
