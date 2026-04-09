# Desktop

Desktop is the current executable workspace for this repo.

## Layout

- `cmd/`: desktop entrypoints
- `internal/core/`: shared desktop infrastructure such as `vpn-core`
- `internal/vless/`: VLESS subscription, config, render, and TUN session code
- `internal/anyconnect/`: Cisco/OpenConnect inspection, auth, and dump tooling

## Commands

- `desktop/cmd/vless-tun`
- `desktop/cmd/openconnect-tun`
- `desktop/cmd/dump`
- `desktop/cmd/cisco-dump`
- `desktop/cmd/vpn-core`
- `desktop/cmd/vpn-auth`
