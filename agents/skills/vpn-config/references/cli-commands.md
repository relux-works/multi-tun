# CLI Commands

## Scaffold local config

```bash
vless-tun setup --source-url "https://key.vpn.dance/connect?key=..."
vless-tun setup --source-url "vless://uuid@example.com:443?security=reality#demo"
openconnect-tun setup --vpn-name "Corp VPN"
openconnect-tun setup --vpn-name "Corp VPN" --server-url "vpn.example.com/engineering"
```

`vless-tun init` remains available as a compatibility alias for the older bootstrap flow.

## Seed OpenConnect auth in Keychain

```bash
security add-generic-password -U -a 'corp-vpn/username' -s multi-tun -w 'alice'
security add-generic-password -U -a 'corp-vpn/password' -s multi-tun -w 'correct-horse-battery-staple'
security add-generic-password -U -a 'corp-vpn/totp_secret' -s multi-tun -w 'BASE32SECRET'
```

For Google Authenticator export QR, do not store the `data=` blob directly. The QR usually contains an `otpauth-migration://offline?...` URL where `data=` is URL-encoded base64 protobuf. Decode it, extract the raw secret bytes, then base32-encode those bytes and store that final base32 value in Keychain.

```bash
python3 - <<'PY'
import base64
import sys
import urllib.parse
from urllib.parse import parse_qs, urlparse

url = sys.stdin.read().strip()
data = parse_qs(urlparse(url).query)["data"][0]
raw = base64.b64decode(urllib.parse.unquote(data))

def read_varint(buf, i):
    value = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, i
        shift += 7

def read_len(buf, i):
    size, i = read_varint(buf, i)
    return buf[i:i + size], i + size

i = 0
while i < len(raw):
    tag = raw[i]
    i += 1
    field = tag >> 3
    wire = tag & 0x07
    if wire == 2:
        value, i = read_len(raw, i)
        if field == 1:
            j = 0
            while j < len(value):
                inner_tag = value[j]
                j += 1
                inner_field = inner_tag >> 3
                inner_wire = inner_tag & 0x07
                if inner_wire == 2:
                    inner_value, j = read_len(value, j)
                    if inner_field == 1:
                        print(base64.b32encode(inner_value).decode())
                        raise SystemExit(0)
                elif inner_wire == 0:
                    _, j = read_varint(value, j)
                else:
                    raise SystemExit(f"unsupported protobuf wire type: {inner_wire}")
    elif wire == 0:
        _, i = read_varint(raw, i)
    else:
        raise SystemExit(f"unsupported protobuf wire type: {wire}")
PY
```

## Read stored OpenConnect auth

```bash
security find-generic-password -a 'corp-vpn/username' -s multi-tun -w
security find-generic-password -a 'corp-vpn/password' -s multi-tun -w
security find-generic-password -a 'corp-vpn/totp_secret' -s multi-tun -w
```

## Generate a TOTP code from Keychain

```bash
oathtool --totp -b "$(security find-generic-password -a 'corp-vpn/totp_secret' -s multi-tun -w)"
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
