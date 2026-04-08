# Example AnyConnect VPN — Split Tunnel Bypass

All hostnames, domains, profile names, account names, and IPs in this note are anonymized placeholders.

## Problem

This example corporate VPN uses Cisco AnyConnect (Secure Client 5.x) with server-pushed profiles from ASA (Adaptive Security Appliance). The "Outside extended" profile enforces **full tunnel** — all traffic, including personal browsing, streaming, and non-work services, is routed through the corporate VPN.

### Why it can't be fixed on the client side (with AnyConnect)

| Barrier | Detail |
|---------|--------|
| Full tunnel default route | `default → utun9` — no split-tunnel ACL pushed by ASA |
| Scripting disabled | `EnableScripting = false` in server-pushed profile — OnConnect/OnDisconnect scripts won't execute |
| Profile overwrite | `BypassDownloader = false` — server overwrites local profile on every connect |
| Route monitoring | AnyConnect actively monitors routing table and reverts manual `route add/delete` changes within seconds |
| No client-side split-tunnel config | AnyConnect has no UI or local config option to override server-pushed routing policy |

**Bottom line:** with the official Cisco client, split tunneling can only be configured server-side on the ASA by network admins.

---

## Solution

Replace the official Cisco AnyConnect client with **openconnect** + **vpn-slice**.

### Components

| Tool | Purpose | Install |
|------|---------|---------|
| [openconnect](https://www.infradead.org/openconnect/) | Open-source VPN client, compatible with Cisco ASA (AnyConnect protocol) | `brew install openconnect` |
| [vpn-slice](https://github.com/dlenski/vpn-slice) | Replaces the default vpnc-script; sets up only specified routes and DNS domains | `pipx install vpn-slice` |

### How it works

```
┌──────────────────────────────────────────────────────────┐
│  openconnect                                             │
│  - Connects to the same ASA servers as AnyConnect        │
│  - Same credentials, same certificate auth               │
│  - But does NOT blindly accept server-pushed routes      │
│  - Delegates routing setup to --script parameter         │
│                                                          │
│  vpn-slice (called as --script)                          │
│  - Receives VPN interface info from openconnect          │
│  - Adds routes ONLY for specified subnets                │
│  - Configures DNS ONLY for specified domains             │
│  - Default route stays on physical interface (en0/Wi-Fi) │
└──────────────────────────────────────────────────────────┘
```

**Traffic flow after connect:**

```
*.corp.example, 10.x.x.x, 198.51.100.x  ──→  utun (VPN tunnel)  ──→  corporate network
everything else                    ──→  en0 (Wi-Fi/LAN)    ──→  internet direct
```

---

## Infrastructure

### VPN servers (from AnyConnect profile `cp_corp_inside_3.xml`)

| Name | Address | Backup servers |
|------|---------|---------------|
| MSK Outside | `vpn-gw1.corp.example/outside` | vpn-gw2.corp.example, vpn-gw3.corp.example |
| Ural Outside | `vpn-gw2.corp.example/outside` | vpn-gw1.corp.example, vpn-gw3.corp.example |
| DV Outside | `vpn-gw3.corp.example/outside` | vpn-gw2.corp.example, vpn-gw1.corp.example |

Resolved IPs (as of 2026-03-23):
- `vpn-gw1.corp.example` → `198.51.100.243`
- `vpn-gw2.corp.example` → `198.51.100.22`
- `vpn-gw3.corp.example` → `198.51.100.36`

Inside servers (`*.region.corp.example`) don't resolve from external DNS — they require VPN to be already connected. Not used in this setup.

### Example network ranges (routed through VPN)

#### RFC1918 — corporate internal

| Range | Purpose |
|-------|---------|
| `10.0.0.0/8` | Main internal corporate network |
| `172.16.0.0/12` | Secondary internal ranges |
| `192.168.0.0/16` | Lab/dev networks (may overlap with home LAN — see caveats) |

#### Public ranges

| Range | WHOIS netname | Known services |
|-------|---------------|----------------|
| `198.51.100.0/24` | EXAMPLE-CORP-EDGE | Jira (`198.51.100.127`), Confluence (`198.51.100.128`), GitLab |
| `192.0.2.0/24` | EXAMPLE-CORP-VPN | VPN infrastructure |
| `203.0.113.0/24` | EXAMPLE-CORP-WEB | `corp.example` frontend (`203.0.113.27`) |

#### DNS domains (resolved via VPN DNS)

- `corp.example`
- `digital.example`
- `it-services.example`
- `services.corp.example`

---

## Script: `~/.scripts/corp-vpn`

Location: `~/.scripts/corp-vpn`

### Usage

```bash
corp-vpn              # connect via Ural Outside (default)
corp-vpn msk          # connect via MSK Outside
corp-vpn dv           # connect via DV Outside
corp-vpn disconnect   # disconnect
corp-vpn status       # show connection status & routes
corp-vpn routes       # show configured corporate subnets
corp-vpn help         # usage info
```

### Prerequisites

```bash
# 1. Install openconnect
brew install openconnect

# 2. Install vpn-slice
brew install pipx    # if not installed
pipx install vpn-slice

# 3. Add ~/.scripts to PATH (in ~/.zshrc)
export PATH="$HOME/.scripts:$PATH"

# 4. Quit Cisco AnyConnect / Secure Client completely
#    (disconnect + quit from menu bar)
```

### How to connect

```bash
# First time — will prompt for credentials
corp-vpn

# Enter username/password when prompted
# sudo password also needed (openconnect creates tun interface)
```

### What happens on connect

1. `openconnect` establishes tunnel to `vpn-gw2.corp.example/outside` (Ural)
2. `vpn-slice` is called instead of default vpnc-script
3. vpn-slice adds routes **only** for the example corporate subnets listed above
4. vpn-slice configures DNS for `*.corp.example` domains to use VPN DNS server
5. Default route stays on `en0` (Wi-Fi) — internet goes direct

### What happens on disconnect

```bash
corp-vpn disconnect
```

1. openconnect process is killed
2. VPN routes are removed automatically
3. DNS config reverts to normal

---

## Caveats & Troubleshooting

### 1. AnyConnect conflict

openconnect and AnyConnect cannot run simultaneously — they compete for the tun interface. Always disconnect and quit AnyConnect before using `corp-vpn`.

If AnyConnect daemon is running in background:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.cisco.secureclient.vpnagentd.plist
```

To re-enable AnyConnect later:
```bash
sudo launchctl load /Library/LaunchDaemons/com.cisco.secureclient.vpnagentd.plist
```

### 2. Home LAN overlap with 192.168.0.0/16

If your home network uses `192.168.x.x` (most do), routing this range through VPN will break local network access. Options:

- **Remove `192.168.0.0/16`** from `CORP_ROUTES` in the script — unless you need access to corporate resources in this range
- Or use a more specific route like `192.168.100.0/24` if you know the exact corporate subnet

### 3. Missing corporate service after connect

If a corporate service doesn't load:

```bash
# 1. Find its IP
dig +short service.corp.example

# 2. Check if it's in a routed range
#    If not — add the range to CORP_ROUTES in the script

# 3. Quick temporary fix (add route manually)
sudo route add -net 1.2.3.0/24 -interface utunX
```

### 4. Certificate authentication

The Outside profile uses password auth. If you need Inside (cert-based) access:

```bash
sudo openconnect \
    --protocol=anyconnect \
    --certificate /path/to/client-cert.pem \
    --sslkey /path/to/client-key.pem \
    --script "vpn-slice 10.0.0.0/8 172.16.0.0/12 198.51.100.0/24" \
    vpn-gw1.internal.corp.example/inside
```

### 5. Logs

```bash
# Connection log
cat /tmp/corp-vpn.log

# PID file
cat /tmp/corp-vpn-openconnect.pid
```

---

## AnyConnect profile analysis

Source files: `~/Downloads/cisco-anyconnect-profiles/`

### Profiles on disk

| File | Description |
|------|-------------|
| `profiles/cp_corp_inside_3.xml` | Main profile, 9 server entries (MSK/Ural/DV × Base/Outside/Inside), cert matching (example VPN CA) |
| `profiles/cp_corp_outside.xml` | Outside-only profile, no server list, just client settings |
| `AnyConnectLocalPolicy.xml` | Local policy for AnyConnect 4.x (`BypassDownloader=false`) |
| `AnyConnectLocalPolicy_secureclient.xml` | Local policy for Secure Client 5.x |

### Key profile settings (blocking client-side bypass)

```xml
<!-- Scripting disabled — OnConnect hooks won't run -->
<EnableScripting UserControllable="false">false</EnableScripting>

<!-- PPP exclusion disabled — no client-side route exclusion -->
<PPPExclusion UserControllable="false">Disable</PPPExclusion>

<!-- Local LAN access allowed — only concession -->
<LocalLanAccess UserControllable="false">true</LocalLanAccess>

<!-- Auto-reconnect enforced -->
<AutoReconnect UserControllable="false">true</AutoReconnect>
```

### LocalPolicy settings

```xml
<!-- Server controls profile updates -->
<BypassDownloader>false</BypassDownloader>

<!-- Scripts not restricted from server push (but profile disables them anyway) -->
<RestrictScriptWebDeploy>false</RestrictScriptWebDeploy>
```

---

## File locations

| What | Path |
|------|------|
| corp-vpn script | `~/.scripts/corp-vpn` |
| AnyConnect profiles (backup) | `~/Downloads/cisco-anyconnect-profiles/` |
| AnyConnect client config | `~/.vpn/.anyconnect` |
| System AnyConnect profiles | `/opt/cisco/secureclient/vpn/profile/` |
| System AnyConnect scripts | `/opt/cisco/secureclient/vpn/script/` (empty) |
| System AnyConnect local policy | `/opt/cisco/secureclient/AnyConnectLocalPolicy.xml` |
| openconnect vpnc-script | `/opt/homebrew/etc/vpnc/vpnc-script` |
| Connection log | `/tmp/corp-vpn.log` |
| PID file | `/tmp/corp-vpn-openconnect.pid` |

---

## Date

2026-03-23
