# v2RayTun + DanceVPN — Routing and RU Bypass Notes

## Summary

DanceVPN in `v2RayTun` is **not** the same class of setup as Cisco AnyConnect with ASA-pushed split-tunnel policy.

- The VPN endpoint itself comes from a normal `v2RayTun` subscription.
- The subscription is auto-updated from a remote URL.
- Local traffic-routing rules are a **separate layer** inside `v2RayTun`.
- On this machine, that local route layer is currently **disabled**, so `*.ru` traffic is effectively going through the VPN path right now.

**Bottom line:** for `v2RayTun`, the right fix is not to edit the DanceVPN subscription itself. The right fix is to enable local `Routes` / `Traffic Rules` in `v2RayTun`, which should survive subscription updates.

---

## Verified Local State

Observed on this Mac on `2026-03-24`.

### Active tunnel

| Item | Value |
|------|-------|
| App | `v2RayTun 2.2 (19)` |
| Main process | `/Applications/v2RayTun.app/Contents/MacOS/v2RayTun` |
| Packet extension | `/Applications/v2RayTun.app/Contents/PlugIns/packet-extension-mac.appex/Contents/MacOS/packet-extension-mac` |
| Active VPN service | `v2RayTun` |
| Active tunnel interface | `utun6` |

### Current routing symptoms

At the system level, the default IPv4 route is currently captured by `v2RayTun`:

```text
default -> utun6
```

Sample checks for Russian destinations:

- `ya.ru` resolved to `77.88.55.242`, `5.255.255.242`, `77.88.44.242`
- `rbc.ru` resolved to `178.248.236.77`
- `kremlin.ru` resolved to `95.173.136.70`, `95.173.136.71`, `95.173.136.72`

`route -n get` for these IPs returned `interface: utun6`.

### Why this currently means “not bypassed”

The active `current-config.json` has:

- outbound `proxy`
- outbound `block`
- outbound `direct`

But it has **no active routing rules** selecting `direct` for `*.ru`.

The group preferences also show:

```text
V2ROUTES_ENABLED = false
```

So right now `v2RayTun` is running without local traffic rules, which means Russian destinations are not excluded from the VPN logic.

---

## Subscription vs Local Routing

This separation is the key point.

### Subscription layer

Current subscription file:

`~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Library/Application Support/Xray/subscriptions/8D7823B6-D4D5-45FE-9F65-9EBB6486CC80.json`

Verified values:

| Key | Value |
|-----|-------|
| `url` | `https://key.vpn.dance/connect?...` |
| `autoUpdate` | `7200` |
| `metaInfo.updateAlways` | `true` |
| `name` | `🇫🇮 Финляндия` |

`logs.txt` confirms updates really happen:

- `2026-03-24 09:40:27 [info] Subscription 🇫🇮 Финляндия updated successfully`

### Local routing layer

Group preferences file:

`~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Library/Preferences/2XZUN9L63Z.com.databridges.privacy.v2RayTun.plist`

Current keys:

| Key | Value |
|-----|-------|
| `V2RAY_CURRENT` | `82424A51-7742-42E7-BCFE-9C1E66805D8B` |
| `V2ROUTES_ENABLED` | `false` |
| `VPNStatus` | `true` |

This is the important distinction:

- subscription/config files are update-driven
- route selection is tracked separately in app preferences/state

That is why a local bypass in `v2RayTun` is expected to survive subscription refreshes.

---

## Local Storage Layout

Shared app-group container:

`~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/`

Important files:

| Path | Purpose |
|------|---------|
| `logs.txt` | runtime log |
| `geoip.dat` | geo IP database |
| `geosite.dat` | geo site database |
| `Library/Application Support/Xray/subscriptions/*.json` | subscription metadata |
| `Library/Application Support/Xray/configs/*.json` | decoded configs from subscription |
| `Library/Application Support/Xray/current-config.json` | active Xray config used now |
| `Library/Preferences/2XZUN9L63Z.com.databridges.privacy.v2RayTun.plist` | selected config + route-enabled flag |

Current active config file:

`~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Library/Application Support/Xray/current-config.json`

Current observed remote VPN endpoint:

- `144.31.90.46:8443` via `vless + reality + grpc`
- secondary config also exists for `144.31.90.46:8444`

---

## Evidence That Local Traffic Rules Exist

This was verified from the app binary/framework, even though rules are not enabled yet on this machine.

Strings found in `v2RayTun` / `Library.framework`:

- `RouteEntranceView`
- `RouteSettingView`
- `V2RouteRuleSettingView`
- `TrafficRulesAPI`
- `TrafficPresetRulesManager`
- `V2ROUTES_ENABLED`
- `V2ROUTES_SELECTED`
- `directDomains`
- `bypassLan`
- `routeOnly`
- `geosite:category-ru`

Interpretation:

- `v2RayTun` has its own local route / traffic rules feature
- it likely supports presets and/or custom rules
- there is strong evidence that a rule based on `geosite:category-ru` exists or is supported

The `geosite:category-ru` part is based on binary inspection, not on an already-enabled local preset on this machine.

---

## Important Verification Nuance

Once local traffic rules are enabled in `v2RayTun`, **`route -n get` alone is not enough** to prove whether `*.ru` is bypassed.

Reason:

- system traffic may still enter the Network Extension via `utun`
- after that, `v2RayTun` / Xray can decide `proxy` vs `direct` internally

So there are two different questions:

1. Does macOS send the packet into the tunnel interface?
2. Does `v2RayTun` then forward that destination through the remote VPN server or send it out directly?

Right now, because `V2ROUTES_ENABLED=false` and there are no route rules, the answer is effectively “everything goes through the VPN logic”.

After enabling local rules, the correct verification should be **functional**, not just `route get`.

---

## How To Fix It Safely

Do **not** edit these by hand:

- `subscriptions/*.json`
- `configs/*.json`
- `current-config.json`

Those files are tied to subscription refresh and active config generation.

The safe place to apply `*.ru` bypass is the `v2RayTun` UI:

1. Open `v2RayTun`
2. Go to `Routes` / `Traffic Rules`
3. Enable local route rules
4. Use a preset or custom rule that sends Russian destinations to `direct`
5. Reconnect / restart the tunnel

Expected persisted effect:

- `V2ROUTES_ENABLED` should become `true`
- a selected preset / route ID should appear in app state

Most likely desired rule:

- route `geosite:category-ru` to `direct`

This exact rule name is inferred from the binary and has not yet been applied on this machine.

---

## How To Verify After Enabling RU Bypass

### Config-level check

Check the group preferences:

```bash
plutil -p ~/Library/Group\ Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Library/Preferences/2XZUN9L63Z.com.databridges.privacy.v2RayTun.plist
```

Expected:

- `V2ROUTES_ENABLED => true`

### Functional check

Generate traffic to a Russian host:

```bash
curl -I https://ya.ru
```

Then inspect the packet extension connections:

```bash
pgrep -f packet-extension-mac
lsof -nP -p <PID> -iTCP
```

Interpretation:

- if only the remote VPN server (`144.31.90.46:8443` / `8444`) is used, RU bypass is probably not active
- if `packet-extension-mac` opens direct connections to Russian destination IPs, the bypass is working

Alternative check from the physical interface:

```bash
sudo tcpdump -i en0 host 77.88.55.242
```

Then run:

```bash
curl -I https://ya.ru
```

If bypass works, you should see direct traffic to the Russian destination on `en0`.

### Legacy route-table check

This is still useful as a quick hint:

```bash
route -n get 77.88.55.242
```

But after enabling local `v2RayTun` traffic rules, this check is not authoritative on its own.

---

## Practical Difference vs Corp AnyConnect

This is the exact opposite of the Cisco ASA case documented in `corp-vpn-wifi-bypass.md`.

### AnyConnect / ASA

- server pushes the policy
- official client gives no real local override
- local route hacks get reverted

### v2RayTun / DanceVPN

- subscription updates the VPN endpoints/configs
- local traffic rules are a separate app feature
- local route decisions appear to be intentionally supported

So for `v2RayTun`, client-side `*.ru` bypass looks feasible.

---

## Applied Test On 2026-03-24

An actual local route was imported and enabled in `v2RayTun`.

Imported route:

```json
{
  "domainStrategy": "AsIs",
  "domainMatcher": "hybrid",
  "name": "Direct Russia",
  "rules": [
    {
      "__name__": "Direct Russia",
      "type": "field",
      "domain": [
        "regexp:.*\\\\.ru$",
        "geosite:category-ru"
      ],
      "ip": [
        "geoip:ru"
      ],
      "outboundTag": "direct"
    }
  ]
}
```

After enabling it in the app UI, local state changed to:

- `V2ROUTES_ENABLED = true`
- `V2ROUTES_SELECTED` was populated automatically

And the active runtime config was rebuilt with:

- a real `routing` section in `current-config.json`
- `Direct Russia`
- `outboundTag = direct`

So this was not just a stored preset. The route was actually injected into runtime config.

---

## Real-World Verification Result

Despite the route being enabled and present in runtime config, the effective public IP for Russian sites stayed on the VPN egress.

Manual verification:

| Check | Result |
|------|--------|
| non-`ru` IP checker | `144.31.90.46` |
| `https://ip.nic.ru/` | `144.31.90.46` |
| `https://yandex.ru/internet/` IPv4 | `144.31.90.46` |
| Yandex geolocation by IP | Helsinki |

Additional local verification:

- during a live TLS session to `ya.ru:443`, the route existed in runtime config
- `current-config.json` clearly contained `Direct Russia`
- but `.ru` traffic still did not produce a different public IP from the VPN egress

### Conclusion

For this machine and this `v2RayTun` build, **adding a routing rule with `outboundTag: direct` is not sufficient to produce a true `.ru` bypass**.

In other words:

- the route is accepted
- the route is enabled
- the route is present in runtime config
- but Russian websites still see the VPN public IP

So the current state is:

- `v2RayTun` routing rule is configured
- effective `.ru` bypass is **not working**

---

## Most Likely Interpretation

`v2RayTun` appears to have at least two different concepts:

1. Xray routing rules inside runtime config
2. a separate “direct service” / traffic-handling layer in the app

Binary inspection showed related strings such as:

- `DirectServiceEnabled`
- `DirectServicesSelected`
- `TrafficPresetRulesManager`

That strongly suggests `outboundTag: direct` alone does not necessarily mean “exit outside the VPN with the home IP” in `v2RayTun`.

It may only mean:

- route to Xray's `freedom` outbound inside the tunnel architecture

But in practice, that still results in traffic being observed externally as the VPN egress.

So a real bypass may require an additional app feature beyond plain routing rules.

---

## Current Snapshot

As of `2026-03-24`, this machine is in this state:

- DanceVPN subscription updates automatically every `7200` seconds
- local route `Direct Russia` is imported and enabled
- `V2ROUTES_ENABLED=true`
- `V2ROUTES_SELECTED` is populated
- `current-config.json` contains a real `routing` section for `*.ru` / `geoip:ru`
- effective `.ru` bypass is still **not** working
