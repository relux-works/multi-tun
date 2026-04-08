# v2RayTun Apple Audit

Date: 2026-04-08

Scope:
- Inspect the installed macOS `v2RayTun.app` bundle copied from `/Applications`.
- Look for evidence of a localhost listener / proxy surface relevant to the Habr localhost-leak claims.
- Avoid starting a fresh VPN session unless needed.

Copied bundle:
- `artifacts/v2raytun-apple-audit/v2RayTun.app`

## Inventory

The copied bundle is a native macOS app, not an iOS-on-Mac stub:
- Main app bundle id: `com.databridges.privacy.v2RayTun`
- App extension bundle id: `com.databridges.privacy.v2RayTun.packet-extension-mac`
- System extension bundle id: `com.databridges.privacy.v2RayTun.snextension`

The packet tunnel app extension declares:
- `NSExtensionPointIdentifier = com.apple.networkextension.packet-tunnel`
- `NSExtensionPrincipalClass = packet_extension_mac.PacketTunnelProvider`

Evidence:
- `artifacts/v2raytun-apple-audit/v2RayTun.app/Contents/PlugIns/packet-extension-mac.appex/Contents/Info.plist:47-52`

Both the app and the packet/system extensions are signed with:
- `com.apple.developer.networking.networkextension = packet-tunnel-provider`
- `com.apple.security.network.server = true`

This entitlement alone does not prove a loopback listener is used, but it removes the argument that the extension is structurally incapable of hosting one.

## Static Binary Findings

The Apple binaries contain strong Xray / SOCKS / tunnel-bridge indicators:
- `Xray`
- `Tun2SocksKit`
- `Socks5Tunnel`
- `Starting socks5 tunnel for ping...`
- `socks5://[::1]:1080`

Important caveat:
- The string `Starting socks5 tunnel for ping...` suggests there is at least one ping-specific SOCKS path.
- On its own, that string does not prove the main VPN path also uses localhost.

## Runtime Artifact Findings

The decisive evidence comes from the local app-group runtime files under:
- `~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun`

Observed files:
- `Configs/current-config.json`
- `Configs/socks-config.yml`
- `Library/Application Support/Xray/current-config.json`
- `Library/Application Support/Xray/socks-config.yml`
- `logs.txt`

### Current Xray Config

The saved runtime config contains a single inbound:
- protocol: `socks`
- listen: `[::1]`
- port: `1080`
- no visible auth fields in the saved inbound settings

Evidence:
- `~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Configs/current-config.json:5-23`

That same config also contains the normal user outbound VLESS connection and routing rules, which means this is not a standalone ping-only config snapshot.

Practical implication:
- the localhost listener is not just present in the saved config; it also does not appear to be guarded by explicit username/password settings in that snapshot

### Tun-to-SOCKS Bridge Config

The saved tunnel bridge config points tunnel traffic at loopback SOCKS:
- `address: ::1`
- `port: 1080`

Evidence:
- `~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Configs/socks-config.yml:1-7`

### Logs

The logs repeatedly show the main startup sequence:
- `Xray response: {"success":true}`
- `Primary inbound (DEFAULT) -> ::1:1080`
- `Starting SOCKS5 tunnel on ::1:1080…`
- `Tunnel started`

Evidence:
- `~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/logs.txt:221-224`
- `~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/logs.txt:1015-1018`

This is the strongest local evidence in the audit. It indicates the normal macOS tunnel path uses a localhost SOCKS inbound on `::1:1080`, not just a packet-tunnel-to-remote direct path with no local proxy surface.

## What Was Not Confirmed

I did not find evidence in the saved `current-config.json` that Xray's public API / `HandlerService` is enabled:
- no `api` block
- no configured API inbound in the saved runtime config

The extension binary does contain generic Xray gRPC / stats / routing service strings, but those also exist in embedded Xray codebases even when not enabled at runtime.

So the current audit supports:
- localhost SOCKS exposure exists on macOS in `v2RayTun`

The current audit does not yet support:
- exposed Xray management API at runtime

## Safe Dynamic Check

At audit time:
- `v2RayTun` app process was running
- `::1:1080` was not currently listening

Interpretation:
- the localhost SOCKS listener appears to be session-scoped, not permanently resident while the app is idle

That does not weaken the main finding. The relevant question is whether the listener appears during an active tunnel session, and the saved logs/configs show that it does.

## Live Proof

On 2026-04-08 I started a fresh session from the macOS app UI and then tested the localhost SOCKS listener from an unrelated shell process.

### Session Bring-Up

Observed after pressing the main connect button:
- `VPNStatus = 1`
- `packet-ex ... TCP [::1]:1080 (LISTEN)`
- log entries:
  - `Trying to start tunnel`
  - `Primary inbound (DEFAULT) -> ::1:1080`
  - `Starting SOCKS5 tunnel on ::1:1080…`
  - `Tunnel started`

Evidence:
- `~/Library/Group Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/logs.txt:1650-1658` (latest startup lines around 2026-04-08 17:34:26 local time)

### No-Auth SOCKS Handshake

Raw SOCKS5 greeting from a normal shell process:

```text
printf '\x05\x01\x00' | nc -6 -w 2 ::1 1080 | xxd -p
0500
```

Interpretation:
- `05 00` means SOCKS version 5, auth method `NO AUTHENTICATION REQUIRED`

This is the cleanest proof that the local listener accepted an unauthenticated client connection from outside the app.

### Real Request Through The Listener

Explicit SOCKS request from a normal shell process:

```text
curl -m 8 -sS -o /tmp/v2raytun-socks-test.out -w '%{http_code}\n' \
  --socks5-hostname '[::1]:1080' https://api.ipify.org
200
cat /tmp/v2raytun-socks-test.out
144.31.90.46
```

Interpretation:
- the request completed successfully through the localhost SOCKS listener
- the shell process did not need credentials to use it

### Cleanup

After the proof run, the tunnel was stopped again:
- `VPNStatus = 0`
- `::1:1080` no longer listening
- log lines:
  - `Tunnel stopped (reason: 1)`
  - `SOCKS exit -> 0`

## Preliminary Conclusion

For macOS, `v2RayTun` is not a clean counterexample to the localhost-proxy thesis.

The local evidence strongly suggests:
- `v2RayTun` uses a localhost SOCKS inbound on `::1:1080`
- a tun-to-SOCKS bridge feeds traffic into that listener
- this is part of the normal tunnel bring-up path, not merely an isolated ping helper

What this means for the iOS discussion:
- this does not prove the iOS build behaves identically
- but it materially weakens the claim that the Apple implementation family is obviously immune just because it is packaged as a packet tunnel extension

## Next Questions

1. Inspect whether the iOS binary is likely to share the same `Library.framework` / core tunnel plumbing.
2. Determine whether any runtime API socket / gRPC management surface is exposed in addition to the SOCKS inbound.
