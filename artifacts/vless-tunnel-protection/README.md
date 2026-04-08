# VLESS Tunnel Protection Notes

Updated: 2026-04-08

Scope: this note captures a quick technical assessment of the Android "localhost attack" claims around mobile VLESS/Xray/sing-box clients. It is based on public primary sources and public proof-of-concept materials. It does not include a local Android device reproduction.

## Executive Summary

The core claim is technically credible: if a mobile client exposes a local SOCKS or control API listener on `127.0.0.1` without strong access control, another app on the same Android device can potentially connect to it and learn tunnel metadata or use the tunnel directly.

The broadest claims in the article are not fully supported. The issue is mode- and client-dependent, not a proof that every mobile VLESS client is vulnerable in the same way. The strongest supported conclusion is narrower:

- Android per-app VPN controls traffic routing, not localhost isolation.
- Local proxy listeners on loopback are a real same-device attack surface.
- Xray control APIs are much riskier than plain local SOCKS if exposed.

## Confirmed Findings

### 1. Android `VpnService` is a routing primitive, not localhost isolation

Android documents per-app VPN as an allowlist or denylist over app traffic routed through `VpnService`. Apps outside the VPN use the normal system network. The platform docs do not describe localhost isolation as part of this mechanism.

References:

- [Android VPN docs](https://developer.android.com/develop/connectivity/vpn)
- [Android `VpnService` reference](https://developer.android.com/reference/android/net/VpnService)

### 2. Android apps can reach each other through loopback listeners

The `Local Mess` disclosure documents that Android apps and browsers can communicate over `127.0.0.1` without platform mediation. That does not prove the exact Habr scenario by itself, but it strongly supports the core assumption that localhost listeners are reachable across apps on the same device.

References:

- [Local Mess disclosure](https://localmess.github.io/)
- [USENIX-linked project page](https://localmess.github.io/#description)

### 3. `sing-box` SOCKS and mixed inbounds are unauthenticated if users are empty

The official `sing-box` docs state that SOCKS inbound authentication is disabled when `users` is empty. The same is true for `mixed` inbound.

References:

- [sing-box SOCKS inbound](https://sing-box.sagernet.org/configuration/inbound/socks/)
- [sing-box mixed inbound](https://sing-box.sagernet.org/configuration/inbound/mixed/)

### 4. Xray SOCKS inbound defaults to `noauth`

The official Xray docs document SOCKS inbound with `auth: "noauth"` as the default.

Reference:

- [Xray SOCKS inbound](https://xtls.github.io/en/config/inbounds/socks.html)

### 5. Xray `HandlerService` materially expands the blast radius

The official Xray API docs state that `HandlerService` can add, remove, and list inbounds/outbounds and manage inbound users. If this API is exposed on localhost in a consumer client without access control, the risk is meaningfully higher than a plain local proxy listener.

Reference:

- [Xray API interface](https://xtls.github.io/en/config/api.html)

### 6. The issue is not universal across all mobile client modes

Official `sing-box for Android` docs describe direct operation through `VpnService` and TUN. This matters because the Habr article frames the problem as if all mobile clients necessarily expose a local SOCKS hop. That is too broad. Some clients and modes can operate through direct TUN plumbing instead of a localhost proxy bridge.

References:

- [sing-box for Android](https://sing-box.sagernet.org/clients/android/)
- [sing-box for Android features](https://sing-box.sagernet.org/clients/android/features/)
- [sing-box client model overview](https://sing-box.sagernet.org/manual/proxy/client/)

### 7. VPN presence detection is a separate and easier problem

Android exposes VPN as a network transport capability. An app does not need the localhost attack to infer that a VPN is active at all.

Reference:

- [Android `NetworkCapabilities.TRANSPORT_VPN`](https://developer.android.com/reference/android/net/NetworkCapabilities)

## Assessment Of The Habr Claims

Source under review:

- [Habr article, published 2026-04-07](https://habr.com/ru/articles/1020080/)
- [Public PoC repository](https://github.com/runetfreedom/per-app-split-bypass-poc)
- [Related detector repository](https://github.com/cherepavel/VPN-Detector)

### Credible

- Another app on the same Android device may be able to connect to an unauthenticated localhost proxy listener.
- If that listener is the tunnel's local egress point, the app may learn the tunnel's observed exit IP or use the proxy directly.
- Exposing Xray API services such as `HandlerService` on localhost is a serious design mistake for an end-user client.

### Plausible But Not Fully Verified Here

- The claim that private spaces or work-profile-style isolation still leak access to the same localhost listeners may be true, but this note does not independently verify that point from platform documentation or local testing.

### Overstated Or Not Publicly Proven

- "All mobile clients based on xray/sing-box" are vulnerable in the same way.
- "There is no safe VLESS client" as a universal statement.
- "Traffic decryption" as a general consequence. The article explicitly withholds the second vulnerability chain, so this note does not treat that as established.
- "All VPNs will soon be blocked" as an engineering conclusion from the technical findings alone.

## Hardening Guidance

### Client-side design

- Prefer direct TUN-based designs over localhost SOCKS or mixed proxy bridges when the platform supports it.
- Do not expose local SOCKS or mixed inbounds unless they are strictly necessary.
- If a local proxy listener is required, require per-device random credentials and treat localhost as hostile.
- Do not expose Xray API in consumer clients by default. If it must exist, limit services aggressively and protect the control plane.
- Treat UDP separately and verify its authentication semantics in the exact client stack before assuming parity with TCP.

### Operational mitigations

- Assume hostile apps on the device may detect that a VPN is active even without localhost exposure.
- Treat separate entry IP and exit IP as a resilience measure, not as a fix for localhost exposure.
- Do not rely on per-app VPN alone as a containment boundary against on-device spyware.

### Implications for this repository

- Generated configs should not introduce local `socks`, `mixed`, or Xray API listeners by default.
- If local helper proxy modes are ever added, they should be explicit, opt-in, and authenticated.
- Security notes for VLESS workflows should distinguish between proxy mode, redirect mode, and direct TUN mode instead of treating them as equivalent.

## Repo-Specific macOS Assessment

This repository's macOS `vless-tun` path is not uniformly exposed to the same issue. The answer depends on render mode.

### `network.mode=tun` (default)

Current default config selects `tun` mode. In that mode the renderer creates a single `tun` inbound and does not render a local `socks`, `mixed`, `http`, or Xray API listener.

Conclusion:

- The Android-style localhost proxy attack does not apply in the same direct form to the default macOS `vless-tun` path.
- There is no localhost proxy in the rendered config for another local process to connect to.

Important nuance:

- A local macOS process can still learn the tunnel exit IP by simply making its own outbound request, because full-device TUN mode routes that process through the VPN too.
- That is not a localhost exposure bug; it is an inherent property of full-tunnel device-wide routing.

### Historical `network.mode=system_proxy`

This repo previously had an optional `system_proxy` mode that rendered a local `mixed` inbound on loopback and enabled `set_system_proxy`. That mode has been removed because it created an unnecessary same-device localhost trust surface and there was no remaining product value in keeping a local proxy listener as a first-class path.

### Practical repo takeaway

- Current `tun` mode: not vulnerable to the specific localhost-listener issue described in the Android article.
- Historical `system_proxy` mode: removed from the repo because it was locally exposed by design.

## Confidence And Limits

Confidence is high on the platform and product facts referenced above, because they come from official Android, `sing-box`, and Xray documentation plus the public `Local Mess` disclosure.

Confidence is moderate on the exact breadth of affected third-party mobile clients, because that depends on each client's runtime wiring and default mode. This note does not claim a full client-by-client audit.
