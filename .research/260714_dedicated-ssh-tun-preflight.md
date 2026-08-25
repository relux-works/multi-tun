# Dedicated SSH TUN Preflight

- Board task: `TASK-260714-dslhb4` — Probe dedicated SSH TUN prerequisites
- Parent: `STORY-260714-1i10gt` — Provision dedicated SSH TUN gateway
- Date: 2026-07-14
- Scope: read-only local and dedicated-Mac inspection. No changes were made to remote `sshd`, PF, sysctls, routes, launchd, or user files.

## Decision

Select **local TUN-to-SOCKS over the managed `ssh-proxy` dynamic-forward transport** for v1. Defer an OpenSSH `-w` gateway until a separately authorized remote provisioning task can prove and configure its server prerequisites.

This is not a claim that macOS OpenSSH lacks tunnel code: both hosts parse `-w`, and their binaries expose tunnel-related markers. It is a conservative decision based on the prerequisites that are currently not affirmed: an effective `sshd PermitTunnel` result, a user-accessible tunnel device, remote IP forwarding, and inspectable PF/NAT state.

## Key Takeaways

- The configured dedicated-Mac account permits practical SSH dynamic forwarding: a bounded local SOCKS5 request successfully opened a channel to the remote loopback SSH listener, then the test process was removed and a normal management SSH connection was rechecked.
- OpenSSH `-w` parser support is necessary but insufficient. OpenSSH documents that `PermitTunnel` defaults to `no`, and a VPN also requires separate interface and route configuration on both hosts.
- The dedicated Mac currently has IPv4 and IPv6 forwarding disabled. PF status/NAT inspection and `sshd -T` effective-config evaluation require elevation that is unavailable through `sudo -n`.
- Both hosts expose `utun` interfaces but no traditional `tun*` or `tap*` device nodes in the preflight. This observation alone is not a platform verdict; it is another reason not to provision `-w` blindly.
- `sing-box` 1.13.3 is installed locally and has documented TUN-inbound plus SOCKS-outbound building blocks. Local TUN launch still needs an interactive privileged path (`sudo -n` is unavailable).
- The remote management peer route used the physical default interface during preflight. A local TUN design must explicitly exclude the dedicated-Mac SSH endpoint from TUN routing to avoid self-capturing the SSH carrier.

## Evidence

| Area | Read-only evidence | Assessment |
| --- | --- | --- |
| Local OpenSSH `-w` | `ssh -G -w any:any` accepted the request and reported point-to-point tunnel mode and `any:any` device selection. | Syntax support only; not a live gateway proof. |
| Dedicated-Mac OpenSSH `-w` | The same parser check exited successfully. Remote platform recorded as Intel macOS 15.7.4. | Syntax support only. |
| Tunnel-device visibility | Both hosts reported zero traditional `tun*`/`tap*` nodes and active `utun*` interfaces. | Do not infer a usable `-w` device from parser success. |
| Dedicated-Mac `PermitTunnel` | User-level `sshd -T -C ...` could not read required host-key material; `sudo -n` was unavailable. The readable config had no relevant global/Match/include override. | No affirmative effective `PermitTunnel` evidence. Treat `-w` as not approved; upstream default is `no`. |
| Dedicated-Mac forwarding | `net.inet.ip.forwarding=0`; `net.inet6.ip6.forwarding=0`. | It is not currently an L3 gateway. |
| Dedicated-Mac PF/NAT | PF state and NAT reads required elevation; non-interactive elevation was unavailable. Config parse/read was not used to infer an active NAT policy. | NAT feasibility is unverified and must not be assumed. |
| Dynamic SSH forwarding | A non-interactive transient `ssh -N -D` listener came up on local loopback. A byte-level SOCKS5 greeting and `CONNECT` to the remote loopback SSH port succeeded. | The account can use local TCP forwarding, which is sufficient for an SSH SOCKS carrier. |
| Cleanup and management safety | The transient SSH child was terminated; no test listener remained. A fresh non-interactive management SSH check succeeded. The remote peer route was on the physical default interface (`en0`) during preflight. | Current management access survived the test; future TUN routing must preserve this path explicitly. |
| Local TUN frontend | `sing-box version 1.13.3` is installed. `sudo -n true` failed. | Viable only through an authorized interactive elevation/system-extension path; no remote elevation is needed. |

Sanitized command results are retained under `.temp/TASK-260714-dslhb4/`, including `prior-preflight-evidence-02.log`, `ssh-dynamic-forward-03.log`, and `local-tun-prerequisite-01.log`. No credential, key, address, or secret configuration values were written to those records.

## Fact Check

- OpenSSH documents `ssh -w local_tun[:remote_tun]` and describes SSH VPN setup as more than an SSH flag: tunnel interfaces and routes must be configured on both sides. [OpenSSH `ssh(1)`](https://man.openbsd.org/ssh)
- `PermitTunnel` accepts `point-to-point` for layer-3 use but defaults to `no`; device permissions independently still apply. [OpenSSH `sshd_config(5)`](https://man.openbsd.org/sshd_config#PermitTunnel)
- `AllowTcpForwarding` defaults to `yes` upstream, but effective server/user restrictions may override it; the successful bounded SOCKS channel is therefore stronger local evidence for this account than the inaccessible effective-config command. [OpenSSH `sshd_config(5)`](https://man.openbsd.org/sshd_config#AllowTcpForwarding)
- sing-box documents a TUN inbound with explicit `route_exclude_address` support and a SOCKS5 client outbound. Combining those components with a loopback SSH SOCKS listener is an architectural inference, not a claim that either document ships this exact product. [sing-box TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/), [sing-box SOCKS outbound](https://sing-box.sagernet.org/configuration/outbound/socks/)
- The selected carrier preserves the existing repository direction: `ssh-proxy` owns a loopback SSH SOCKS endpoint and remains separate from a future transparent TUN product. [SSH proxy product contract](260714_ssh-proxy-product-contract.md)

## Transport Comparison

| Option | Current evidence | Additional remote changes | Management-access risk | Decision |
| --- | --- | --- | --- | --- |
| OpenSSH `-w` point-to-point gateway | Parser support only; effective `PermitTunnel` unavailable; no affirmative device permission; IPv4/IPv6 forwarding disabled; PF/NAT unreadable without elevation. | `PermitTunnel point-to-point`, tunnel-device access, IP addressing/routes, forwarding, scoped PF NAT, rollback. | High until the SSH carrier route is explicitly preserved. | Defer. |
| Local TUN → loopback SOCKS5 → SSH dynamic forward | Local TUN engine is present; SSH dynamic SOCKS channel and post-test management access succeeded. | None for the carrier. Remote continues to make normal outbound TCP connections per SSH forwarding. | Bounded by explicit exclusion of the SSH endpoint and local physical-network routes. | Select for v1. |
| Application-scoped `ssh-proxy` only | Existing product contract covers SOCKS plus loopback HTTP CONNECT. | None. | Low; no system routing mutation. | Remains a valid non-transparent fallback and the v1 carrier. |

## V1 Remote Setup Contract

V1 makes **no dedicated-Mac configuration changes**. It composes an already permitted SSH dynamic forward with a local TUN frontend:

```text
selected local traffic
  -> local sing-box TUN inbound
  -> SOCKS5 outbound at 127.0.0.1:<ssh-proxy-port>
  -> managed OpenSSH -D carrier
  -> dedicated-Mac sshd
  -> normal remote TCP egress
```

Required contract for the future local implementation:

1. Resolve the dedicated-Mac SSH endpoint before TUN activation. Keep the resolved IPv4/IPv6 endpoint(s) and the active physical route ephemeral; do not write them to versioned config or logs.
2. Start the managed SSH dynamic forward on exact loopback only and prove SOCKS5 readiness before the TUN is exposed.
3. Configure the local TUN to use the loopback SOCKS5 endpoint and exclude the dedicated-Mac SSH endpoint as `/32` and/or `/128` via the TUN route-exclusion mechanism. Also preserve local/loopback and required LAN management routes.
4. Refuse startup if the pre-TUN route to the SSH endpoint already resolves through the proposed TUN, or if the endpoint cannot be resolved safely before TUN activation.
5. Use a privileged local launch path only after explicit local authorization. This preflight found no non-interactive sudo grant; a future service design must not assume one.
6. On failure or stop, remove only state owned by the TUN runtime. `ssh-proxy` lifecycle remains explicit and must not be killed as an unidentified process.
7. Validate both planes after startup: an SSH/SOCKS readiness probe and a route check proving the SSH endpoint remains outside the TUN. A public-egress smoke belongs to the downstream implementation task, not this remote preflight.

This contract directly addresses the repository's earlier upstream self-capture incident: a full TUN must never route its own transport carrier back through itself.

## Deferred OpenSSH `-w` Gateway Contract

Do not create gateway apply scripts from the current evidence. A future authorized task may proceed only after all of these are verified in a disposable/rollback-safe sequence:

1. An administrator evaluates `sshd -T -C ...` for the target user and confirms `PermitTunnel point-to-point` rather than a broader mode.
2. A short-lived isolated `ssh -w` test proves that the exact macOS OpenSSH build can allocate a tunnel device accessible to the selected account; it must remove the test interface on exit.
3. The remote endpoint receives an explicitly documented transit address plan, routes, and a rollback path that preserves the original management route.
4. IPv4 forwarding is enabled only if the design requires L3 forwarding. IPv6 is either configured with equally explicit forwarding/NAT policy or deliberately kept out of scope and blocked at the TUN boundary.
5. PF NAT is inspected and installed only through a dedicated owned anchor/rule set, with preflight, status, and rollback. Do not parse a readable PF file as proof that NAT is active.
6. An out-of-band or timed rollback guard is in place before any default-route change, and the management SSH endpoint is excluded from the new tunnel path.

## Risks and Boundaries

| Risk | Mitigation |
| --- | --- |
| SSH carrier self-capture after a full local TUN route | Resolve before launch; exclude the dedicated-Mac endpoint; verify physical route before and after startup. |
| Remote `PermitTunnel` differs through an administrator-only Match/default path | Treat it as disabled until `sshd -T -C` is evaluated with approved elevation. |
| Remote egress policy blocks a particular destination | Keep this preflight bounded; require a target-specific downstream egress smoke. |
| Local TUN needs privileged setup | Make elevation an explicit local deployment prerequisite; never fake it with a non-working unprivileged route setup. |
| Future PF/NAT change interrupts management | Use an owned anchor, explicit rollback, and a route-preservation guard before applying any default-route or NAT rule. |

## Recommendation

`TASK-260714-dslhb4` should unblock downstream work on the **local TUN-to-SOCKS transport** only. `TASK-260714-iq68gr` must remain gated on a separate design decision/authorized gateway-preflight refresh before it writes or applies dedicated-Mac setup scripts. There is no task-level blocker because the selected v1 transport does not require remote forwarding, NAT, or `PermitTunnel` changes.

## References

- [OpenSSH `ssh(1)`](https://man.openbsd.org/ssh)
- [OpenSSH `sshd_config(5)` — `PermitTunnel`](https://man.openbsd.org/sshd_config#PermitTunnel)
- [OpenSSH `sshd_config(5)` — `AllowTcpForwarding`](https://man.openbsd.org/sshd_config#AllowTcpForwarding)
- [sing-box TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [sing-box SOCKS outbound](https://sing-box.sagernet.org/configuration/outbound/socks/)
- [Repository SSH proxy product contract](260714_ssh-proxy-product-contract.md)
