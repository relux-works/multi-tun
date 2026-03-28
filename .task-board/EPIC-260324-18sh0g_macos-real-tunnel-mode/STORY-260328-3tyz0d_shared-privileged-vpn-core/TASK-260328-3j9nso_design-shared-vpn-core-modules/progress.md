## Status
to-review

## Assigned To
codex

## Created
2026-03-28T10:20:21Z

## Last Update
2026-03-28T10:52:02Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-28 proposed shared core design:
1. Keep exactly one privileged long-lived LaunchDaemon: the shared VPN core service. openconnect-tun helper is the starting point; vless-tun should stop creating per-session root LaunchDaemons for sing-box.
2. Split the current openconnect helper into reusable submodules instead of one helper.go blob:
- internal/vpncore/service: install/uninstall/status of the shared root daemon (plist rendering, bootstrap/bootout, socket ownership).
- internal/vpncore/rpc: unix socket transport, request/response framing, protocol versioning, error mapping.
- internal/vpncore/process: root child spawn, stdin payload injection, stdout/stderr log redirection, setpgid, signal pid or process-group, liveness probing.
- internal/vpncore/launchd: only the launchd primitives needed for the core service itself, not per-VPN session daemons.
3. Put protocol-specific wrappers above the core:
- internal/openconnect/runtime stays responsible for auth, profile resolution, route/dns decisions, and builds a typed spawn request for openconnect.
- internal/session for vless-tun stays responsible for render/session bookkeeping, but delegates privileged sing-box spawn/stop to vpncore/process instead of internal/session/launchd.go.
4. Do not expose a forever-generic root shell. Today openconnect helper effectively accepts arbitrary argv and arbitrary kill targets. For the shared core, narrow the RPC surface to typed or at least validated primitives so the trusted daemon is reusable but not an unbounded root command runner.
5. Suggested first migration slice: preserve the current openconnect helper behavior, extract its daemon/service/rpc/process internals into internal/vpncore/*, then rewire openconnect imports to the new package without changing UX. After that, replace vless launch_mode=launchd in tun mode with a helper/core-backed launch path and keep launchd only for the core daemon itself.

## Precondition Resources
(none)

## Outcome Resources
(none)
