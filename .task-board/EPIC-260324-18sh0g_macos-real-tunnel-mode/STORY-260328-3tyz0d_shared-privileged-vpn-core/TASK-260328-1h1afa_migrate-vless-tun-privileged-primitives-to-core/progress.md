## Status
to-review

## Assigned To
codex

## Created
2026-03-28T10:20:21Z

## Last Update
2026-03-28T11:21:20Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-28 vless-tun migration map:
1. internal/session/launchd.go becomes the primary deletion target for per-session root LaunchDaemon management once vpncore/service + vpncore/process exist.
2. internal/session/session.go keeps cache/session metadata, profile bookkeeping, and non-privileged lifecycle branching, but the launch_mode=launchd branch should be replaced by a helper/core-backed privileged mode for tun sessions.
3. stop semantics should move from direct sudo/launchctl bootout toward the same privileged core signal path used by openconnect, ideally with process-group support for sing-box.
4. CLI and config can stay thin: vless-tun run/reconnect/stop/status continue to expose high-level UX, while render.privileged_launch should eventually collapse toward auto/helper/direct semantics instead of a separate per-session launchd mode.
5. Concrete first refactor target after vpncore extraction: make session.Start/session.Stop call vpncore for root sing-box spawn/stop in tun mode, while keeping system_proxy and direct non-root paths untouched.
2026-03-28 implementation shipped: added internal/vpncore + cmd/vpn-core, rewired openconnect helper to shared vpn-core, switched vless tun helper path to vpncore spawn/signal, and kept internal/session/launchd.go only as a legacy compatibility seam for old launchd-managed sessions.
2026-03-28 follow-up fix: legacy launchd-backed vless sessions now stop via the preserved launchd control path instead of falling through to an unprivileged process-group kill. This keeps already-running works.relux.vless-tun sessions manageable until they are restarted onto vpn-core.
2026-03-28 live validation: legacy launchd-backed session 20260328T101711Z stopped cleanly, then vless-tun started session 20260328T112052Z with launch_mode=helper, pid=42063, utun233 present. This confirms the migration path from works.relux.vless-tun to vpn-core-backed helper mode on a real machine.

## Precondition Resources
(none)

## Outcome Resources
(none)
