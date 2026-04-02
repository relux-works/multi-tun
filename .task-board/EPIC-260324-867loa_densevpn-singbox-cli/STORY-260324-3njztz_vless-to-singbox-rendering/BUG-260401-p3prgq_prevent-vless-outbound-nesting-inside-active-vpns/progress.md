## Status
to-review

## Assigned To
codex

## Created
2026-03-31T21:06:07Z

## Last Update
2026-03-31T21:08:25Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Implemented startup guard in internal/session/session.go: on macOS tun mode, vless-tun now inspects the upstream VLESS server route before launch and refuses nested-tunnel startup when the upstream host already resolves via another VPN interface such as utun/tun/ppp/ipsec. Added tests in internal/session/session_test.go, updated README.md and SPEC.md, rebuilt, ran go test ./internal/session/... ./internal/cli/..., ./scripts/setup.sh, and verified live that vless-tun start now fails with: upstream VLESS route 144.31.90.46:8443 currently goes via utun11; refusing nested tun startup while active VPN services are connected: v2RayTun, corp outside.

## Precondition Resources
(none)

## Outcome Resources
(none)
