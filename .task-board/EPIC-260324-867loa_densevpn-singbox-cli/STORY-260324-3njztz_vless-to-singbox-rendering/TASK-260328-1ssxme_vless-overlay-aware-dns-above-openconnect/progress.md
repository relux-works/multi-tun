## Status
development

## Assigned To
codex

## Created
2026-03-28T19:49:26Z

## Last Update
2026-03-28T22:37:27Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-28 live repro: standalone openconnect split-include now preserves primary DNS, but starting vless-tun above active openconnect still breaks non-Corp lookups. sing-box log for session 20260328T194341Z shows dns/local[dns-direct] querying DHCP DNS on en0 ([192.168.1.1:53], search [IGD_MGTS]) instead of consuming openconnect supplemental resolver files. openconnect session 20260328T194252Z confirms Corp /etc/resolver/* files are present and global resolver state is clean. Goal: make vless render overlay-aware so generic DNS uses proxy path while Corp/corp suffixes use openconnect-specific resolvers.
2026-03-28 implementation update: added overlay-aware vless render/start behavior. When openconnect has an active session, cli resolves overlay DNS metadata from its runtime session file and passes domains + nameservers into sing-box rendering. Under overlay mode, generic bypass DNS no longer routes to dns-direct/local DHCP; direct outbound switches to dns-proxy for generic direct traffic, while Corp/corporate suffixes get a dedicated dns-overlay UDP server bound to openconnect nameservers. Added coverage in internal/openconnect/session_test.go and internal/singbox/render_test.go. go test ./... passed and vless-tun was rebuilt. Live smoke still pending.
2026-03-29 follow-up: successful overlay config for session 20260328T221706Z already showed dns-overlay and direct.domain_resolver=dns-proxy, but sing-box still initialized dns/local[dns-direct] and logged DHCP resolver discovery on en0. Per sing-box local DNS behavior on macOS, that path still uses DHCP/NetworkExtension, so overlay mode now removes dns-direct/local entirely. Overlay config keeps only dns-proxy for generic lookups and dns-overlay UDP to Corp nameservers for corporate suffixes. go test ./... passed and vless-tun rebuilt for next live smoke.
2026-03-29 live behavior after overlay config changes: standalone openconnect split-include remains healthy, and standalone vless remains healthy. When both tunnels are up together, external DNS still collapses while Corp/internal hosts keep resolving; stopping openconnect immediately restores external resolution for the already-running vless session without restarting vless. This points to remaining system DNS ownership conflict during overlay rather than route blackholing or broken standalone configs.

## Precondition Resources
(none)

## Outcome Resources
(none)
