## Status
to-review

## Assigned To
codex

## Created
2026-03-26T08:40:43Z

## Last Update
2026-03-31T13:22:38Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Implemented cisco-dump start/status/stop with ~/.cache/cisco-dump session artifacts, localhost 127.0.0.1:60808 tcpdump capture, Cisco log mirroring, process/lsof snapshots, and start alias support for vless-tun/openconnect-tun. Verified with go test ./... and a smoke status run on an empty cache dir.
Extended cisco-dump with default Corp host probes (gitlab.services.corp.example, portal.corp.example), explicit --probe-host/--probe-ns flags, and host-level DNS/route/TCP/HTTPS snapshots on network changes plus final stop.
Adjusted cisco-dump shutdown so final host probes run from the stop command after daemon exit; host probe commands now execute in parallel and default stop timeout is 10s. Verified with a --no-tcpdump smoke session that host-probes-network_change-* and host-probes-final_stop-* artifacts are written and stop completes cleanly.

## Precondition Resources
(none)

## Outcome Resources
(none)
