## Status
to-review

## Assigned To
codex

## Created
2026-03-28T22:11:30Z

## Last Update
2026-03-28T22:37:39Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-29 repro: user interrupted openconnect start twice during auth_stage fetching_saml_config. Runtime was left with current-session.json for 20260328T220901Z and pid=0, while no live VPN session existed. This did not activate overlay-aware vless render, but it leaves confusing stale state and should be cleared automatically on auth/bootstrap interruption.
2026-03-29 implementation update: openconnect Connect no longer writes current-session runtime state before auth/bootstrap completes. Runtime file is now only persisted after a live PID exists, so SIGINT during fetching_saml_config / auth no longer leaves pid=0 session artifacts behind. Targeted package tests passed; full go test ./... running in parallel / green before this note.

## Precondition Resources
(none)

## Outcome Resources
(none)
