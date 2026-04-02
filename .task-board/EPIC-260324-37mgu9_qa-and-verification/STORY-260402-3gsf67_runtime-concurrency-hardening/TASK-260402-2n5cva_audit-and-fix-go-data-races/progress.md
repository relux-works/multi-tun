## Status
development

## Assigned To
codex

## Created
2026-04-02T19:03:34Z

## Last Update
2026-04-02T19:07:43Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [ ] Audit manual concurrent paths beyond race-detector coverage (buffers, maps, session state, logs, goroutine signaling)
- [x] Fix confirmed races and add focused regression tests where practical
- [ ] Document residual risk, false negatives, or intentionally unsolved areas in board notes and docs if needed
- [x] Run repo-wide go test -race and capture failing packages or flakes

## Notes
Kickoff scope: cross-cutting repo audit after a real hostscan bug caused by unsynchronized concurrent stdout/stderr capture in openconnect runtime. Use that incident as the first pattern to search for, then widen to shared session/runtime code across openconnect, vless, vpn-core, dump, and config loaders.
First race-detector pass found two concrete issues in internal/openconnect: (1) hostscan still wrote concurrently into an unsynchronized log writer when stdout/stderr were merged, and (2) lookupHostWithTimeoutOpenConnect launched a goroutine that closed over the mutable global lookupHostOpenConnect function var. Both were patched before the second race pass.
Second pass result: after patching the two openconnect concurrency issues, the full repo now passes go test -race ./.... A quick manual grep over goroutine/channel and merged-output patterns did not reveal another obvious stdout/stderr shared-buffer bug, but the broader manual concurrency sweep remains open before this task can move to review.

## Precondition Resources
(none)

## Outcome Resources
(none)
