## Status
done

## Assigned To
codex

## Created
2026-04-08T14:21:30Z

## Last Update
2026-04-08T14:51:31Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Started Apple binary/source availability audit for v2RayTun to look for localhost listener/proxy indicators (e.g. NWListener, 127.0.0.1, SOCKS/HTTP proxy strings).
Audit summarized in artifacts/v2raytun-apple-audit/README.md. Main outcome: macOS v2RayTun is not a clean counterexample to the localhost-proxy thesis; saved runtime configs and logs show normal tunnel bring-up through a localhost SOCKS inbound on ::1:1080.
Reopened umbrella audit for live proof attempt against v2RayTun localhost SOCKS listener during an active session.
Live proof added to artifacts/v2raytun-apple-audit/README.md. Main outcome is now stronger: macOS v2RayTun not only configures a localhost SOCKS inbound on ::1:1080, but also accepts unauthenticated connections from another local process during an active tunnel session.
Done after static + runtime + live localhost proof. Findings persisted in artifacts and logbook.

## Precondition Resources
(none)

## Outcome Resources
(none)
