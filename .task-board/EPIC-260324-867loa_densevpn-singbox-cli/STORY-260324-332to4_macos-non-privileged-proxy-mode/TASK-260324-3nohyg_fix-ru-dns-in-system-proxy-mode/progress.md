## Status
done

## Assigned To
codex

## Created
2026-03-24T12:05:36Z

## Last Update
2026-03-24T12:19:06Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Confirmed regression: in system_proxy mode .ru traffic matched direct outbound but DNS resolution for direct timed out. Fixed renderer by assigning domain_resolver=dns-direct to the direct outbound and verified live after reconnect. Live check through 127.0.0.1:2080: api.ipify.org returned 144.31.90.46 while ip.nic.ru returned 91.77.167.22. Session log simultaneously showed non-.ru traffic on outbound/vless[proxy] and .ru traffic on outbound/direct[direct].

## Precondition Resources
(none)

## Outcome Resources
(none)
