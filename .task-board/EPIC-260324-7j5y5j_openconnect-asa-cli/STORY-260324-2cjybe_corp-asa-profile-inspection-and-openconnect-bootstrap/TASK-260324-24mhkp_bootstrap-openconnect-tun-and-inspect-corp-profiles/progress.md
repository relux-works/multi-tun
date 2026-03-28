## Status
to-review

## Assigned To
codex

## Created
2026-03-24T19:30:04Z

## Last Update
2026-03-24T21:46:24Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Renamed repos to multi-tun/multi-tun_old. Next: scaffold openconnect-tun and inspect local Corp AnyConnect profiles under ~/Downloads and /opt/cisco.
Renamed repos to multi-tun/multi-tun_old. Scaffolded openconnect-tun with live commands: status, profiles, inspect-profiles. Smoke-checked against real Corp XML in ~/Downloads/cisco-anyconnect-profiles and /opt/cisco/secureclient/vpn/profile; parsed 9 host entries from cp_corp_inside_3.xml and surfaced PPPExclusion=Disable, EnableScripting=false, LocalLanAccess=true.
Bootstrap expanded from inspection-only into real runtime scaffolding: added connect/disconnect/routes commands, profile-name resolution from AnyConnect XML, duplicate HostEntry dedupe across /opt/cisco and ~/Downloads profile dirs, and dry-run validation for both full and split-include modes. Verified with go test ./... and ./scripts/setup.sh.
Finding: username/password keychain bootstrap works; vpn-auth now reaches OTP page for Ural Outside extended. Remaining friction is auth visibility and TOTP wiring, not profile resolution.

## Precondition Resources
(none)

## Outcome Resources
(none)
