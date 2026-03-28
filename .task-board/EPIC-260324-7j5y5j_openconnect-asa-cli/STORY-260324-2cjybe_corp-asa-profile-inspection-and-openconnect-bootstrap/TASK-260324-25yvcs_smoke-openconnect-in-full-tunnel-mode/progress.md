## Status
development

## Assigned To
codex

## Created
2026-03-24T19:42:30Z

## Last Update
2026-03-28T12:10:54Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Starting dependency/runtime prep: install vpn-slice, inspect previous openconnect driver flow, and prepare first full-tunnel smoke path.
Prepared the live full-tunnel smoke path. Dry-run now resolves profile "Ural Outside extended" to vpn-gw2.corp.example/outside and shows the exact openconnect command with Homebrew vpnc-script. Important constraint: full mode will own default route and global DNS, so the live smoke should not run concurrently with an active vless-tun session.
Added persisted runtime diagnostics to openconnect-tun: separate cache/log root at ~/.cache/openconnect-tun, session metadata in runtime/current-session.json, per-session logs in sessions/, status output with session/log fields, and disconnect via tracked session lifecycle. Also fixed a likely cause of the earlier hang by pre-warming sudo with sudo -v and using sudo -n for the actual openconnect --cookie-on-stdin launch.
Aligned the CLI lifecycle with vless-tun: canonical commands are now run/reconnect/status/stop, with connect/disconnect kept as aliases. Also added a persisted starting session state so status can expose log_file and last_log_line while a foreground run is still inside auth or handshake.
Latest live smoke reached vpn-auth OTP step, not password fill. Follow-up: surface auth progress lines in terminal, not only session log, so hangs/fallbacks are visible during run.
Implemented compact auth_stage terminal output for openconnect-tun run. Foreground run now shows stage transitions like vpn_auth, fetching_saml_config, login_page, otp_page_waiting_for_second_factor, and fallback_openconnect_authenticate, while the full stderr still stays in the session log.
Latest live full-tunnel run did pass SAML login/password/TOTP, but ASA returned error 13: Cisco Secure Desktop not installed on the client. The final cookie rejection from openconnect is a downstream symptom after vpn-auth fell back to emitting a raw SAML token instead of a full ASA session cookie.
Added scripts/openconnect-gitlab-smoke.sh as a non-autorun smoke helper for the manual sequence: vless-tun stop -> openconnect-tun run -> wait up to 15s for session active -> curl https://gitlab.services.corp.example/ and require GitLab-looking HTML -> openconnect-tun stop with force-drop fallback -> vless-tun run. Verified only with bash -n; the script has not been executed yet.
Updated the smoke helper to warm sudo once at startup and keep the sudo timestamp alive during the whole run, so vless-tun stop/run and forced openconnect cleanup do not re-prompt mid-script. Also fixed EXIT cleanup so the sudo keepalive and background run process are both torn down reliably.
Follow-up architecture note: repeated sudo prompts are a limitation of the current direct CLI->root model for vless-tun/openconnect-tun. Proper fix is a privileged launchd helper or NetworkExtension-style service so start/stop/status do not rely on per-command sudo; a narrow sudoers NOPASSWD rule is only a short-term workaround.
Latest live Corp result on 2026-03-25: aggregate-auth now preserves reply urlpath, shares cookie jar, shims xmlstarlet/curl for stock csd-post.sh, and can loop hostscan->wait->re-init multiple times. The ASA still returns a fresh host-scan ticket/token after each TOKEN_SUCCESS and finally fails SAML auth-reply with error id=13 (Cisco Secure Desktop not installed on the client). This isolates the remaining blocker to Corp-specific CSD payload semantics rather than SAML/browser plumbing alone.
2026-03-28: live overlay smoke over active vless-tun now reaches helper-backed openconnect connect and obtains the Corp session cookie. Non-Corp reachability stayed up enough for curl https://www.avito.ru/ to return HTTP/2 403 from QRATOR, but GitLab SSH still stalled during banner exchange and the user manually interrupted openconnect after the machine hung. No successful GitLab clone directory was created.

## Precondition Resources
(none)

## Outcome Resources
(none)
