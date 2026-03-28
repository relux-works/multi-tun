# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-03-27

### 1758 — split-include Now Augments User Masks With Official Corp Supplemental DNS Suffixes
- FINDING: latest standalone session `openconnect-session-20260327T144146Z.log` already had a working scoped resolver for `corp.example -> 10.23.16.4,10.23.0.23` on `utun8`, so the remaining DNS gap was no longer “resolver missing” but “official AnyConnect installs a broader supplemental suffix set than our split-include path”.
- FINDING: official Cisco snapshot `cisco-dump-session-20260327T133554Z/snapshots/network-20260327T133957.780Z.txt` shows `utun8` supplemental resolvers not just for `corp.example`, but also `inside.corp.example`, `region.corp.example`, `edge.region.corp.example`, `branch.example`, `branch.corp.example`, `corp-it.example`, `corp-it.internal`, `corp-sec.example`, `workspace.example`, `security.example`, and related domains, while using `region.corp.example` as the scoped search domain.
- ROOT CAUSE: `internal/openconnect/runtime.go` already knew the full Corp suffix set in `supplementalResolverSpecForServer()`, but `supplementalResolverSpecForConnect()` dropped that set in `split-include` mode and kept only user-provided `vpn_domains`, typically just `corp.example`.
- FIX: `internal/openconnect/runtime.go` now merges the official Corp server spec domains into `split-include`, falls back to server-spec nameservers when the user does not provide explicit ones, and prefers the official `SearchDomain` (`region.corp.example`) over the first user mask. Tests updated in `internal/openconnect/runtime_test.go`.

### 1648 — Official Cisco Uses scutil Dynamic Store For Split DNS; /etc/resolver Emulation Was The Wrong Layer
- FINDING: fresh official AnyConnect dump `cisco-dump-session-20260327T133554Z` and live `scutil` state show that Cisco does not create `/etc/resolver/corp.example`; instead it writes `State:/Network/Service/<service-id>/DNS` with `InterfaceName=utun8`, `ServerAddresses=10.23.16.4,10.23.0.23`, `SearchDomains=[region.corp.example]`, and `SupplementalMatchDomains=[inside.corp.example, corp.example, ...]`, plus matching `State:/Network/Service/<service-id>/IPv4`.
- FINDING: standalone `openconnect-tun` session `openconnect-session-20260327T120053Z.log` authenticated and brought up `utun8`, but our split-include shim still used `/etc/resolver/corp.example` and plain `route ... -interface utun8` entries; direct `dig @10.23.16.4 gitlab.services.corp.example` timed out and the route table showed `Gateway=utun8` instead of Cisco-like `link#33`/`ifscope` routes.
- FINDING: after the first `scutil` patch, session `openconnect-session-20260327T140828Z.log` showed the correct scoped resolver (`corp.example -> 10.23.16.4/10.23.0.23` on `if_index=utun8`) and `ifscope` routes, but `vpn-slice` still left a conflicting `/etc/resolver/corp.example` with `10.24.60.197/10.24.60.8`, and `search.tailscale` still carried Corp suffixes.
- FINDING: `openconnect-tun stop` still returned too early because it waited only for the `openconnect` PID, while the root `disconnect` wrapper kept running probes/cleanup for a few more seconds; if `vless-tun` started immediately after, DNS looked globally broken until the helper finally finished.
- FIX: `internal/openconnect/runtime.go` now skips expensive probe runs on `disconnect`, and `internal/openconnect/session.go` now waits for per-session helper processes, dynamic-store keys, and resolver files to disappear before reporting `stop` complete. Tests remain green on `go test ./internal/openconnect ./internal/openconnectcli ./cmd/openconnect-tun`.

### 1444 — split-include Now Forces Configured Scoped DNS Nameservers And Logs Them
- FINDING: after the Python-compat fix, `vpn-slice` in session `openconnect-session-20260327T112032Z.log` successfully created `/etc/resolver/corp.example`, but it populated it with `10.24.60.197` / `10.24.60.8`, which is the same incomplete DNS pair previously seen from standalone OpenConnect and still not enough for internal `gitlab.services.corp.example`.
- FIX: `internal/openconnectcfg/config.go` now supports `split_include.nameservers`, `internal/openconnectcli/app.go` passes them through into `ConnectOptions` and status output, `internal/openconnect/session.go` now logs `vpn_nameservers`, and `internal/openconnect/runtime.go` now reuses the existing resolver-shim machinery in `split-include` mode to overwrite only the configured domain masks with the configured nameservers after `vpn-slice` runs.
- LIVE CONFIG: `~/.config/openconnect-tun/config.json` now pins `split_include.nameservers=["10.23.16.4","10.23.0.23"]` next to `vpn_domains=["corp.example"]`, matching the working supplemental resolver pair previously observed from official AnyConnect.

### 1429 — split-include Failed Because pipx vpn-slice Broke On Python 3.14 distutils Removal
- FINDING: live session `openconnect-session-20260327T110812Z.log` authenticated and brought up the tunnel, but the generated wrapper logged `No module named 'distutils'` immediately after invoking `vpn-slice`, so no scoped Corp resolver files were installed and `gitlab.services.corp.example` stayed unresolved.
- ROOT CAUSE: the user-local `vpn-slice` entrypoint in `~/.local/bin` points to a `pipx` virtualenv on Python `3.14.3`, while `vpn_slice.__main__` still imports `from distutils.version import LooseVersion` on macOS.
- FIX: `internal/openconnect/runtime.go` now writes a tiny `distutils.version.LooseVersion` compatibility module into the per-session helper dir and prepends it to `PYTHONPATH` only for `vpn-slice`-based script runs, so split-include works again without mutating the user's `pipx` environment.

### 1418 — openconnect-tun Learned Persistent split_include Defaults And Stopped Injecting Corp DNS Shim Into vpn-slice
- ROOT CAUSE: `openconnect-tun` had coexistence-safe pieces already (`vpn-slice --domains-vpn-dns`, `--route`), but no persistent config section for them; at the same time the newer hardcoded Corp DNS shim still applied even in `split-include`, which could add more corporate suffix resolvers than the user explicitly wanted.
- FIX: `internal/openconnectcfg/config.go` now supports `split_include.routes` and `split_include.vpn_domains`, `internal/openconnectcli/app.go` now merges those defaults with CLI `--route/--vpn-domains`, and `internal/openconnect/runtime.go` now limits the hardcoded Corp supplemental resolver shim to `--mode full` only.
- LIVE CONFIG: `~/.config/openconnect-tun/config.json` now defaults to `split-include` with corporate private-network routes plus `vpn_domains=["corp.example"]`, so `openconnect-tun start` can keep `*.corp.example` lookups in-VPN while leaving unrelated public DNS out of the tunnel by default.

### 1357 — DNS Shim Now Restores search.tailscale To Avoid External Resolver Slowdown
- FINDING: after the first Corp DNS shim run, `/etc/resolver/search.tailscale` ended up carrying the corporate suffix list even after the tunnel was gone; external DNS went back to normal only once `openconnect` was killed and the system settled.
- ROOT CAUSE: the shim correctly added domain-specific resolver files, but Tailscale's `search.tailscale` file could retain an expanded corporate search list, making external hostname resolution feel slow and muddying the coexistence test.
- FIX: `internal/openconnect/runtime.go` now backs up `/etc/resolver/search.tailscale` in the per-session helper dir and restores it after both `apply_dns_shim` and `remove_dns_shim`, so Corp suffixes stay in managed domain resolvers instead of leaking into the Tailscale search file.

### 1335 — Official Cisco DNS Gap Reproduced; openconnect-tun Now Injects Supplemental Resolver Shim
- FINDING: standalone `openconnect` session `20260327T102437Z` did not receive `INTERNAL_IP4_DNS` / `CISCO_SPLIT_DNS` in the script environment; after `vpnc-script` it only produced `region.corp.example` supplemental DNS with `10.24.60.197` / `10.24.60.8`, which is insufficient for `gitlab.services.corp.example`.
- FINDING: official AnyConnect `cisco-dump` session `20260327T102834Z` first showed full `utun8` supplemental resolvers in [network-20260327T102903.829Z.txt], roughly one second after the OCSC timeline reached `Establishing VPN - Configuring system`; those resolvers covered `corp.example`, `inside.corp.example`, `branch.example`, `corp-it.example`, and related suffixes via `10.23.16.4` / `10.23.0.23`.
- FIX: `internal/openconnect/runtime.go` now embeds an Corp-specific DNS shim into the generated script wrapper for `/outside` sessions on `*.corp.example`: on connect/reconnect it writes managed `/etc/resolver/<domain>` files for the observed Cisco domain set, and on disconnect it removes only files marked as `# Added by openconnect-tun DNS shim`.
- STATUS: the next live `openconnect-tun` run should prove whether reproducing Cisco's supplemental resolver suffixes is enough to make `gitlab.services.corp.example` resolve and open without the official client.

### 1308 — Added DNS Diagnostics To openconnect-tun And cisco-dump
- FIX: `internal/openconnect/runtime.go` now wraps the effective `--script` command (`vpnc-script` or `vpn-slice`) in a generated helper that appends `reason`, `INTERNAL_IP4_*`, `INTERNAL_IP6_*`, `CISCO_*`, `scutil --dns`, `/etc/resolver`, and `netstat -rn -f inet` snapshots to the session log before and after the script runs.
- FIX: `internal/ciscodump/runtime.go` now writes `network-*.txt` snapshots alongside process/socket artifacts, with `scutil --dns`, `scutil --proxy`, `/etc/resolver`, and IPv4 route table state so official AnyConnect runs can be compared against standalone `openconnect`.
- STATUS: the next live Corp check should answer the core DNS question directly from artifacts: whether the headend is actually sending `INTERNAL_IP4_DNS` / `CISCO_SPLIT_DNS`, and whether macOS scoped resolvers are being installed.

### 1256 — OpenConnect Transport Works; Remaining Access Gap Is DNS, Not Auth
- FINDING: session `20260327T094220Z` in [openconnect-session-20260327T094220Z.log] shows a real AnyConnect tunnel bring-up: `Got CONNECT response: HTTP/1.1 200 OK`, `CSTP connected`, `Established DTLS connection`, and `Configured as 10.101.17.230`.
- FINDING: live routing sends `gitlab.services.corp.example` traffic via `utun8`, but the hostname resolves publicly as `www.corp.example -> 203.0.113.27`; `scutil --dns` on `utun8` shows `1.1.1.1` and `8.8.8.8`, not an internal corporate resolver.
- ROOT CAUSE: “VPN seems connected but internal GitLab is unreachable” is no longer an auth or tunnel-establishment problem. The remaining gap is DNS/split-DNS behavior after connect, while the transport itself is up.
- FIX: `internal/openconnectcli/app.go` status output now prefers live `openconnect` runtime over Cisco CLI state so a healthy session no longer appears as `state: disconnected` just because `/opt/cisco/anyconnect/bin/vpn state` is unrelated to the standalone `openconnect` process.

### 2215 — Corp Aggregate Auth Now Completes; Remaining Blocker Is Only Privileged Tunnel Startup
- BREAKTHROUGH: `openconnect-tun start --profile 'Ural Outside extended' --mode full` now reaches `auth_stage: cookie_obtained` and logs a resolved auth result (`aggregate_auth host: vpn-gw2.corp.example`, `aggregate_auth connect_url: https://vpn-gw2.corp.example/outside`) in [openconnect-session-20260327T092736Z.log], meaning the ASA finally accepted the `auth-reply` and handed back a usable cookie.
- ROOT CAUSE OF PRIOR LOOP: the final `auth-reply` was missing two upstream OpenConnect fields under `<config-auth>`: `<group-select>` and `<host-scan-token>`. Adding those aligned the synthetic aggregate-auth reply with OpenConnect's own XML builder and broke the continuation loop.
- SUPPORTING FIXES: the normal `vpn-auth` binary in `~/.local/bin` now includes preset-cookie loading, password-only Keycloak login handling, and TOTP re-submit on the next 30s slot, which removed the browser-side stalls seen in follow-up SSO pages.
- OUTCOME: the default auth mode was switched back to `aggregate`, because that is now the working live path; the only remaining stop in unattended self-tests is the expected `sudo: a password is required` when the tool transitions from auth to actually starting the privileged VPN process.

## 2026-03-26

### 2152 — Browser Automation Reached Continuation-Loop; Final Session Handoff Still Missing
- FINDING: the aggregate-auth path now reliably clears multiple client-side blockers: native `libcsd` hostscan succeeds twice, `vpn-auth` handles the password-only Keycloak login page, and TOTP retry now waits for a fresh 30s slot instead of resubmitting a spent code.
- FACT: after those fixes, the second SSO follow-up can complete all the way to `You are successfully logged in` and back to `+webvpn+/index.html`, yielding a fresh `acSamlv2Token`, but the final ASA `auth-reply` still does not return `<session-token>`.
- NEW BEHAVIOR: richer `auth-reply` variants split into two server modes. `capabilities_*` variants return a browser `auth-request` with `sso-v2-login`; `full_profile_*` variants return an `auth-request` with only `<opaque>` and no login URL. `openconnect-tun` now distinguishes these and can retry the same SSO token without reopening the browser, but the continuation still loops without producing a session cookie.
- CONCLUSION: the remaining blocker is now firmly in the last ASA session-handoff step. It is no longer “hostscan failed”, “browser got stuck”, or “OTP reused”. The next likely source of truth is either a native Cisco/OpenConnect session-resume behavior we are not reproducing, or a missing field/cookie in the final `auth-reply` body that only official clients send.

### 2046 — Aggregate SAML Glue Reached Cisco Session-Coherency Limits
- FINDING: `openconnect-tun --auth aggregate` now successfully executes the full interleaved flow `hostscan -> wait.html -> SSO -> deferred second hostscan -> auth-reply`, and the session log shows native `libcsd` `TOKEN_SUCCESS`, browser-side `acSamlv2Token`, imported ASA cookies (`CSRFtoken`, `webvpnLang`, `acsamlcap`, `webvpnlogin`), and even WebView preseed with hostscan-side cookies before SSO.
- FACT: despite that, the final ASA `auth-reply` still deterministically returns `<error id="13">Cisco Secure Desktop not installed on the client</error>`; the failure survives both browser-cookie import and browser-cookie preloading, so the blocker is no longer “missing cookie X” in the aggregate glue.
- CONCLUSION: the remaining gap is likely session coherency between the HTTP aggregate-auth client and Cisco’s browser/control-plane implementation, not another missing field in the synthetic XML. Further progress is more likely via the native `openconnect --authenticate` path or deeper Cisco/client session reuse than by continuing to polish the split HTTP+WebView aggregate flow.

### 2033 — openconnect Lost `/outside` After Hostscan And Re-entered SSO At `/`
- FINDING: after the native `libcsd` path stopped killing `cscan`, `openconnect --authenticate` advanced past `wait.html` and then issued `POST https://vpn-gw2.corp.example/` instead of `POST https://vpn-gw2.corp.example/outside`, immediately hitting `Please complete the authentication process in the AnyConnect Login window. No SSO handler`.
- ROOT CAUSE: the remaining failure moved from hostscan execution to path/group preservation across the post-hostscan redirect chain; the tunnel-group URL path `/outside` was no longer present when `openconnect` resumed auth.
- FIX: `internal/openconnect/runtime.go` now normalizes auth targets for `openconnect --authenticate` to `https://host` plus `--usergroup <urlpath>`, so `vpn-gw2.corp.example/outside` becomes root URL + explicit `outside` group instead of relying on a path that can disappear mid-flow.

### 2024 — Native libcsd Helper Was Killing cscan Right After Launch
- ROOT CAUSE: the generated `csd-native.py` wrapper called `csd_free()` immediately after a successful `csd_run()`, and `libcsd.log` showed that this path explicitly shuts down the posture library and kills the scanner with `exitcode(15)`.
- FINDING: `openconnect --authenticate` was already on the correct live path and the wrapper emitted `TOKEN_SUCCESS`, but `openconnect` then looped forever on `+CSCOE+/sdesktop/wait.html` because the actual Cisco scanner had been terminated by the helper itself.
- FIX: `internal/openconnect/runtime.go` now prefers `csd_detach()` after a successful `csd_run()` and skips `csd_free()` on the success path; `csd_free()` is kept only for failure cleanup before the scanner is fully detached.

### 1948 — openconnect-tun Defaulted Back To openconnect --authenticate And Learned Native libcsd
- DECISION: `openconnect-tun` now treats `--auth openconnect` as the default live path again, with `--auth aggregate` kept as an explicit fallback/debug backend instead of silently owning the default SAML flow.
- FACT: native Cisco hostscan can be driven headlessly through the installed `~/.cisco/vpn/cache/lib64_appid/libcsd.dylib`; the working arg set for Corp is `allow-updates`, `host`, `ticket`, `langsel`, `stub=0`, `group`, `vpnclient`, `url`, `server-certhash`, and `fqdn`.
- FIX: `internal/openconnect/runtime.go` now resolves native `libcsd` parameters from the target ASA endpoint and wires them into the generated `--csd-wrapper` used by `openconnect --authenticate`, while preserving the stock `csd-post.sh` shim path as fallback when native Cisco artifacts are missing.
- TEST: `TestBuildNativeCSDConfigUsesResolvedIPAndFingerprint`, `TestCSDWrapperScriptPrefersNativeHelperWhenConfigured`, and `TestNormalizeAuthModeDefaultsToOpenConnect` cover the new path in `internal/openconnect/runtime_test.go`.

### 1837 — Hostscan Wait Flow Was Ignoring 302 Redirects Entirely
- ROOT CAUSE: after `TOKEN_SUCCESS`, `waitForHostScan` only accepted `HTTP 302` as a terminal success code and never followed the `Location` chain, so aggregate-auth could re-enter `init` with cookies still in an intermediate hostscan-pending state and get a fresh challenge.
- FIX: `internal/openconnect/runtime.go` now logs `hostscan_wait_location` and follows up to five redirects on `wait.html`, preserving the shared cookie jar across the chain before the next aggregate-auth refresh.
- TEST: `TestWaitForHostScanFollowsRedirectChain` in `internal/openconnect/runtime_test.go` now verifies that the redirected target sees the `sdesktop` cookie and that both wait statuses are logged.

### 1906 — openconnect Hostscan Stopped Forcing Every Requested Process/File To Exist
- ROOT CAUSE: the `curl` shim inside `internal/openconnect/runtime.go` appended `endpoint.process[...]` / `endpoint.file[...]` overrides with `exists="true"` for every requested `Process` and `File` triplet from `data.xml`, including obviously false Windows-only artifacts like `*.exe`; that overrode the stock `csd-post.sh` answers which were already made truthful on macOS via the earlier `pidof` / GNU `stat` shims.
- FIX: the scan augmentation now leaves stock process/file detection intact and instead augments the posture with local `waDiagnose.txt` signals: `system_info.protected`, antimalware products from `GetDefinitionState` / `GetRealTimeProtectionState`, and firewall entries only when `GetFirewallState` reports `enabled=true`.
- SAFETY: if `waDiagnose.txt` is absent or yields no usable security products, the old `secinsp_* -> endpoint.am[...]` antimalware fallback still kicks in, but the blanket `Process/File=true` lies are gone.

### 1808 — cisco-dump Now Auto-Derives OCSC Timeline And Summary Artifacts
- FIX: `internal/ciscodump/ocsc.go` now parses loopback pcap files directly, extracts OCSC-framed payloads, filters them down to high-signal printable strings, and writes `ocsc-timeline.txt` plus `ocsc-summary.txt` into the session artifact directory.
- FIX: `cisco-dump stop` now persists those derived artifact paths and counts in session metadata, and `cisco-dump inspect --session-id ...` can regenerate them for historical sessions without another live AnyConnect run.
- FINDING: on session `20260326T144914Z`, the derived OCSC timeline captured the exact GUI/control-plane sequence `Please enter the requested proxy credentials` -> `Establishing VPN - Initiating connection` -> `Examining system` -> `Activating VPN adapter` -> `Configuring system`, plus `profile.xml`, `vpn-gw-2.corp.example`, and `vpn-gw1.corp.example/outside`.

### 1757 — Live AnyConnect Control Plane Runs Through ACExtension OCSC Loopback
- FINDING: in `cisco-dump` session `20260326T144914Z`, the new all-loopback snapshots exposed `ACExtension:95058` on `127.0.0.1:54763 <-> 127.0.0.1:54764`; this process lives at `/Applications/AnyConnect.app/Wrapper/AnyConnect.app/PlugIns/ACExtension.appex/ACExtension`.
- FINDING: decoding the corresponding pcap stream shows a plain OCSC-framed control protocol with strings like `vpn-gw1.corp.example/outside`, `vpn-gw-2.corp.example`, `profile.xml`, `Please enter the requested proxy credentials`, and staged status text such as `Establishing VPN - Examining system` / `Activating VPN adapter` / `Configuring system`.
- DECISION: `internal/ciscodump/runtime.go` now treats `/Applications/AnyConnect` plus `ACExtension` / `acsockext` as first-class tracked Cisco processes, because the modern AnyConnect stack clearly does not surface everything through legacy `vpnagentd` / `cscan` alone.

### 1718 — cisco-dump Needed All-Loopback Attribution, Not Just Known Cisco PIDs
- FINDING: a live `cisco-dump` run captured a real `localhost-loopback.pcap` with `656 packets captured`, but the pid-filtered `sockets-*` snapshots still showed only the stable `vpnagentd:872 <-> vpn:2910` control socket pair on `127.0.0.1:29754`.
- ROOT CAUSE: loopback traffic in the pcap included additional ephemeral localhost flows outside the preselected Cisco PID set, so the previous snapshot view could not attribute those connections to processes even though the pcap itself was useful.
- FIX: `internal/ciscodump/runtime.go` now records an extra `all_loopback_tcp_lsof` section plus `all_loopback_tcp_netstat` alongside the tracked Cisco PID sections, and its socket snapshot digest now normalizes away volatile counters so repeated identical topology changes stop churning snapshots.

### 1337 — cisco-dump Was Too Narrow For Live AnyConnect IPC
- ROOT CAUSE: `cisco-dump` defaulted to `tcp and host 127.0.0.1 and port 60808`, but the live AnyConnect run exposed a different localhost TCP pair (`127.0.0.1:62824 -> 127.0.0.1:29754`), so the pcap stayed header-only.
- FINDING: per-pid `lsof` snapshots for root-owned Cisco helpers were also blind because `vpnagentd` needs privileged `lsof`; the old artifacts only captured user-owned `vpn -s`.
- FIX: `internal/ciscodump/runtime.go` now captures all localhost TCP by default, writes socket snapshots from `lsof -i` / `lsof -U` plus loopback `netstat`, and reuses the existing sudo timestamp for root-owned Cisco helper inspection.
- FIX: `internal/ciscodump/runtime.go` also mirrors `~/.cisco/vpn/cache` artifacts and stops writing duplicate process snapshots when only `etime` changed.

## 2026-03-25

### 0059 — openconnect-tun Now Uses OpenConnect As The ASA/CSD Source Of Truth
- ROOT CAUSE: the old `vpn-auth --server` full-flow path reached SAML and TOTP, but it still failed at ASA error 13 because the ASA/CSD handshake happened outside OpenConnect.
- FIX: `internal/openconnect/runtime.go` now always authenticates through `openconnect --authenticate`; when SAML is in play it injects a generated `--external-browser` wrapper that runs `vpn-auth --url`, captures the localhost callback, and replays it back into OpenConnect.
- FIX: the same runtime now resolves Homebrew `csd-post.sh` from the stable `opt/openconnect/libexec/openconnect/csd-post.sh` path when available and wraps it with tiny macOS `pidof` / GNU `stat -c %Y` shims instead of hardcoding a versioned Cellar path.
- FIX: added `internal/openconnect/runtime_test.go` coverage for stable `csd-post.sh` resolution and generated auth helper wiring.

### 0052 — openconnect-tun Terminal Output Now Shows Auth Stages
- FINDING: Live Corp auth no longer stalls at password entry; `vpn-auth` reaches the OTP page, so the remaining blind spot was stage visibility in the foreground terminal.
- FIX: `internal/openconnect/runtime.go` now mirrors only compact auth stage transitions to `ProgressWriter` as `auth_stage: ...` while keeping the full auth stderr in the per-session log file.
- FIX: Added `internal/openconnect/runtime_test.go` coverage for stage detection, dedupe, and TOTP-aware OTP stage naming.

### 0041 — multi-tun Local Runtime Now Layers Project Instructions And Board Skills
- FINDING: `alexis-agents-infra` local setup itself is healthy after the repo rename; the gap was project-local wiring on top of it, not the shared infra runtime.
- FIX: `scripts/setup.sh` now runs `agents-infra setup local` when available, copies `agents/instructions/INSTRUCTIONS_PROJECT.md` into `.agents/.instructions/INSTRUCTIONS_PROJECT.md`, and appends it to both local instruction entrypoints.
- FIX: Local setup now links the repo `vpn-config` skill plus the shared `project-management` skill into repo-local `.agents/skills`, `.claude/skills`, and `.codex/skills`.
- DECISION: `multi-tun` board-first workflow is now reinforced in repo `AGENTS.md`, repo-local project instructions, and the `vpn-config` skill text so spawned agents inherit the same board discipline.

### 0017 — Corp Auth Bootstrap Uses Searchable Keychain Account Prefix
- DECISION: `openconnect-tun` Corp password lookup now uses Keychain account `multi-tun-corp-vpn-pwd` instead of the shorter `corp-vpn-pwd`.
- FIX: Updated live config in `~/.config/openconnect-tun/config.json` and documented the auth block in `README.md`.
- NOTE: Service name remains `multi-tun`; only the account name changed to make future Keychain searches and inventory clearer.
- DECISION: Default Corp bootstrap now references one password secret only. `totp_secret_keychain_account` remains supported in code but is no longer wired in the live config.

### 0020 — openconnect-tun Reused Legacy Corp Password Entry
- DECISION: Live `openconnect-tun` auth config now points to existing Keychain account `corp-vpn/password` instead of inventing a new alias.
- FINDING: `corp-vpn/password` and `corp-vpn/totp_secret` already exist under service `multi-tun`; `multi-tun-corp-vpn-pwd` does not.
- FIX: Updated `~/.config/openconnect-tun/config.json` and the README auth example to match the existing Keychain inventory.

### 0026 — openconnect-tun Now Reads Corp Username From Keychain Too
- DECISION: Live Corp bootstrap is now fully keychain-backed for login identity: `corp-vpn/username` plus `corp-vpn/password` under service `multi-tun`.
- FIX: Added optional `auth.username_keychain_account` to `internal/openconnectcfg/config.go` and taught `resolveCredentials` in `internal/openconnectcli/app.go` to prefer explicit flags, then keychain-backed username, then plain `auth.username`.
- FIX: Added `internal/openconnectcli/app_test.go` coverage for keychain-backed username/password/TOTP and plain-username fallback.

## 2026-03-24

### 2328 — openconnect-tun Got Persistent Session Logs And Separate Cache Root
- FIX: `openconnect-tun` now persists runtime state in `~/.cache/openconnect-tun` with per-session logs under `sessions/` and `runtime/current-session.json`, separate from `~/.cache/vless-tun`.
- FIX: live `connect` now runs `sudo -v` before launching `openconnect` and then uses `sudo -n` for the actual `--cookie-on-stdin` call, removing the stdin conflict where `sudo` could eat the cookie or appear to hang.
- FIX: `status` now reports `cache_dir`, `session`, `session_id`, `log_file`, and stale-session `last_log_line`; `disconnect` now stops either the tracked session or an untracked live `openconnect` pid.
- FIX: lifecycle commands are now `run` / `reconnect` / `stop` to match `vless-tun`, while `connect` / `disconnect` stay as compatibility aliases.
- STATUS: `go test ./...`, `./scripts/setup.sh`, and dry-run profile resolution still pass.

### 2308 — openconnect-tun Dry-Run Path Validated And DNS Strategy Clarified
- FIX: `ResolveServerFromProfiles` now deduplicates identical `HostEntry` values repeated across `/opt/cisco/...` and `~/Downloads/...`, so profile selectors like `Ural Outside extended` resolve cleanly instead of failing as ambiguous.
- FACT: `openconnect-tun connect --profile 'Ural Outside extended' --mode full --dry-run` resolves to `vpn-gw2.corp.example/outside` with the Homebrew `vpnc-script`.
- FACT: `openconnect-tun connect --profile 'Ural Outside extended' --mode split-include --route 198.51.100.0/24 --route 203.0.113.0/24 --vpn-domains corp.example,digital.example,services.corp.example --dry-run` resolves to the same endpoint and wires `vpn-slice`.
- FACT: `vpn-slice` on macOS implements split DNS via scoped `/etc/resolver/<domain>` files, which is compatible with the goal of preserving the default resolver stack while adding Corp-only DNS.
- RISK: stock `vpnc-script` still owns global DNS and default route in full mode, so live full-tunnel smoke must stay isolated from parallel `vless-tun` sessions.

### 2235 — Repo Renamed To multi-tun And openconnect-tun Bootstrapped
- DECISION: `vpn-config` repo folder is now `multi-tun`; old orchestrator repo moved aside to `multi-tun_old`.
- FIX: Renamed the VLESS entrypoint from `cmd/vpn-config` to `cmd/vless-tun` and changed the Go module path to `multi-tun`.
- FIX: Added `openconnect-tun` with `status`, `profiles`, and `inspect-profiles` commands backed by `internal/openconnect` and local AnyConnect XML parsing.
- FACT: Live smoke check works against real Corp assets: `openconnect-tun status` sees 9 CLI profiles and `openconnect-tun inspect-profiles` parses `cp_corp_inside_3.xml` / `cp_corp_outside.xml` from both `/opt/cisco/...` and `~/Downloads/...`.
- SCOPE: `cmd/openconnect-tun`, `internal/openconnect`, `scripts/setup.sh`, `README.md`, `SPEC.md`, `AGENTS.md`.

### 1644 — Privileged TUN Backend Added
- DECISION: Real macOS TUN path stays in `vpn-config` under `vless-tun`, not `skill-multi-tun`.
- FIX: Added `render.privileged_launch` with `auto`, `sudo`, `direct`, `launchd` in `internal/config/config.go`.
- FIX: Reworked session backend in `internal/session/session.go` and `internal/session/launchd.go` so `run/status/stop/reconnect` support launch-aware lifecycle and persisted launch metadata.
- SCOPE: `internal/cli/run_stop.go`, `internal/cli/status.go`, `configs/local.example.json`, `README.md`, `SPEC.md`, `agents/skills/vpn-config/SKILL.md`.
- STATUS: `go test ./...` passes. Live verification under Telegram still pending in `TASK-260324-hqt44c`.

### 1645 — Render Tests Were Behind Current Defaults
- ANOMALY: `internal/singbox/render_test.go` still expected empty `rule_set` when direct bypasses were disabled, but default config already injects `proxy-exceptions`.
- FIX: Updated render tests to match current `bypass_exclude_suffixes` behavior.
- STATUS: Resolved.

## 2026-03-28

### 2358 — openconnect-tun Got A Passwordless Privileged Helper
- DECISION: The unattended-automation pain point belongs to `openconnect-tun`, not `vless-tun`, because the Corp SSO/CSD flow was already working and the remaining blocker was the final privileged `openconnect` start/stop step.
- FIX: Added a root LaunchDaemon helper in `internal/openconnect/helper.go` plus `openconnect-tun helper install|status|uninstall`, with a user-owned unix socket used for the final privileged `openconnect --background` launch and later `kill -INT/-TERM/-KILL` signaling.
- FIX: `openconnect.Connect()` now resolves the privileged backend automatically: `helper` first when the helper is reachable, otherwise the existing `sudo` path, while preserving the old pre-auth `sudo` preflight when the helper is absent.
- FIX: Session metadata and logs now record `privileged_mode` and `helper_socket`, and `openconnect-tun status` prints the active privileged mode for tracked sessions.
- TEST: Added helper unit coverage in `internal/openconnect/helper_test.go`; `go test ./...` passes.
- LIVE VERIFY: `openconnect-tun helper install` succeeded on the host, `helper status` reported `reachable`, and a real `openconnect-tun start` against `Ural Outside extended` completed with `privileged_mode=helper`, `server=vpn-gw2.corp.example/outside`, and `interface=utun233`.
- LIVE VERIFY: `openconnect-tun stop` then stopped the same session cleanly without falling back to `sudo`, and `openconnect-tun status` returned to `session: none`.
