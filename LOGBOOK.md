# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-04-08

### 1736 — `v2RayTun` macOS Accepts Unauthenticated Local SOCKS Clients
- FINDING: installed `v2RayTun` macOS runtime persists a localhost SOCKS inbound on `[::1]:1080` in [current-config.json](/Users/alexis/Library/Group%20Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Configs/current-config.json#L5) and a tun-to-SOCKS bridge to `::1:1080` in [socks-config.yml](/Users/alexis/Library/Group%20Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/Configs/socks-config.yml#L1).
- FINDING: during a live session on 2026-04-08, [logs.txt](/Users/alexis/Library/Group%20Containers/2XZUN9L63Z.com.databridges.privacy.v2RayTun/logs.txt#L1650) recorded `Primary inbound (DEFAULT) -> ::1:1080` and `Starting SOCKS5 tunnel on ::1:1080…`; `lsof` showed `packet-extension-mac` listening on `[::1]:1080`.
- FINDING: raw SOCKS5 greeting `printf '\x05\x01\x00' | nc -6 -w 2 ::1 1080 | xxd -p` returned `0500`, proving the listener accepted `NO AUTHENTICATION REQUIRED` from an unrelated local shell process.
- FINDING: `curl --socks5-hostname '[::1]:1080' https://api.ipify.org` returned HTTP `200` and body `144.31.90.46`, proving a second local process could use the active tunnel through the listener without credentials.
- DECISION: treat `v2RayTun` macOS as a concrete example of the localhost-proxy attack surface discussed in the April 2026 Habr article; this is now a positive contrast case for `vless-tun` after removal of `system_proxy`.
- SCOPE: full audit captured in [artifacts/v2raytun-apple-audit/README.md](/Users/alexis/src/multi-tun/artifacts/v2raytun-apple-audit/README.md).

## 2026-04-02

### 1720 — `vless-tun` Config Remastered Around `source`, `network`, And Provider-Neutral Artifacts
- DECISION: the old `vless-tun` config shape overloaded root `subscription_url` plus a broad `render` block with unrelated concerns: source selection, mode, TUN/system-proxy transport, bypass policy, proxy DNS, generated artifact path, and launch backend details all lived together.
- FIX: [internal/config/config.go](/Users/alexis/src/multi-tun/internal/config/config.go) now supports a preferred schema built around `source`, optional `default`, `network`, optional `launch`, `routing`, `dns`, `logging`, and `artifacts`, while still reading the legacy `subscription_url`, `selected_profile`, and `render` fields as fallbacks.
- FIX: `source.mode=proxy|direct` is now real runtime behavior instead of just a config idea: [fetch.go](/Users/alexis/src/multi-tun/internal/subscription/fetch.go) treats `proxy` as an HTTP source that resolves to one or more `vless://` entries and `direct` as a literal `vless://...` source with no extra fetch hop.
- DECISION: `launch` is now modeled as an override-only block. If it is omitted, `vless-tun` keeps the existing automatic behavior and prefers the shared `vpn-core` backend when it is available instead of forcing launch backend details into the happy-path config.
- DECISION: the generated sing-box artifact was renamed conceptually from provider-specific `dancevpn-sing-box.json` to neutral `artifacts.singbox_config_path`, with the live config now pointing at `~/.config/vless-tun/generated/sing-box.json`.
- LIVE CHANGE: [config.json](/Users/alexis/.config/vless-tun/config.json) was migrated to the preferred shape without any legacy mirror fields; [README.md](/Users/alexis/src/multi-tun/README.md) now documents the new tree and the optional `launch` override model.
- TEST: Added coverage in [config_test.go](/Users/alexis/src/multi-tun/internal/config/config_test.go) and [fetch_test.go](/Users/alexis/src/multi-tun/internal/subscription/fetch_test.go); `go test ./...` passed, `./vless-tun` was rebuilt, `./vless-tun render` emitted the new `generated/sing-box.json`, and `./vless-tun status --config ...` now reports `mode: tun` with the new rendered artifact path.

### 1645 — `openconnect-tun` Config Remastered Around `default` + Nested Server Profiles
- DECISION: the old `openconnect-tun` config shape was carrying one VPN policy across root `split_include`, top-level `servers[...]`, and top-level `profiles[...]`, which made the relationship between selected profile and real ASA endpoint indirect and hard to read.
- FIX: [internal/openconnectcfg/config.go](/Users/alexis/src/multi-tun/internal/openconnectcfg/config.go) now supports a remastered preferred schema with `default.server_url`, `default.profile`, and nested `servers.<url>.profiles.<profile>.{mode,split_include}` while remaining backward-compatible with the legacy fields.
- FIX: [internal/openconnectcli/app.go](/Users/alexis/src/multi-tun/internal/openconnectcli/app.go) now resolves defaults from the new `default` block, resolves configured server URLs directly from nested profile entries before falling back to AnyConnect XML, and prefers profile-scoped `mode` over the legacy root `default_mode`.
- FIX: `vpn_domains` are now normalized as suffix masks rather than a plain deduped string list, so covered entries like `inside.corp.example` collapse under `corp.example` during option resolution.
- LIVE CHANGE: `~/.config/openconnect-tun/config.json` was migrated from the mixed legacy-plus-draft state to the new single-shape layout, with Corp split-include routes/nameservers/profile policy now living only under `servers.vpn-gw2.corp.example/outside.profiles.Ural Outside extended`.
- TEST: Added coverage in [config_test.go](/Users/alexis/src/multi-tun/internal/openconnectcfg/config_test.go) and [app_test.go](/Users/alexis/src/multi-tun/internal/openconnectcli/app_test.go); `go test ./...` passed and `./openconnect-tun` was rebuilt.

### 1510 — `openconnect-tun stop` Now Clears Orphaned Root Resolver State
- ROOT CAUSE: interrupted `openconnect-tun` runs could leave root-owned `/etc/resolver/*` split-include files behind after `runtime/current-session.json` was already gone; in that state `openconnect-tun status` showed `session: none`, but `scutil --dns` still published `corp.example -> 10.23.16.4/10.23.0.23`, which is enough to break official Cisco AnyConnect SSO navigation on the same host.
- FIX: [internal/openconnect/session.go](/Users/alexis/src/multi-tun/internal/openconnect/session.go) now runs orphaned resolver cleanup from `Stop(...)` for `cleaned_orphaned`, `stale_cleaned`, and `cleared_starting_cleaned` states; cleanup goes through the shared `vpn-core` helper when available and removes only files marked as owned by `openconnect-tun`.
- FIX: [internal/openconnectcli/app.go](/Users/alexis/src/multi-tun/internal/openconnectcli/app.go) now reports those cleanup states explicitly, and [internal/openconnect/session_test.go](/Users/alexis/src/multi-tun/internal/openconnect/session_test.go) covers the no-session and pid=0 starting-session cases.
- LIVE VERIFY: `./openconnect-tun stop` on 2026-04-02 removed the stale Corp resolver set; `/etc/resolver` collapsed back to `search.tailscale` only and `scutil --dns` no longer showed Corp supplemental resolvers.

### 1450 — Native CSD Was Still Using The Old Hostname Resolver For Cert Hash
- ROOT CAUSE: after `fetching_saml_config` was fixed, aggregate hostscan could still fall back to `csd-post.sh` because [internal/openconnect/runtime.go](/Users/alexis/src/multi-tun/internal/openconnect/runtime.go) fetched the server cert SHA1 with `tls.Dial(hostname:443)`, which still used the pre-fix system resolver path for `vpn-gw2.corp.example`.
- FINDING: live session `openconnect-session-20260402T111926Z.log` reached `aggregate_auth_hostscan` and logged only `hostscan_csd_wrapper: /opt/homebrew/.../csd-post.sh` before the user interrupted, confirming native `libcsd` had been rejected before wrapper execution even though `~/.cisco/vpn/cache/lib64_appid/libcsd.dylib` existed.
- FIX: [internal/openconnect/runtime.go](/Users/alexis/src/multi-tun/internal/openconnect/runtime.go) now resolves the server address through `resolveOpenConnectDialAddress(...)` before the TLS dial used for cert hashing, and hostscan logs `hostscan_csd_native_unavailable` when native CSD setup fails.
- TEST: [internal/openconnect/runtime_test.go](/Users/alexis/src/multi-tun/internal/openconnect/runtime_test.go) now covers SHA1 fetch through a resolved fallback address; `go test ./...` passed and `./openconnect-tun` was rebuilt.

### 1420 — vless Overlay DNS Was Outranking Existing Bypass Suffixes
- ROOT CAUSE: with `vless-tun` active in `tun` mode, broad bypasses (`.ru`, `.xn--p1ai`) already existed, but overlay render still routed matching corporate suffixes to `dns-overlay` before evaluating bypass DNS rules. That made `vpn-gw2.corp.example` resolve on the corporate overlay path despite explicit bypass intent.
- FIX: [internal/singbox/render.go](/Users/alexis/src/multi-tun/internal/singbox/render.go) now adds `dns-direct` under overlay when bypass suffixes exist and orders tun-mode DNS rules as `proxy-exceptions -> ru-direct -> dns-overlay -> final proxy`, so bypass DNS wins over broader overlay suffixes.
- FIX: local `~/.config/openconnect-tun/config.json` now lists `vpn-gw2.corp.example` in the active `bypass_suffixes` overrides for `vpn-gw2.corp.example/outside` and `Ural Outside extended`.
- TEST: [internal/singbox/render_test.go](/Users/alexis/src/multi-tun/internal/singbox/render_test.go) updated for the new precedence model; `go test ./...` passed and `./vless-tun` was rebuilt.

### 1358 — SAML Bootstrap Hung On Pre-VPN `corp.example` Supplemental DNS
- ROOT CAUSE: live `openconnect-tun start` stalled at `auth_stage: fetching_saml_config` because `vpn-gw2.corp.example` matched an active `corp.example` supplemental resolver on `10.23.16.4/10.23.0.23` before VPN establishment; on this host both Go `net.LookupHost`/`getaddrinfo` and `dscacheutil` could hang on that path, so aggregate-auth never read the initial SAML config.
- FINDING: plain `dig vpn-gw2.corp.example` returned `198.51.100.22` immediately and `curl --resolve vpn-gw2.corp.example:443:198.51.100.22 https://vpn-gw2.corp.example/outside` returned `HTTP/1.1 200 OK`, isolating the blocker to local resolver selection rather than ASA reachability.
- FIX: [internal/openconnect/runtime.go](/Users/alexis/src/multi-tun/internal/openconnect/runtime.go) now bounds the primary host lookup with a short timeout, prefers aliases plus `dig` fallback before `dscacheutil`, and applies a timeout to `dscacheutil` itself.
- TEST: [internal/openconnect/runtime_test.go](/Users/alexis/src/multi-tun/internal/openconnect/runtime_test.go) adds regression coverage for timeout-to-fallback and `dig` fallback; `go test ./...` passed and `./openconnect-tun` was rebuilt.

## 2026-04-01

### 1349 — portal DNS Splits Between Public And Corporate Views
- FINDING: official AnyConnect dump `cisco-dump-session-20260401T103101Z` captured conflicting `portal.corp.example` views inside one session: `snapshots/host-probes-network_change-20260401T103227.970Z.txt` shows `dscacheutil` plus route pinned to `10.25.1.4` on `utun5`, corporate `dig @10.23.16.4/.23` also returns `10.25.1.4`, and TCP/HTTPS probes time out; later `snapshots/host-probes-network_change-20260401T103326.093Z.txt` shows `dscacheutil`, route, and HTTPS back on public `203.0.113.27` via `en0` with `HTTP/2 302`.
- FINDING: standalone `openconnect-tun` dump `cisco-dump-session-20260401T103604Z` stayed on the private view through `snapshots/host-probes-final_stop-20260401T103737.762Z.txt`: `dscacheutil` and route resolve `portal.corp.example` to `10.25.1.4` on `utun5`, plain `dig` still returns `www.corp.example` -> `203.0.113.27`, corporate `dig @10.23.16.4/.23` returns `10.25.1.4`, and TCP/HTTPS probes time out.
- STATUS: treat `portal.corp.example` as a separate DNS-routing edge case, not as the same class of failure as the broader Corp suffix merge/order bug.

### 1130 — vless-tun Stop/Status Now Recover Legacy Launchd Sessions
- FIX: `internal/session/session.go` now resolves current session via `ResolveCurrent(...)`, falling back to a live `works.relux.vless-tun` LaunchDaemon plus latest launchd session metadata when `runtime/current-session.json` is missing after reboot.
- FIX: `internal/session/launchd.go` now reads `launchctl print system/<label>` without `sudo` first, so normal-user `vless-tun status|diagnose` can detect legacy system launchd services; privileged `bootout` still requires sudo.
- FIX: `internal/cli/status.go`, `internal/cli/diagnose.go`, and `internal/cli/run_stop.go` now use the recovered launchd session, so `vless-tun stop` enters the privileged launchd stop path instead of returning `no current session file found`.
- TEST: Added launchd fallback coverage in `internal/session/session_test.go`; `go test ./internal/session ./internal/cli` and `go test ./...` pass.
- LIVE VERIFY: rebuilt `vless-tun`; live `vless-tun status` now shows `session: active`, `pid: 570`, `launch_mode: launchd` for the orphaned daemon on the host.

### 1110 — Live vless-tun Config Moved Off Legacy Launchd Mode
- DECISION: live `~/.config/vless-tun/config.json` now sets `render.privileged_launch.mode="sudo"` so future `vless-tun run` starts only on explicit user command and no longer chooses the legacy launchd path for this host.
- FINDING: `vless-tun diagnose` now reports `configured_launch_mode: sudo`, while the already-loaded `works.relux.vless-tun` LaunchDaemon remains active until removed with root privileges.
- BLOCKED: unloading `system/works.relux.vless-tun` and deleting `/Library/LaunchDaemons/works.relux.vless-tun.plist` require admin authentication on the host; agent-side `sudo -n` and unprivileged `launchctl bootout` both failed.

### 1103 — vless-tun Status Misses RunAtLoad LaunchDaemon After Reboot
- FINDING: live host state showed `openconnect-tun status -> session: none, state: disconnected`, but `vless-tun status` reported `connection: degraded` with `session: none` while `launchctl print system/works.relux.vless-tun` showed a running LaunchDaemon pid and `netstat -rn -f inet` still routed `0/1` and `128/1` via `utun233`.
- ROOT CAUSE: `~/.config/vless-tun/config.json` still pins `render.privileged_launch.mode=launchd`, `/Library/LaunchDaemons/works.relux.vless-tun.plist` has `RunAtLoad=true`, and `internal/cli/status.go` only reports an active session when `~/.cache/vless-tun/runtime/current-session.json` exists; after reboot the daemon restarts `sing-box` but that runtime pointer is absent, so CLI loses ownership while the tunnel stays active.
- ANOMALY: the active daemon was still using legacy session log `/Users/alexis/.cache/vless-tun/sessions/sing-box-session-20260328T101711Z.log`, confirming launchd service persistence independent of newer helper-mode session metadata.
- STATUS: Diagnosed on live host; cleanup/fix not applied in this slice.

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
