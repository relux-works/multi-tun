# SSH Proxy Product Contract

- Board task: `TASK-260714-2zf19z` — Define SSH proxy product contract
- Parent story: `STORY-260714-3h0sfw` — Productize SSH proxy HTTP bridge
- Research date: 2026-07-14
- Scope: desktop architecture and acceptance criteria only; no product code changes
- Diagram: [`diagrams/plantuml/sequence/ssh-proxy-managed-lifecycle.puml`](diagrams/plantuml/sequence/ssh-proxy-managed-lifecycle.puml)

## Verdict

The proposed product is coherent and implementable without a platform or protocol blocker.
`ssh-proxy` is the only canonical user-facing name. One managed daemon owns the
system SSH dynamic-forwarding child and one native plaintext HTTP/1.1 forward-proxy
listener on loopback. HTTPS clients use HTTP `CONNECT`; there is no TLS listener,
certificate installation, or TLS interception. Both HTTP request modes open their
upstream TCP connection through SOCKS5 while preserving destination hostnames for
resolution from the remote SSH host.

The existing `ssh-tun` implementation is uncommitted and has no released compatibility
contract, so the correct migration is a clean source rename, not an alias or dual-path
compatibility layer. The contract below resolves all product decisions in scope.

## Key Takeaways

- `ssh-proxy` replaces `ssh-tun` everywhere: command, package, config/cache paths,
  setup/deinit wiring, examples, logs, tests, and documentation.
- Exactly one daemon owns both runtime components for a selected profile. Startup is
  SSH -> protocol-level SOCKS5 readiness -> HTTP bridge; shutdown is HTTP bridge -> SSH.
- The proxy exposes one plaintext HTTP endpoint at `http://127.0.0.1:8080` by default.
  Ordinary HTTP uses absolute-form forwarding; HTTPS uses an opaque `CONNECT` tunnel.
- Hostnames are sent to SOCKS5 as `ATYP=DOMAINNAME`; the bridge must not resolve them
  locally. OpenSSH then connects from the remote machine.
- Both listeners are restricted to the exact IPv4 loopback address `127.0.0.1`.
  The product never changes macOS system proxy state and never installs trust material.
- `ssh-proxy run -- command ...` ensures the runtime is ready and scopes proxy
  environment variables to that child process. It does not invoke a shell or stop a
  daemon that remains under the explicit `start`/`stop` lifecycle.

## Context And Existing Boundaries

The repository currently contains an untracked desktop implementation under
`desktop/internal/sshtun/` and `desktop/cmd/ssh-tun/`. `git ls-files` and `git log`
return no tracked history for those paths; `git status --short` reports them as new
files. This supports a clean rename before the first committed product contract.

### Existing Behavior Verified From Source

| Boundary | Current behavior | Evidence |
| --- | --- | --- |
| Product path | Defaults to `~/.config/ssh-tun/config.json` and `~/.cache/ssh-tun/<profile>` | `desktop/internal/sshtun/config/config.go:51-64` |
| Profile selection | `current` or `--server` resolves one configured SSH host | `desktop/internal/sshtun/config/config.go:151-193` |
| SSH transport | `/usr/bin/ssh -N -C -D ...` with forward-failure, keepalive, timeout, batch, and quiet options | `desktop/internal/sshtun/config/config.go:200-215` |
| Process owner | CLI detaches the SSH process with `Setsid`; no long-lived parent owns another component | `desktop/internal/sshtun/cli/app.go:121-168` |
| Readiness | A successful TCP connection to the SOCKS port is treated as ready | `desktop/internal/sshtun/cli/app.go:292-312` |
| State | Atomic JSON records one PID, endpoint, profile, timestamp, and log path | `desktop/internal/sshtun/session/session.go:12-60` |
| Status | `up`, `degraded`, or `down` is derived from SSH PID liveness plus a TCP connect | `desktop/internal/sshtun/cli/app.go:171-210` |
| Stop | CLI signals the recorded SSH PID, optionally escalates to kill, then removes state | `desktop/internal/sshtun/cli/app.go:213-273` |
| Bind validation | Any syntactically valid IP is currently accepted; it is not restricted to loopback | `desktop/internal/sshtun/config/config.go:218-230` |
| Installation | Setup builds/links `ssh-tun` and seeds its old config path; deinit removes old binary/config/cache paths | `scripts/setup.sh:9-28`, `scripts/setup.sh:236-329`, `scripts/deinit.sh:9-40` |

The focused baseline command `go test ./desktop/internal/sshtun/...` passed on
2026-07-14. It proves the current config/session/CLI tests are green; it does not prove
the target daemon or HTTP bridge because those components do not exist yet. Evidence is
stored in `.temp/TASK-260714-2zf19z/go-test-sshtun-01.log`.

### Gaps The New Contract Must Close

1. A detached SSH child cannot own the in-process HTTP listener. A daemon boundary is
   required so failure, status, and shutdown are atomic across both components.
2. TCP accept is weaker than SOCKS readiness. Startup must complete a SOCKS5 greeting
   before exposing the HTTP proxy.
3. Current validation accepts `0.0.0.0`, LAN addresses, and other non-loopback IPs.
   The target product must reject them before any process or listener starts.
4. Current state names one generic PID. Target state must distinguish daemon PID from
   SSH child PID and record both endpoint states.
5. No HTTP proxy, `CONNECT` path, ordinary HTTP forwarding path, or child-only launcher
   exists in the current implementation.

## Normative Product Contract

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative within this
document.

### 1. Canonical Product Identity

- The public command MUST be `ssh-proxy`.
- `ssh-proxy` names the application-scoped proxy product. A future transparent TUN
  product may separately use `ssh-tun`, but that name MUST NOT be retained as an alias,
  migration shim, or documentation synonym for this product.
- Public help, output, README text, setup/deinit scripts, examples, binary names, log
  names, and test fixtures MUST use `ssh-proxy`.
- Go entrypoint/package paths MUST move to `desktop/cmd/ssh-proxy/` and
  `desktop/internal/sshproxy/`.
- Default paths MUST be:
  - config: `${XDG_CONFIG_HOME:-$HOME/.config}/ssh-proxy/config.json`
  - per-profile cache: `${XDG_CACHE_HOME:-$HOME/.cache}/ssh-proxy/<profile>/`
  - current state: `<cache>/runtime/current-session.json`
  - session logs: `<cache>/sessions/ssh-proxy-session-<id>.log`
- This story's shipped implementation MUST NOT contain an `ssh-tun` executable,
  install symlink, compatibility command, config fallback, cache fallback, or dual-read
  behavior.
- Historical research may name `ssh-tun` only to explain the pre-commit rename.

### 2. Configuration And Clean Migration

The resolved server profile MUST retain the current SSH transport fields and add one
HTTP proxy port:

```json
{
  "current": "dedicated",
  "servers": {
    "dedicated": {
      "host": "ssh.example.invalid",
      "account": "",
      "listen_address": "127.0.0.1",
      "socks_port": 1080,
      "http_port": 8080
    }
  }
}
```

Rules:

- Omitted `listen_address`, `socks_port`, and `http_port` resolve to `127.0.0.1`,
  `1080`, and `8080` respectively.
- `listen_address` applies to both listeners and MUST resolve to the exact string
  `127.0.0.1`. `localhost`, `0.0.0.0`, `::1`, LAN addresses, and other IPs are not
  accepted in version 1. This gives setup, status output, and tests one deterministic
  security boundary.
- Both ports MUST be in `1...65535` after defaults and MUST differ.
- Existing `host`, optional `account`, optional cache override, SSH executable override,
  and selected `dedicated` profile semantics remain unchanged.
- This is a clean source migration. There is no automatic runtime fallback to
  `~/.config/ssh-tun` and no cache migration. Old PID state MUST NOT be reused.
- Setup MUST preserve an existing `~/.config/ssh-proxy/config.json`; it may seed the
  renamed example only when the new path is absent.
- Any developer-only pre-commit config that must be retained is copied once to the new
  path outside product behavior. Setup MUST NOT silently overwrite or delete it.
- A still-running old process that owns either port causes a clear start/setup failure;
  the new product MUST NOT kill an unidentified process to reclaim a port.

### 3. Runtime Ownership And State

- Each resolved active profile has exactly one managed `ssh-proxy` daemon, protected by
  a per-profile lock. A second start for the same profile MUST fail without changing the
  live runtime.
- The daemon is the sole owner of:
  1. the `/usr/bin/ssh` child,
  2. the SOCKS5 readiness state,
  3. the HTTP forward-proxy listener and active relays,
  4. the current-session state file and lifecycle log.
- There is no separate HTTP service, launchd job, or system-wide proxy helper.
- Commands resolve one profile per invocation. Separate profiles MAY run concurrently
  only when their SOCKS and HTTP endpoints are distinct.
- State MUST be written atomically with mode `0600`; profile runtime/cache directories
  SHOULD be user-only (`0700`). State MUST distinguish at least:
  - instance/session ID,
  - lifecycle state,
  - daemon PID,
  - SSH child PID,
  - profile and SSH host,
  - SOCKS and HTTP endpoints,
  - per-endpoint readiness,
  - start timestamp and log path.
- State MUST NOT contain SSH keys, agent material, proxy payloads, request headers,
  cookies, authorization values, or request bodies.

### 4. Start Ordering And Atomicity

`ssh-proxy start [--config path] [--server profile]` is synchronous and MUST return
success only after both endpoints are usable.

1. Load and validate config without side effects.
2. Acquire the per-profile lock and reject a live instance.
3. Reject unavailable or identical endpoint ports before spawning SSH.
4. Start the daemon and record `starting` state.
5. Start `/usr/bin/ssh` with dynamic forwarding bound to
   `127.0.0.1:<socks_port>` and the existing hardened arguments.
6. Wait for SSH liveness and complete a SOCKS5 greeting. A bare TCP connect is not
   sufficient readiness evidence.
7. Only after SOCKS5 readiness, bind and start the HTTP listener at
   `127.0.0.1:<http_port>`.
8. Mark `up`, atomically persist both PIDs/endpoints, and return them to the caller.

If SSH exits, SOCKS readiness times out, the HTTP port loses a bind race, or HTTP server
startup fails, the daemon MUST close any partial HTTP state, terminate and wait for the
SSH child, remove current state/lock, and return a nonzero start result. A failed start
must never leave a usable half-runtime.

If the SSH child exits later, the daemon MUST immediately stop accepting HTTP proxy
traffic, close active relays, record the failure, and shut itself down. If the HTTP
server fails fatally, the daemon MUST terminate SSH and shut down. The bridge must
never remain advertised without its managed SOCKS upstream.

### 5. Stop Ordering

`ssh-proxy stop [--config path] [--server profile] [--timeout duration] [--force]`
MUST be idempotent.

1. Resolve the selected profile and current daemon instance.
2. Ask that daemon to enter `stopping`.
3. Close the HTTP listener first so no new proxy requests are accepted.
4. Close/drain active HTTP and CONNECT relays within the bounded shutdown timeout.
5. Signal the SSH child with `SIGTERM` and wait.
6. If and only if `--force` is present after timeout, escalate owned processes to
   `SIGKILL`.
7. Remove current state and lock only after both components are down.

When state is absent, stop reports already down and succeeds. Stale state may be
removed only after proving the recorded daemon is not alive; PID-only state must not
be used to kill an unrelated process.

### 6. Status Contract

`ssh-proxy status` MUST be read-only with respect to live processes and MUST report:

- aggregate `connection`: `down`, `starting`, `up`, `degraded`, or `stopping`,
- daemon liveness and PID,
- SSH child liveness and PID,
- profile and SSH host,
- `socks_listen` and `socks_ready`,
- `http_proxy` and `http_ready`,
- session ID, start time, and log path when state exists,
- stale-state indication when state exists but its daemon is gone.

`up` means the daemon is alive, the SSH child is alive, a SOCKS5 greeting succeeds,
and the daemon has an active HTTP listener. `degraded` means the daemon is alive but
at least one owned component is not ready; it is a transient failure state and must
progress to shutdown, not remain indefinitely. `down` is a successful status result,
not a CLI error. Invalid config or unreadable/corrupt state is a nonzero CLI error.

### 7. HTTP-To-SOCKS5 Bridge

The bridge is one plaintext HTTP/1.1 forward proxy. The proxy URL is always
`http://127.0.0.1:<http_port>`, including the value used for `HTTPS_PROXY`.
“HTTPS support” means `CONNECT` tunneling through this HTTP proxy; it does not mean
TLS on the loopback listener.

#### CONNECT Requests

1. Require authority-form `host:port`; reject an empty/malformed host or port with
   `400 Bad Request`.
2. Open a SOCKS5 `CONNECT` to the requested destination.
3. For a hostname, encode the original hostname as SOCKS5 `ATYP=DOMAINNAME`; do not
   resolve it with the local resolver. IP literals use their corresponding SOCKS5
   address type.
4. On success, return `200 Connection Established` without `Content-Length` or
   `Transfer-Encoding`, then relay bytes bidirectionally and opaquely.
5. Preserve half-close semantics long enough to flush outstanding bytes, then close
   both sides. Do not parse TLS, generate certificates, or inspect tunneled content.
6. Map upstream refusal/protocol failure to `502 Bad Gateway` and bounded connect
   timeout to `504 Gateway Timeout`.

Version 1 accepts any syntactically valid TCP port. This is a deliberate local-tool
decision: the listener is restricted to trusted loopback clients, not deployed as a
network proxy. Documentation MUST state that any local process able to connect can use
the tunnel and that there is no destination ACL or proxy authentication.

#### Ordinary HTTP Requests

1. Require an absolute-form `http://host[:port]/path?query` request target. HTTPS uses
   `CONNECT`; unsupported schemes receive `501 Not Implemented`.
2. Derive the destination and `Host` from the absolute request target, ignoring a
   conflicting received `Host` value.
3. Open the origin TCP connection through SOCKS5 using the original hostname and port
   (`80` when omitted).
4. Forward origin-form path/query to the origin. Preserve method, body, end-to-end
   headers, and response semantics.
5. Remove the incoming `Connection` field and every header it nominates; remove other
   hop-by-hop/proxy-only fields before forwarding. Add an appropriate `Via` field.
6. The bridge is not a cache and MUST NOT transform payload content.
7. Malformed client messages receive `400`; SOCKS/origin failure receives `502`;
   bounded origin timeout receives `504`.

These rules are necessary for both GET-like and body-carrying requests; validation must
include at least GET and POST so “ordinary HTTP” does not accidentally mean GET only.

### 8. Generic Service-Scoped Launcher

Public syntax is:

```text
ssh-proxy run [--config path] [--server profile] -- command [arg ...]
```

Contract:

- `--` and a non-empty command are required.
- `run` resolves the profile and uses the same start/health path. It launches the child
  only after aggregate status is `up`; startup failure prevents child execution.
- The command is executed directly as an argument vector, not through a shell. Child
  stdin/stdout/stderr remain attached, signals are forwarded, and `ssh-proxy run`
  returns the child's exit status.
- The child environment starts from the caller environment, then replaces any existing
  proxy keys with:
  - `HTTP_PROXY=http://127.0.0.1:<http_port>`
  - `HTTPS_PROXY=http://127.0.0.1:<http_port>`
  - lowercase `http_proxy` and `https_proxy` aliases with the same value for client
    compatibility.
- `NO_PROXY`/`no_proxy` are inherited unchanged. `ALL_PROXY` is not injected.
- Environment changes exist only in the child and its descendants. The launcher MUST
  NOT mutate the parent shell, launchd environment, macOS SystemConfiguration, or
  network service proxy settings.
- `run` does not auto-stop the managed daemon when the child exits. Lifecycle remains
  explicit and race-free through `start`/`stop`; concurrent child commands cannot tear
  down one another's proxy.
- Documentation may show Claude Code as one consumer, but no Claude-specific command,
  process detection, configuration, or lifecycle logic belongs in `ssh-proxy`.
- SOCKS-aware non-HTTP clients use `socks5h://127.0.0.1:<socks_port>` or their native
  remote-DNS SOCKS setting. `run` does not pretend HTTP proxy variables cover arbitrary
  protocols.

### 9. Security Boundary

| Boundary | Normative decision |
| --- | --- |
| Network exposure | Both listeners bind only exact `127.0.0.1`; config validation rejects every other address before startup. |
| Local trust | No proxy authentication. Any local process that can reach the port can use the remote egress; this is not protection against hostile local accounts or malware. |
| TLS | No TLS interception, local CA, certificate generation, SNI rewriting, or decrypted payload inspection. CONNECT is a blind relay. |
| System configuration | No `networksetup`, `scutil`, SystemConfiguration mutation, PAC file, or global environment mutation. |
| Privilege | Runs as the invoking user; no root/helper/LaunchDaemon is required for the proxy runtime. |
| SSH credentials | Authentication remains with OpenSSH config, agent, and Keychain. The product stores no private key, password, or agent socket contents. |
| DNS | Hostnames cross the local SOCKS5 connection as domain names and are selected/resolved from the remote SSH side. |
| Logging | Lifecycle, redacted errors, PIDs, endpoints, and timing only. Never request/response bodies, cookies, auth headers, or tunneled bytes. |
| Resource limits | Header size, handshake, connect, idle, and shutdown durations must be bounded; fatal component failure tears down the aggregate runtime. |

IANA classifies `127.0.0.0/8` as loopback and neither forwardable nor globally
reachable. Binding `127.0.0.1` prevents remote network ingress, but it does not create a
same-user authorization boundary; the local-trust caveat above remains mandatory.

## Protocol Fact Check

The design was checked against primary specifications and official runtime docs:

1. OpenSSH documents `-D` as a local dynamic application-level forward, supports
   SOCKS4/SOCKS5, and determines the remote connection destination from the application
   protocol. This validates the existing SSH transport and the bridge's use of the local
   SOCKS5 endpoint. Source: [OpenBSD `ssh(1)` manual, `-D`](https://man.openbsd.org/ssh.1#D).
2. SOCKS5 defines `ATYP=0x03` for a domain-name `DST.ADDR`. Combined with OpenSSH's
   “connect from the remote machine” behavior, preserving the hostname in the SOCKS5
   request is the standards-aligned way to avoid local DNS. The remote-DNS conclusion is
   an inference from these two primary sources. Source: [RFC 1928 sections 4-6](https://www.rfc-editor.org/rfc/rfc1928.html#section-4).
3. HTTP `CONNECT` requests a blind bidirectional tunnel; any 2xx switches immediately
   into tunnel mode, and the intermediary must close both sides after flushing when one
   side closes. This validates opaque HTTPS support without MITM. Source:
   [RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).
4. HTTP/1.1 clients send ordinary proxy requests in absolute-form and CONNECT in
   authority-form. A proxy must derive a new `Host` from the absolute target. Source:
   [RFC 9112 sections 3.2.2-3.2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2).
5. HTTP intermediaries must remove `Connection`-nominated fields and proxies must add
   `Via`; this informs ordinary forwarding tests. Source:
   [RFC 9110 sections 7.6.1 and 7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1).
6. Go's default HTTP transport recognizes `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
   plus lowercase variants, validating the generic child environment contract. Source:
   [Go `net/http.ProxyFromEnvironment`](https://pkg.go.dev/net/http#ProxyFromEnvironment).
7. Go `os/exec` accepts an explicit per-child environment and does not invoke a shell by
   default, validating child-only injection and direct argument execution. Source:
   [Go `os/exec.Cmd`](https://pkg.go.dev/os/exec#Cmd).
8. IANA marks `127.0.0.0/8` as loopback, non-forwardable, and not globally reachable.
   Source: [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml).

No source contradicts the managed daemon or HTTP-to-SOCKS design. RFC 9110 warns that
unrestricted CONNECT can relay non-Web ports. Version 1 consciously accepts that risk
inside the documented loopback/local-process trust boundary; it MUST NOT be generalized
to a non-loopback listener without a separate authentication and destination-policy
decision.

## Acceptance And Validation Matrix

The implementation is acceptable only when every row passes.

| Area | Required evidence |
| --- | --- |
| Clean rename | `ssh-proxy` is the only installed/documented command; packages, examples, outputs, config/cache/log paths, setup/deinit, `.gitignore`, and tests use the canonical name. No user-facing `ssh-tun` compatibility path remains. |
| Config | Tests prove defaults `127.0.0.1`, `1080`, `8080`; reject non-loopback addresses, equal/out-of-range ports, missing host, and invalid current profile; preserve the dedicated profile and SSH args. |
| Single owner | Tests prove duplicate start rejection, daemon/SSH PID state, atomic state writes, stale state recovery without signaling an unrelated PID, and no separate bridge process. |
| Start ordering | A fake SSH/SOCKS harness proves HTTP never binds before a successful SOCKS5 greeting. SOCKS timeout, SSH early exit, and HTTP bind failure each tear down all partial state. |
| Stop ordering | Instrumented fakes prove HTTP listener/relays close before SSH receives termination; timeout and `--force` escalation affect only owned processes; repeated stop succeeds. |
| Status | Tests cover down, starting, up, degraded, stopping, and stale state; output includes daemon, SSH, both endpoints, and both readiness values. |
| CONNECT | Fake SOCKS captures `ATYP=DOMAINNAME` and unchanged hostname/port; a client receives 200 only after SOCKS success; bidirectional opaque bytes and half-close behavior pass; upstream failures map to 502/504. |
| Ordinary HTTP | GET and POST arrive at a fake origin through fake SOCKS with origin-form path/query, reconstructed Host, body intact, hop-by-hop fields removed, Via present, and response returned. |
| Security | Runtime tests inspect listener addresses and reject `0.0.0.0`, LAN IPs, `localhost`, and `::1`; logs contain no payload/auth data; no test or code path invokes macOS system proxy tools. |
| `run` launcher | Tests prove startup-before-child, exact proxy URL injection in upper/lowercase keys, unchanged parent environment and NO_PROXY, direct argv execution, stdio/signal forwarding, child exit-code propagation, and daemon persistence after child exit. |
| Live egress | A proxy-aware HTTP client shows direct public egress differs from both ordinary HTTP and HTTPS-via-CONNECT requests launched with `ssh-proxy run`, and proxied egress matches the dedicated Mac. Record redacted IP/location evidence only. |
| Full validation | `go test -race ./desktop/internal/sshproxy/...`, `go test ./...`, `go vet ./...`, `bash -n scripts/setup.sh scripts/deinit.sh`, PlantUML validation, and `git diff --check` pass. |

The live smoke must inspect macOS system proxy settings before and after and prove they
are unchanged. It must not require disabling VLESS/OpenConnect unless the selected SSH
route itself is misconfigured; that route remains an independent transport prerequisite.

## Concrete Acceptance Criteria For Downstream Tasks

1. `ssh-proxy` is the sole product name and uses only new config/cache/log paths.
2. One daemon per selected active profile owns exactly one system SSH child and one
   in-process HTTP bridge.
3. `start` is atomic in SSH -> SOCKS5-ready -> HTTP-ready order.
4. `stop` is atomic in HTTP-closed -> SSH-stopped order.
5. `status` reports daemon, SSH, both endpoints, and protocol/readiness state.
6. CONNECT and ordinary HTTP both traverse SOCKS5 with hostname-preserving remote DNS.
7. Only exact `127.0.0.1` listeners are permitted; no global/system proxy mutation or
   TLS interception exists.
8. `run --` is generic, directly executes any child, and scopes proxy variables to that
   child while leaving the daemon under explicit lifecycle control.
9. Unit/integration tests, race tests, full Go tests/vet, shell checks, diagram checks,
   diff checks, and a dedicated-egress smoke provide the required evidence.

## Unresolved Product Decisions

None. All decisions needed by `TASK-260714-aeflct`, `TASK-260714-1y0y8v`, and
`TASK-260714-2gw4tw` are fixed above. Any future non-loopback listener, proxy
authentication, CONNECT destination ACL, automatic daemon leasing, HTTP/2 proxy
support, or TLS-inspecting behavior is explicitly out of scope and requires a new
tracked product decision.
