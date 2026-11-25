# sing-box TUN lab

An isolated A/B bench for the sing-box TUN stacks (`system`, `gvisor`, `mixed`) that the
`vless-tun` helper path uses. It runs entirely inside one Colima VM: a TLS server and a
client behind a sing-box TUN with a `direct` outbound. No VPN node, subscription or key is
involved, and the host's live tunnels are not touched.

What it measures:

- long TLS 1.3 streams (certificate verified against a throwaway lab CA) whose every byte is
  checked against a deterministic pattern (`pattern/`), so corruption is caught even when TLS
  would only report `bad record MAC`;
- concurrent connection churn through the TUN, counting connect timeouts and bad replies.

## Layout

| Path | Tracked | Purpose |
| --- | --- | --- |
| `Dockerfile` | yes | Alpine image with sing-box (release tarball verified by SHA-256) and the lab binaries |
| `singbox-{system,gvisor,mixed}.json` | yes | TUN configs that differ only in `stack` |
| `cmd/labserver`, `cmd/labclient`, `pattern/` | yes | Go server, client and stream pattern (with tests) |
| `.runtime/` | no (`.gitignore`) | built binaries, downloaded tarball, VM mount, run output |

## Run

```bash
cd lab/singbox-tun
R=$PWD/.runtime
mkdir -p "$R/bin" "$R/dl" "$R/out"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$R/bin/labserver" ./cmd/labserver
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$R/bin/labclient" ./cmd/labclient
F=sing-box-1.13.3-linux-arm64-musl.tar.gz
curl -sSLf -o "$R/dl/$F" "https://github.com/SagerNet/sing-box/releases/download/v1.13.3/$F"

# Own Colima profile; mount only the output folder, no inotify forwarding, no context switch.
colima start --profile multi-tun --activate=false --mount-inotify=false \
  --mount "$R/out:w" --cpus 4 --memory 4
export DOCKER_CONTEXT=colima-multi-tun
docker build -t sblab:1.13.3 .
# Start from a clean state every run: no leftover server or network from an earlier run.
docker rm -f sblab-srv >/dev/null 2>&1; docker network rm sblab >/dev/null 2>&1
docker network create --subnet 10.77.0.0/24 sblab
docker run -d --name sblab-srv --network sblab --ip 10.77.0.10 --cap-add NET_ADMIN \
  -v "$R/out:/out" sblab:1.13.3 \
  sh -ec 'ip addr add 203.0.113.10/32 dev lo; exec labserver --ca-out /out/ca.pem'

STACK=system   # or gvisor, mixed
# Every step fails the run: a config sing-box rejects, sing-box exiting, a missing tun0, a bench
# route that does not use tun0, or sing-box dying during the run. Only then is the summary valid.
docker run --rm --network sblab --privileged --device /dev/net/tun -v "$R/out:/out" sblab:1.13.3 sh -ec "
  sing-box check -c /etc/lab/singbox-$STACK.json
  sing-box run -c /etc/lab/singbox-$STACK.json > /out/singbox-$STACK.log 2>&1 & SB=\$!
  for i in \$(seq 1 20); do ip link show tun0 >/dev/null 2>&1 && break; kill -0 \$SB 2>/dev/null || { echo 'sing-box exited' >&2; exit 3; }; sleep 0.5; done
  ip link show tun0 >/dev/null 2>&1 || { echo 'tun0 did not appear' >&2; exit 4; }
  ip route add 203.0.113.0/24 dev tun0 metric 10
  ip route add 203.0.113.0/24 via 10.77.0.10 dev eth0 metric 20
  ip route get 203.0.113.10 | grep -q 'dev tun0' || { echo 'bench route does not use tun0' >&2; exit 5; }
  labclient --label tun-$STACK --streams 8 --duration 90s --churn 32
  kill -0 \$SB 2>/dev/null || { echo 'sing-box died during the run' >&2; exit 6; }"
```

The client prints one JSON summary and exits 1 when any stream failed or mismatched. The
sing-box `direct` outbound is bound to `eth0`, so it reaches the server over the metric-20
route while the client's own traffic takes the TUN route.

Clean up when done: `docker rm -f sblab-srv; docker network rm sblab; colima stop --profile multi-tun`.

Negative control: `STACK=missing` (no such config) must end with a non-zero exit from `sing-box
check` and print no client summary.
