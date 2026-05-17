#!/bin/sh
set -eu

policy="${1:?policy is required}"
config="${2:-/work/sing-box.json}"
out_dir="${3:-/out}"

mkdir -p "$out_dir"
rm -f "$out_dir/gate.log" "$out_dir/sing-box.log" "$out_dir/curl.log" "$out_dir/ipify.out"
chown -R gate:gate "$out_dir"
chmod 0777 "$out_dir"

explicit_gate=0
if jq -e '.outbounds[]? | select(.tag == "sni-gate" and .type == "socks")' "$config" >/dev/null 2>&1; then
  explicit_gate=1
fi

listen="0.0.0.0:18080"
gate_mode_args=""
if [ "$explicit_gate" = "1" ]; then
  listen="127.0.0.1:18080"
  gate_mode_args="--socks5"
fi

runuser -u gate -- python3 /usr/local/bin/sni-gate.py \
  --listen "$listen" \
  --policy "$policy" \
  --log "$out_dir/gate.log" \
  $gate_mode_args &
gate_pid="$!"

for _ in $(seq 1 50); do
  if ss -ltn sport = :18080 | grep -q 18080; then
    break
  fi
  sleep 0.1
done

if [ "$explicit_gate" = "0" ]; then
  iptables -t nat -F OUTPUT
  iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner 0 -j REDIRECT --to-ports 18080
fi
iptables -t nat -S OUTPUT > "$out_dir/iptables-nat-output.txt" 2>&1 || true
iptables -t nat -vL OUTPUT -n > "$out_dir/iptables-nat-before.txt" 2>&1 || true

sing-box run -c "$config" > "$out_dir/sing-box.log" 2>&1 &
singbox_pid="$!"

ps -eo pid,user,uid,args > "$out_dir/ps-after-singbox-start.txt"
ip route show table all > "$out_dir/ip-route-after-singbox-start.txt" 2>&1 || true
ip rule show > "$out_dir/ip-rule-after-singbox-start.txt" 2>&1 || true
iptables -t nat -S OUTPUT > "$out_dir/iptables-nat-output-after-singbox-start.txt" 2>&1 || true
iptables -t nat -vL OUTPUT -n > "$out_dir/iptables-nat-after-singbox-start.txt" 2>&1 || true

if grep -q '"listen_port"[[:space:]]*:[[:space:]]*1080' "$config"; then
  curl_args="--socks5-hostname 127.0.0.1:1080"
  for _ in $(seq 1 80); do
    if ss -ltn sport = :1080 | grep -q 1080; then
      break
    fi
    sleep 0.1
  done
else
  curl_args=""
  sleep 4
fi

set +e
http_code="$(runuser -u client -- curl -m 20 -sS $curl_args -o "$out_dir/ipify.out" -w "%{http_code}" https://api.ipify.org 2>"$out_dir/curl.log")"
curl_status="$?"
set -e

iptables -t nat -S OUTPUT > "$out_dir/iptables-nat-output-after-curl.txt" 2>&1 || true
iptables -t nat -vL OUTPUT -n > "$out_dir/iptables-nat-after-curl.txt" 2>&1 || true
ip route show table all > "$out_dir/ip-route-after-curl.txt" 2>&1 || true
ip rule show > "$out_dir/ip-rule-after-curl.txt" 2>&1 || true

kill "$singbox_pid" 2>/dev/null || true
kill "$gate_pid" 2>/dev/null || true
wait "$singbox_pid" 2>/dev/null || true
wait "$gate_pid" 2>/dev/null || true

printf 'policy=%s\ncurl_status=%s\nhttp_code=%s\n' "$policy" "$curl_status" "$http_code" > "$out_dir/result.env"
if [ -s "$out_dir/ipify.out" ]; then
  printf 'ipify=%s\n' "$(cat "$out_dir/ipify.out")" >> "$out_dir/result.env"
else
  printf 'ipify=\n' >> "$out_dir/result.env"
fi

cat "$out_dir/result.env"
