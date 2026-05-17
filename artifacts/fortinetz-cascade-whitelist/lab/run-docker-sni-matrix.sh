#!/bin/sh
set -eu

config="${1:?sing-box config path is required}"
out_base="${2:?output directory is required}"
image="${FORTINETZ_SNI_LAB_IMAGE:-fortinetz-sni-lab:local}"
docker_bin="${DOCKER:-docker}"
script_dir="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$out_base"

"$docker_bin" build \
  --build-arg SING_BOX_VERSION="${SING_BOX_VERSION:-1.13.3}" \
  -t "$image" \
  "$script_dir"

printf 'policy\tcurl_status\thttp_code\tipify\tsni\tallowed\n' > "$out_base/matrix.tsv"

for policy in strict_ru_sni popular_sni_allow sni_ip_match entry_ip_block; do
  policy_out="$out_base/$policy"
  rm -rf "$policy_out"
  mkdir -p "$policy_out"

  cid="$("$docker_bin" create \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    "$image" "$policy" /work/sing-box.json /out)"

  cleanup() {
    "$docker_bin" rm -f "$cid" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT INT TERM

  "$docker_bin" cp "$config" "$cid:/work/sing-box.json"
  "$docker_bin" start -a "$cid" > "$policy_out/docker-stdout.log" 2>&1 || true
  "$docker_bin" cp "$cid:/out/." "$policy_out/" >/dev/null 2>&1 || true
  cleanup
  trap - EXIT INT TERM

  curl_status="$(awk -F= '/^curl_status=/{print $2}' "$policy_out/result.env" 2>/dev/null || true)"
  http_code="$(awk -F= '/^http_code=/{print $2}' "$policy_out/result.env" 2>/dev/null || true)"
  ipify="$(awk -F= '/^ipify=/{print $2}' "$policy_out/result.env" 2>/dev/null || true)"
  sni="$(jq -r 'select(.event=="decision") | .sni' "$policy_out/gate.log" 2>/dev/null | tail -1 || true)"
  allowed="$(jq -r 'select(.event=="decision") | .allowed' "$policy_out/gate.log" 2>/dev/null | tail -1 || true)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$policy" "$curl_status" "$http_code" "$ipify" "$sni" "$allowed" >> "$out_base/matrix.tsv"
done

cat "$out_base/matrix.tsv"
