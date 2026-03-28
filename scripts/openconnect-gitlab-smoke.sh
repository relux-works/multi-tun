#!/usr/bin/env bash
set -euo pipefail

OPENCONNECT_WAIT_SECONDS="${OPENCONNECT_WAIT_SECONDS:-15}"
OPENCONNECT_STOP_TIMEOUT="${OPENCONNECT_STOP_TIMEOUT:-15s}"
GITLAB_URL="${GITLAB_URL:-https://gitlab.services.corp.example/}"
GITLAB_CURL_TIMEOUT="${GITLAB_CURL_TIMEOUT:-10}"
STATUS_POLL_INTERVAL="${STATUS_POLL_INTERVAL:-1}"

run_pid=""
sudo_keepalive_pid=""
run_timed_out=0
gitlab_check_ran=0
gitlab_check_passed=0

log() {
  printf '[openconnect-gitlab-smoke] %s\n' "$*"
}

cleanup_run_process() {
  if [[ -n "${run_pid}" ]] && kill -0 "${run_pid}" 2>/dev/null; then
    log "stopping foreground openconnect-tun run pid=${run_pid}"
    kill "${run_pid}" 2>/dev/null || true
    wait "${run_pid}" 2>/dev/null || true
  fi
  run_pid=""
}

stop_sudo_keepalive() {
  if [[ -n "${sudo_keepalive_pid}" ]] && kill -0 "${sudo_keepalive_pid}" 2>/dev/null; then
    kill "${sudo_keepalive_pid}" 2>/dev/null || true
    wait "${sudo_keepalive_pid}" 2>/dev/null || true
  fi
  sudo_keepalive_pid=""
}

on_exit() {
  stop_sudo_keepalive
  cleanup_run_process
}

start_sudo_keepalive() {
  log "warming sudo timestamp"
  sudo -v

  (
    while true; do
      sudo -n true >/dev/null 2>&1 || exit 0
      sleep 30
    done
  ) &
  sudo_keepalive_pid=$!
}

force_drop_openconnect() {
  log "force-dropping openconnect"
  sudo -n pkill -KILL -x openconnect 2>/dev/null || true
  sleep 1
  openconnect-tun stop --timeout 1s >/dev/null 2>&1 || true
}

wait_for_openconnect_connection() {
  local deadline
  deadline=$((SECONDS + OPENCONNECT_WAIT_SECONDS))

  while (( SECONDS < deadline )); do
    if [[ -n "${run_pid}" ]] && ! kill -0 "${run_pid}" 2>/dev/null; then
      wait "${run_pid}" || true
      return 1
    fi

    if openconnect-tun status 2>/dev/null | rg -q '^session: active$'; then
      return 0
    fi

    sleep "${STATUS_POLL_INTERVAL}"
  done

  return 1
}

check_gitlab() {
  local body
  body="$(curl -fsSL --max-time "${GITLAB_CURL_TIMEOUT}" "${GITLAB_URL}")" || return 1

  if [[ "${body}" == *GitLab* ]] || [[ "${body}" == *gitlab* ]]; then
    return 0
  fi

  return 1
}

main() {
  trap on_exit EXIT

  start_sudo_keepalive

  log "stopping vless-tun"
  vless-tun stop || true

  log "starting openconnect-tun run"
  openconnect-tun run &
  run_pid=$!

  log "waiting up to ${OPENCONNECT_WAIT_SECONDS}s for openconnect session to become active"
  if wait_for_openconnect_connection; then
    gitlab_check_ran=1
    log "openconnect session is active; checking ${GITLAB_URL}"
    if check_gitlab; then
      gitlab_check_passed=1
      log "gitlab check passed"
    else
      log "gitlab check failed"
    fi
  else
    run_timed_out=1
    log "openconnect did not become active within ${OPENCONNECT_WAIT_SECONDS}s; skipping gitlab check"
    cleanup_run_process
  fi

  log "stopping openconnect-tun"
  if ! openconnect-tun stop --timeout "${OPENCONNECT_STOP_TIMEOUT}"; then
    force_drop_openconnect
  fi
  cleanup_run_process

  log "starting vless-tun run"
  vless-tun run

  if (( run_timed_out )); then
    log "result: openconnect startup timeout"
    return 1
  fi
  if (( gitlab_check_ran == 0 )); then
    log "result: gitlab check skipped"
    return 1
  fi
  if (( gitlab_check_passed == 0 )); then
    log "result: gitlab check failed"
    return 1
  fi

  log "result: success"
}

main "$@"
