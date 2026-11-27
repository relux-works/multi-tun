# `TunWave` (`tun-wave`) — Archon & Sanctuary Launch Specification

- **Axiloom Project:** `TunWave` (`tun-wave`, `proj_cekgqm644n6agzx4q63hyyd5tu`)
- **Required Archon Profile:** `tech-lead` (from `https://github.com/relux-works/agentic-profiles`)
- **Supervisor:** `archon-sanctuary` (`/Users/alexis/.local/bin/archon-sanctuary`)
- **Environment Manager:** `archon` (`/Users/alexis/.local/bin/archon`)

## CRITICAL Tunnel Testing Safety (`work-mac` ONLY)
- **NEVER start, stop, or test VPN/TUN tunnels on this primary Mac (`m1max`)!**
- All live tunnel tests MUST run over SSH on **`work-mac` (`ssh work-mac`)**.
- **BEFORE touching any tunnel on `work-mac`**, terminate all running Claude and Codex sessions on `work-mac` first!

## 1. How to Launch a Supervised Lead or Worker Session (Codex or Claude)

Never launch raw `codex` or `claude` without its resolved Archon environment and `archon-sanctuary` supervision.

### Step A — Verify / Sync Profile Environment
```bash
/Users/alexis/.local/bin/archon profile sync tech-lead
```
Resolved managed homes:
- **Codex (`codex_cli`):** `CODEX_HOME=/Users/alexis/.curator/environments/tech-lead/codex_cli`
- **Claude (`claude_code`):** `CLAUDE_CONFIG_DIR=/Users/alexis/.curator/environments/tech-lead/claude_code`

### Step B — Start Session Under `archon-sanctuary` with `GoalChain` & `WakeHook`
```bash
EXEC_ID="tun-wave-lead"
SHOME="/Users/alexis/.curator/session-host"
mkdir -m 0700 -p "$SHOME/sessions/$EXEC_ID"

cat > "$SHOME/sessions/$EXEC_ID/plan.json" << 'PLAN'
{
  "binary": "/opt/homebrew/bin/codex",
  "args": ["exec", "--dangerously-bypass-approvals-and-sandbox", "<YOUR_TASK_PROMPT>"],
  "cwd": "/Users/alexis/src/multi-tun",
  "env": [
    "CODEX_HOME=/Users/alexis/.curator/environments/tech-lead/codex_cli",
    "ARCHON_PROFILE=tech-lead",
    "PATH=/Users/alexis/.local/bin:/Users/alexis/src/relux-works/axiloom-client/bin:/Users/alexis/src/relux-works/axiloom-configurator-client/bin:/opt/homebrew/bin:/usr/bin:/bin"
  ]
}
PLAN

/Users/alexis/.local/bin/archon-sanctuary start \
  --home "$SHOME" --execution "$EXEC_ID" --adapter json-fixture --input-state idle \
  --vendor openai --model gpt-5-codex --reasoning high \
  --workspace "/Users/alexis/src/multi-tun" --plan "$SHOME/sessions/$EXEC_ID/plan.json" &

# Attach WakeHook (wakes supervisor only when session + all spawned subagents are quiescent)
/Users/alexis/.local/bin/archon-sanctuary hooks add \
  --home "$SHOME" --execution "$EXEC_ID" --id "wake-supervisor" \
  --on "quiescent,goal_step,goal_completed,goal_stalled" \
  --notify-execution "cto"

# Attach Quiescence-Aware GoalChain (will NOT nudge while spawned subagents are running)
/Users/alexis/.local/bin/archon-sanctuary goal set \
  --home "$SHOME" --execution "$EXEC_ID" --grace-ms 1500 \
  --step "Step 1: Orient via axiloom guide --with-status and execute task" \
  --step "Step 2: Verify axiloom validate --strict (0/0)::axiloom validate --strict"
```

## 2. Profile Governance Rule
- **Do NOT create ad-hoc or duplicate profiles.** If a worker requires a new capability or profile change, request it from the CTO (`cto`) so `relux-works/agentic-profiles` remains a single clean taxonomy.
