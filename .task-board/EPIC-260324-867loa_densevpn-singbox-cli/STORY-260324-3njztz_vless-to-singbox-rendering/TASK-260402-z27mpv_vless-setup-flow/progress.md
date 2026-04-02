## Status
to-review

## Assigned To
codex

## Created
2026-04-02T14:24:15Z

## Last Update
2026-04-02T15:59:24Z

## Blocked By
- (none)

## Blocks
- TASK-260402-qiah94

## Checklist
- [x] Add vless-tun setup as the dedicated bootstrap entrypoint
- [x] Mirror the agent-facing setup UX used for openconnect where it still applies
- [x] Scaffold the default config without introducing Keychain placeholder writes unless requirements change later
- [x] Return the generated config path/link after setup so the user can inspect it

## Notes
Target UX from the user: tell the agent to set up vless, have the agent run vless-tun setup, scaffold the default config, and return the config path for review. Current assumption: no Keychain placeholder writes are needed for vless setup.
Implemented vless-tun setup as the preferred scaffold entrypoint. It writes the preferred source/default/network/routing/dns/logging/artifacts schema, supports direct or proxy source URLs, optional default profile selector, and prints the config path for review.
Retested from clean reinstall by suffixing live configs, running deinit/setup.sh, and executing vless-tun setup. Fresh scaffold writes preferred schema, but current default network.mode came out system_proxy; verify whether setup happy path should default to tun instead.
Adjusted vless-tun scaffold default from system_proxy to tun so the default generated config matches the intended normal tunnel happy path on macOS. system_proxy remains supported as an explicit opt-in mode only.

## Precondition Resources
(none)

## Outcome Resources
(none)
