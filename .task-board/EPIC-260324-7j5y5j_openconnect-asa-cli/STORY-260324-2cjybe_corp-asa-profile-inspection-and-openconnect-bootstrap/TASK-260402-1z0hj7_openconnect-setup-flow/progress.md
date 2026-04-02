## Status
to-review

## Assigned To
codex

## Created
2026-04-02T14:24:15Z

## Last Update
2026-04-02T19:02:28Z

## Blocked By
- (none)

## Blocks
- TASK-260402-qiah94

## Checklist
- [x] Add openconnect-tun setup as the dedicated bootstrap entrypoint
- [x] Ask for the target VPN name before scaffolding the config
- [x] Seed default full-mode config with no bypasses and placeholder auth wiring in Keychain/config
- [x] Return the generated config path/link after setup so the user can inspect it

## Notes
Target UX from the user: tell the agent to set up openconnect, get asked for the VPN name, have the agent run openconnect-tun setup, scaffold the config with default full mode and no bypasses, stub everything needed with placeholders in Keychain and config, then hand back the config path for review.
Implemented openconnect-tun setup. It accepts a user-facing VPN name, resolves server_url from local AnyConnect XML when needed, scaffolds a full-mode/no-bypass config, seeds placeholder keychain accounts without clobbering existing secrets unless --force is used, and prints the resulting config path.
Follow-up: current keychain items still look identical from the outside because they all inherit the default multi-tun label. Refresh the setup path so username/password/totp items get distinct external labels/kinds/comments in Keychain Access without clobbering existing secret values.
Keychain metadata follow-up completed: openconnect-tun setup now rewrites or seeds username/password/totp items with distinct external labels, kinds, and comments in Keychain Access while preserving existing secret values unless --force is used.
Follow-up: keychain naming/labels should key off server_url rather than profile name, because the credentials are scoped to the target VPN endpoint. Update setup scaffolding and labels to derive the default account base from server_url and treat profile as secondary display context.
Default keychain account derivation now keys off server_url rather than profile name. setup scaffolding uses a normalized server-based account base (for example vpn-gw2-corp-example-outside/password), while Keychain labels show the server_url and keep the profile as secondary comment context.
Retested from clean reinstall by suffixing live configs, running deinit/setup.sh, and executing openconnect-tun setup. Fresh scaffold now lands as full mode without bypasses and seeds server-based keychain accounts.
Investigated fresh hostscan failure after clean reinstall. The live log already contained TOKEN_SUCCESS, so the failure came from our in-memory hostscan output check, not from Cisco CSD itself. Patched performHostScan to use a synchronized capture buffer for concurrent stdout/stderr and added regression tests around concurrent writes and fake csd-post success output.

## Precondition Resources
(none)

## Outcome Resources
(none)
