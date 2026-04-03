## Status
development

## Assigned To
codex

## Created
2026-04-02T14:24:15Z

## Last Update
2026-04-03T15:22:50Z

## Blocked By
- (none)

## Blocks
- TASK-260402-qiah94

## Checklist
- [x] Inventory required CLI/system tools for vless-tun, openconnect-tun, vpn-auth, CSD, and TOTP auth flows
- [x] Detect missing prerequisites locally and install them through the supported setup path
- [x] Install the vpn-config skill into the global runtime and fan out repo-local symlinks from that global install
- [ ] Remove stale resource copies and degitize leftover skill artifacts so only the working global runtime scheme remains

## Notes
This task covers global vpn-config skill packaging/setup, prerequisite verification, missing tool installation, TOTP-related auth prerequisites, global install, repo-local symlink fan-out, and cleanup of stale degitized/resource leftovers.
This task also needs to support the new agent-facing setup flows: when the agent says it can run openconnect-tun setup or vless-tun setup, the global vpn-config skill/runtime must already have the required toolchain, TOTP/auth prerequisites, and global install/symlink layout in place for those commands to work end-to-end.
Updated scripts/setup.sh to verify/install stable prerequisites (ripgrep, pipx, openconnect, oath-toolkit, python3, vpn-slice), keep vpn-auth as an explicit prerequisite warning because its install source is still unresolved, install the vpn-config skill into the global runtime, and fan out repo-local symlinks from that global install instead of pointing local shims directly at the repo skill directory.
Added scripts/deinit.sh as the paired uninstall path for multi-tun. It removes managed global/local skill links and ~/.local/bin symlinks by default, and only purges config/cache/keychain/build artifacts behind explicit --purge-* flags.
Added shell helper script for Google Auth export TOTP extraction and now updating vpn-config skill text to include concrete example command and expected output for agents.
Updated vpn-config skill with a concrete shell example and expected output for google-auth-export-secret.sh so agents can answer with an exact command/result instead of only describing the decode steps.
Follow-up: vpn-auth cannot stay a mere warning because openconnect-tun start defaults to --auth aggregate, which currently depends on vpn-auth. Audit the old vpn-auth source and wire a supported build/install path into setup.
Bundled the legacy Swift WebKit helper as cmd/vpn-auth, taught scripts/setup.sh to install its TOTP prerequisite totp-cli, build the package, stage the repo-local vpn-auth binary, and link it into ~/.local/bin as a managed multi-tun product binary. scripts/deinit.sh now tears down the managed vpn-auth link and build artifact alongside the rest of the toolchain. Verification: swift build -c release --package-path cmd/vpn-auth, go test ./..., ./scripts/setup.sh, vpn-auth --version, and ./scripts/deinit.sh --dry-run all passed.
Follow-up from live install review: setup still misses sing-box even though vless-tun start depends on it. Add Homebrew check/install for sing-box to the shipped setup flow and re-verify end-to-end prerequisites.
Closed the remaining live gap in shipped prerequisites: scripts/setup.sh now also ensures sing-box, because vless-tun start depends on it. Re-verified with command -v sing-box, sing-box version, and a fresh ./scripts/setup.sh run after the change.

## Precondition Resources
(none)

## Outcome Resources
(none)
