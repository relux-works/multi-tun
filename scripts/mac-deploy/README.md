# macOS Deploy Script

`deploy-multi-tun.sh` installs or updates `multi-tun` on another Mac from git.
It is safe to commit because it contains no tunnel credentials.

Do not commit live tunnel configs. The local config bundle paths below are
ignored by git as a guard rail:

- `scripts/mac-deploy/config/`
- `scripts/mac-deploy/configs/`

Portable bundle layout:

```text
config/
  vless-tun/config.json
  openconnect-tun/config.json
deploy-multi-tun.sh
README.md
SHA256SUMS
```

Run from a bundle:

```bash
./deploy-multi-tun.sh --config-bundle ./config
```

Run from a checkout:

```bash
scripts/mac-deploy/deploy-multi-tun.sh --config-bundle /path/to/config
```

The deploy path runs the checkout's `scripts/setup.sh`. On host-native macOS
installs, that setup step performs the Homebrew OpenConnect launch check after
all formula installs and repairs a stale Homebrew linkage with a targeted
`brew reinstall openconnect` only when `openconnect --version` cannot launch.
It does not alter non-Homebrew OpenConnect installations or cross-build mode.

The script accepts `__HOME__`, `__XDG_CONFIG_HOME__`, and
`__XDG_CACHE_HOME__` placeholders in config files and expands them on the target
Mac before installation. Existing target config files are backed up with a UTC
timestamp before replacement.

The old `~/.config/multi-tun` config directory is legacy. By default the deploy
script archives it to `~/.config/multi-tun.legacy-bak-<timestamp>` so the active
target Mac config surface contains only:

- `~/.config/vless-tun/config.json`
- `~/.config/openconnect-tun/config.json`

OpenConnect auth values are intentionally not exported. The copied config keeps
Keychain account names; seed the actual values on the target Mac with
`security add-generic-password -U`.
