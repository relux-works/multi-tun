package cli

import (
	"errors"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/singbox"
)

// errLiveLaunchModeProbe marks a test that reached the real launch-mode resolver, whose auto mode
// probes the live vpn-core helper socket. Package init installs it before any test runs; tests that
// need a mode stub resolveLaunchModeCLI themselves.
var errLiveLaunchModeProbe = errors.New("test reached the live launch-mode resolver")

func init() {
	resolveLaunchModeCLI = func(string, config.PrivilegedLaunchConfig) (string, error) {
		return "", errLiveLaunchModeProbe
	}
	validateHelperConfigCLI = func([]byte) error { return errors.New("test reached the default helper validator") }
	// The default reads the work VPN's overlay DNS from the host; tests get a fixed empty result.
	resolveRenderOptionsCLI = func(string) singbox.RenderOptions { return singbox.RenderOptions{} }
}
