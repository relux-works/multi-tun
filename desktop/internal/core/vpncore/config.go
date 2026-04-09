package vpncore

const (
	defaultServiceLabel      = "works.relux.vpn-core"
	defaultServicePlistPath  = "/Library/LaunchDaemons/works.relux.vpn-core.plist"
	defaultServiceSocketPath = "/var/run/works.relux.vpn-core.sock"

	legacyOpenConnectHelperLabel      = "works.relux.openconnect-tun-helper"
	legacyOpenConnectHelperPlistPath  = "/Library/LaunchDaemons/works.relux.openconnect-tun-helper.plist"
	legacyOpenConnectHelperSocketPath = "/var/run/works.relux.openconnect-tun-helper.sock"

	CompatibilityLegacyOpenConnectHelper = "legacy-openconnect-helper"
)

type ServiceConfig struct {
	Label      string
	PlistPath  string
	SocketPath string
}

type ServiceStatus struct {
	Label         string
	PlistPath     string
	SocketPath    string
	Reachable     bool
	DaemonPID     int
	Compatibility string
}

func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		Label:      defaultServiceLabel,
		PlistPath:  defaultServicePlistPath,
		SocketPath: defaultServiceSocketPath,
	}
}

func LegacyOpenConnectHelperConfig() ServiceConfig {
	return ServiceConfig{
		Label:      legacyOpenConnectHelperLabel,
		PlistPath:  legacyOpenConnectHelperPlistPath,
		SocketPath: legacyOpenConnectHelperSocketPath,
	}
}

type compatibilityConfig struct {
	ServiceConfig
	Compatibility string
}

var compatibilityServiceConfigsVPNCore = func(cfg ServiceConfig) []compatibilityConfig {
	if !sameServiceConfig(cfg, DefaultServiceConfig()) {
		return nil
	}
	return []compatibilityConfig{
		{
			ServiceConfig: LegacyOpenConnectHelperConfig(),
			Compatibility: CompatibilityLegacyOpenConnectHelper,
		},
	}
}

func sameServiceConfig(left, right ServiceConfig) bool {
	return left.Label == right.Label &&
		left.PlistPath == right.PlistPath &&
		left.SocketPath == right.SocketPath
}
