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
	Label          string
	PlistPath      string
	SocketPath     string
	Reachable      bool
	DaemonPID      int
	Compatibility  string
	HelperSnapshot *HelperSnapshot
}

// RequestSnapshot is deliberately limited to non-sensitive request metadata.
// It never carries command arguments, stdin, log paths, endpoints, credentials,
// target PIDs, or signal values.
type RequestSnapshot struct {
	Action    string `json:"action"`
	AgeMillis int64  `json:"age_ms"`
}

// CompletedRequestSnapshot adds only outcome and timing metadata to the same
// redacted action used by active and queued request snapshots.
type CompletedRequestSnapshot struct {
	Action         string `json:"action"`
	Outcome        string `json:"outcome"`
	DurationMillis int64  `json:"duration_ms"`
	AgeMillis      int64  `json:"age_ms"`
}

// HelperSnapshot is the optional, backward-compatible request-health payload
// returned by the existing ping response.
type HelperSnapshot struct {
	ActiveRequests       []RequestSnapshot         `json:"active_requests"`
	QueuedRequests       []RequestSnapshot         `json:"queued_requests"`
	LastCompletedRequest *CompletedRequestSnapshot `json:"last_completed_request,omitempty"`
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
