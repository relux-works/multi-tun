// Package diag provides read-only, dependency-injected diagnostics. A zero Deps
// performs no host I/O; absent collectors produce explicit unavailable results.
package diag

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"multi-tun/desktop/internal/core/failclosed"
	"multi-tun/desktop/internal/core/vpncore"
)

type VPNCoreHealth struct {
	Reachable            bool                              `json:"reachable"`
	Label                string                            `json:"label"`
	SocketPath           string                            `json:"socket_path"`
	DaemonPID            int                               `json:"daemon_pid"`
	ProtocolVersion      int                               `json:"protocol_version,omitempty"`
	Capabilities         []string                          `json:"capabilities,omitempty"`
	Compatibility        string                            `json:"compatibility,omitempty"`
	MaintenanceActive    bool                              `json:"maintenance_active"`
	ActiveRequests       []vpncore.RequestSnapshot         `json:"active_requests,omitempty"`
	QueuedRequests       []vpncore.RequestSnapshot         `json:"queued_requests,omitempty"`
	LastCompletedRequest *vpncore.CompletedRequestSnapshot `json:"last_completed_request,omitempty"`
	PinnedBins           []vpncore.PinnedBinaryStatus      `json:"pinned_bins,omitempty"`
	ToolDrift            []string                          `json:"tool_drift,omitempty"`
	Error                string                            `json:"error,omitempty"`
}
type TUNInterfaceInfo struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	Flags     string   `json:"flags"`
	Role      string   `json:"role"`
}
type GuardHealth struct {
	ConfigEnabled      bool     `json:"config_enabled"`
	Services           []string `json:"services"`
	TunnelInterface    string   `json:"tunnel_interface"`
	TunnelUp           bool     `json:"tunnel_up"`
	HelperEnabled      bool     `json:"helper_enabled"`
	PFEnabled          bool     `json:"pf_enabled"`
	AnchorLoaded       bool     `json:"anchor_loaded"`
	Enforcing          bool     `json:"enforcing"`
	Blocking           bool     `json:"blocking"`
	TableEntries       int      `json:"table_entries"`
	LiveTableEntries   int      `json:"live_table_entries"`
	TableMatches       bool     `json:"table_matches"`
	PhysicalInterfaces []string `json:"physical_interfaces"`
	LastError          string   `json:"last_error,omitempty"`
	LastRecovery       string   `json:"last_recovery,omitempty"`
	Error              string   `json:"error,omitempty"`
}
type SessionHealth struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	SessionID  string `json:"session_id,omitempty"`
	PID        int    `json:"pid,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Profile    string `json:"profile,omitempty"`
	LogPath    string `json:"log_path,omitempty"`
	Error      string `json:"error,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
}
type DNSSummary struct {
	PrimaryNameservers    []string         `json:"primary_nameservers"`
	SupplementalResolvers []ScutilResolver `json:"supplemental_resolvers,omitempty"`
	ScopedResolvers       []ScutilResolver `json:"scoped_resolvers"`
	EtcResolverFiles      []string         `json:"etc_resolver_files"`
	Error                 string           `json:"error,omitempty"`
}
type AuthHealth struct {
	Server  string `json:"server"`
	Mode    string `json:"mode"`
	Storage string `json:"storage"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
}
type DoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type DoctorReport struct {
	Timestamp  string             `json:"timestamp"`
	Verdict    string             `json:"verdict"`
	Healthy    bool               `json:"healthy"`
	Stack      []string           `json:"stack,omitempty"`
	VPNCore    VPNCoreHealth      `json:"vpn_core"`
	Interfaces []TUNInterfaceInfo `json:"interfaces"`
	Guard      GuardHealth        `json:"guard"`
	Sessions   []SessionHealth    `json:"sessions"`
	DNS        DNSSummary         `json:"dns"`
	Auth       []AuthHealth       `json:"auth"`
	Checks     []DoctorCheck      `json:"checks"`
}

// Configuration carries only diagnostic policy and redacted authentication
// metadata. Secret values must never cross this boundary.
type Configuration struct {
	Present        bool
	Error          string
	HelperRequired bool
	Stack          []string
	Policy         failclosed.Policy
	ConfigPath     string
	Auth           []AuthHealth
}
type Deps struct {
	Now           func() time.Time
	Configuration func(context.Context) Configuration
	VPNCore       func(context.Context) VPNCoreHealth
	Interfaces    func(context.Context) ([]TUNInterfaceInfo, error)
	Guard         func(context.Context) GuardHealth
	Sessions      func(context.Context) ([]SessionHealth, error)
	ScutilDNS     func(context.Context) (string, error)
	ResolverFiles func(context.Context) ([]string, error)
	RouteGet      func(context.Context, string) (string, error)
	ResolveIP     func(context.Context, string) ([]netip.Addr, error)
	ReadFile      func(string) ([]byte, error)
	HTTPClient    *http.Client
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			r = ' '
		}
		if !unicode.IsPrint(r) || unicode.IsControl(r) {
			continue
		}
		if n >= max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
func collect(ctx context.Context, d Deps) (DoctorReport, Configuration, ScutilDNSSnapshot) {
	r := DoctorReport{Timestamp: d.now().UTC().Format(time.RFC3339), Verdict: "ok", Healthy: true}
	c := Configuration{}
	if d.Configuration != nil {
		c = d.Configuration(ctx)
		if len(c.Stack) > 0 {
			r.Stack = append([]string(nil), c.Stack...)
		}
	}
	check := func(name, status, detail string) {
		r.Checks = append(r.Checks, DoctorCheck{name, status, clean(detail, 512)})
		if status == "fail" {
			r.Healthy = false
			r.Verdict = "unhealthy"
		}
	}
	if !c.Present {
		check("config", "warn", "missing")
	} else if c.Error != "" {
		check("config", "fail", c.Error)
	} else {
		check("config", "ok", "loaded")
	}
	if d.VPNCore != nil {
		r.VPNCore = d.VPNCore(ctx)
	} else {
		r.VPNCore.Error = "collector unavailable"
	}
	if !r.VPNCore.Reachable || r.VPNCore.Error != "" {
		status := "warn"
		if c.HelperRequired {
			status = "fail"
		}
		check("vpn-core", status, "unreachable: "+r.VPNCore.Error)
	} else {
		check("vpn-core", "ok", "reachable")
	}
	if len(r.VPNCore.ToolDrift) > 0 {
		check("tool drift", "warn", strings.Join(r.VPNCore.ToolDrift, ", "))
	}
	if d.Interfaces != nil {
		var err error
		r.Interfaces, err = d.Interfaces(ctx)
		if err != nil {
			check("interfaces", "warn", err.Error())
		}
	} else {
		check("interfaces", "warn", "collector unavailable")
	}
	if d.Sessions != nil {
		var err error
		r.Sessions, err = d.Sessions(ctx)
		if err != nil {
			check("sessions", "fail", err.Error())
		}
	} else {
		check("sessions", "warn", "collector unavailable")
	}
	for _, s := range r.Sessions {
		status := "ok"
		if s.State == "unknown" || s.State == "stale" || s.Error != "" {
			status = "fail"
		}
		check("session "+s.Name, status, s.State+" "+s.Error)
	}
	// Only interfaces attributable to a collected session are assigned its role.
	for i := range r.Interfaces {
		in := &r.Interfaces[i]
		in.Role = "system"
		for _, s := range r.Sessions {
			if s.State == "active" && s.Interface == in.Name {
				in.Role = "tun-wave"
				if s.Kind == "openconnect" {
					in.Role = "openconnect"
				}
			}
		}
	}
	if d.Guard != nil {
		r.Guard = d.Guard(ctx)
	} else {
		r.Guard.Error = "collector unavailable"
	}
	r.Guard.ConfigEnabled = c.Policy.Enabled
	r.Guard.TunnelInterface = c.Policy.TunnelInterface
	for _, s := range c.Policy.Services {
		r.Guard.Services = append(r.Guard.Services, s.Name)
	}
	for _, in := range r.Interfaces {
		if in.Name == c.Policy.TunnelInterface {
			r.Guard.TunnelUp = in.Up
		}
	}
	r.Guard.Blocking = r.Guard.Enforcing && !r.Guard.TunnelUp
	if c.Policy.Enabled && (!r.Guard.Enforcing || r.Guard.Error != "") {
		check("fail-closed", "fail", "configured guard is not enforcing: "+r.Guard.Error)
	} else {
		status := "ok"
		if r.Guard.Error != "" {
			status = "warn"
		}
		check("fail-closed", status, fmt.Sprintf("enabled=%t enforcing=%t %s", c.Policy.Enabled, r.Guard.Enforcing, r.Guard.Error))
	}
	var snap ScutilDNSSnapshot
	if d.ScutilDNS != nil {
		out, err := d.ScutilDNS(ctx)
		if err != nil {
			r.DNS.Error = err.Error()
		} else {
			snap = ParseScutilDNS(out)
			if len(snap.Resolvers) == 0 {
				r.DNS.Error = "no DNS resolvers reported"
			}
		}
	} else {
		r.DNS.Error = "collector unavailable"
	}
	if match := MatchResolverForHost(snap, ""); match != nil {
		r.DNS.PrimaryNameservers = match.Nameservers
	}
	for _, resolver := range snap.Resolvers {
		if resolver.Scoped {
			r.DNS.ScopedResolvers = append(r.DNS.ScopedResolvers, resolver)
		} else if resolver.Domain != "" {
			r.DNS.SupplementalResolvers = append(r.DNS.SupplementalResolvers, resolver)
		}
	}
	if d.ResolverFiles != nil {
		files, err := d.ResolverFiles(ctx)
		r.DNS.EtcResolverFiles = files
		if err != nil {
			r.DNS.Error = strings.TrimSpace(r.DNS.Error + " " + err.Error())
		}
	}
	if r.DNS.Error != "" {
		check("dns", "warn", r.DNS.Error)
	} else {
		check("dns", "ok", strings.Join(r.DNS.PrimaryNameservers, ", "))
	}
	r.Auth = c.Auth
	for _, a := range r.Auth {
		status := a.Status
		if status == "error" {
			status = "fail"
		}
		check("auth "+a.Server, status, a.Detail)
	}
	return r, c, snap
}
func Doctor(ctx context.Context, d Deps) DoctorReport { r, _, _ := collect(ctx, d); return r }
func FormatDoctorText(r DoctorReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Doctor: %s (%s)\n", clean(r.Verdict, 40), clean(r.Timestamp, 80))
	if len(r.Stack) > 0 {
		fmt.Fprintf(&b, "Stack: %s\n", clean(strings.Join(r.Stack, ", "), 256))
	}
	fmt.Fprintf(&b, "vpn-core: reachable=%t pid=%d proto=%d caps=%s label=%s socket=%s compatibility=%s maintenance=%t active=%d queued=%d\n", r.VPNCore.Reachable, r.VPNCore.DaemonPID, r.VPNCore.ProtocolVersion, clean(strings.Join(r.VPNCore.Capabilities, ","), 120), clean(r.VPNCore.Label, 160), clean(r.VPNCore.SocketPath, 256), clean(r.VPNCore.Compatibility, 80), r.VPNCore.MaintenanceActive, len(r.VPNCore.ActiveRequests), len(r.VPNCore.QueuedRequests))
	if r.VPNCore.LastCompletedRequest != nil {
		last := r.VPNCore.LastCompletedRequest
		fmt.Fprintf(&b, "  last request: %s %s (%dms)\n", clean(last.Action, 80), clean(last.Outcome, 80), last.DurationMillis)
	}
	for _, in := range r.Interfaces {
		fmt.Fprintf(&b, "TUN %-10s up=%t mtu=%d role=%s flags=%s addresses=%s\n", clean(in.Name, 32), in.Up, in.MTU, clean(in.Role, 32), clean(in.Flags, 100), clean(strings.Join(in.Addresses, ", "), 512))
	}
	fmt.Fprintf(&b, "PF guard: configured=%t helper=%t pf=%t anchor=%t enforcing=%t blocking=%t table=%d live=%d matches=%t physical=%s\n", r.Guard.ConfigEnabled, r.Guard.HelperEnabled, r.Guard.PFEnabled, r.Guard.AnchorLoaded, r.Guard.Enforcing, r.Guard.Blocking, r.Guard.TableEntries, r.Guard.LiveTableEntries, r.Guard.TableMatches, clean(strings.Join(r.Guard.PhysicalInterfaces, ","), 160))
	fmt.Fprintf(&b, "  services=%s tunnel=%s up=%t error=%s recovery=%s\n", clean(strings.Join(r.Guard.Services, ","), 256), clean(r.Guard.TunnelInterface, 32), r.Guard.TunnelUp, clean(r.Guard.Error+" "+r.Guard.LastError, 512), clean(r.Guard.LastRecovery, 256))
	for _, s := range r.Sessions {
		fmt.Fprintf(&b, "Session %s: %s %s id=%s pid=%d interface=%s profile=%s log=%s\n", clean(s.Name, 80), clean(s.Kind, 32), clean(s.State, 20), clean(s.SessionID, 80), s.PID, clean(s.Interface, 32), clean(s.Profile, 160), clean(s.LogPath, 256))
	}
	fmt.Fprintf(&b, "DNS: primary=%s supplemental=%d scoped=%d resolver files=%s\n", clean(strings.Join(r.DNS.PrimaryNameservers, ", "), 256), len(r.DNS.SupplementalResolvers), len(r.DNS.ScopedResolvers), clean(strings.Join(r.DNS.EtcResolverFiles, ", "), 512))
	for _, a := range r.Auth {
		fmt.Fprintf(&b, "Auth %s: mode=%s storage=%s status=%s %s\n", clean(a.Server, 80), clean(a.Mode, 40), clean(a.Storage, 40), clean(a.Status, 20), clean(a.Detail, 256))
	}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "%-5s %-22s %s\n", clean(c.Status, 8), clean(c.Name, 80), clean(c.Detail, 512))
	}
	return b.String()
}
