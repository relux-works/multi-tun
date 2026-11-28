package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/diag"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
)

// This single factory is replaced by CLI tests. Building dependencies does not
// inspect the host; all reads occur through the callbacks when requested.
var diagnosticsDepsCLI = newDiagnosticsDeps

func newDiagnosticsDeps(path string, timeout time.Duration) diag.Deps {
	var cfg config.ProjectConfig
	var loaded bool
	var cfgErr error
	load := func() {
		if !loaded {
			cfg, cfgErr = config.Load(path)
			loaded = true
		}
	}
	d := diag.Deps{Now: time.Now, ReadFile: os.ReadFile, HTTPClient: diag.NewHTTPClient(timeout)}
	d.Configuration = func(context.Context) diag.Configuration {
		load()
		c := diag.Configuration{Present: cfgErr == nil}
		if cfgErr != nil {
			if !errors.Is(cfgErr, os.ErrNotExist) {
				c.Present = true
				c.Error = "configuration could not be loaded or validated"
			}
			return c
		}
		c.HelperRequired = cfg.LaunchOrDefault().Mode == config.LaunchModeHelper || cfg.LaunchOrDefault().Mode == config.LaunchModeAuto
		c.Stack = append([]string(nil), cfg.Stack...)
		policy, err := cfg.FailClosedPolicy()
		c.Policy = policy
		if err != nil {
			c.Error = "invalid fail_closed policy"
		}
		effective, _, err := cfg.Effective(config.SelectionOptions{AllowMissingProfile: true})
		if err == nil && effective.EngineType() != config.EngineOpenConnect {
			c.ConfigPath = effective.SingboxConfigPath()
		} else {
			c.ConfigPath = resolveDiagnosticSingBoxConfigPath(cfg)
		}
		if len(cfg.Servers) == 0 {
			c.Auth = append(c.Auth, diagnosticAuth("default", cfg))
		} else {
			names := make([]string, 0, len(cfg.Servers))
			for name := range cfg.Servers {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				e, _, err := cfg.Effective(config.SelectionOptions{Server: name, AllowMissingProfile: true})
				if err != nil {
					c.Auth = append(c.Auth, diag.AuthHealth{Server: name, Storage: "missing", Status: "error", Detail: "server configuration unavailable"})
					continue
				}
				c.Auth = append(c.Auth, diagnosticAuth(name, e))
			}
		}
		return c
	}
	d.VPNCore = func(context.Context) diag.VPNCoreHealth {
		svc := vpncore.DefaultServiceConfig()
		s, err := vpncore.InspectService(svc)
		h := diag.VPNCoreHealth{
			Reachable:       s.Reachable,
			Label:           s.Label,
			SocketPath:      s.SocketPath,
			DaemonPID:       s.DaemonPID,
			ProtocolVersion: s.ProtocolVersion,
			Capabilities:    append([]string(nil), s.Capabilities...),
			Compatibility:   s.Compatibility,
		}
		if err != nil {
			h.Error = err.Error()
		}
		if s.MaintenanceDrain != nil {
			h.MaintenanceActive = s.MaintenanceDrain.Active
		}
		if s.HelperSnapshot != nil {
			h.ActiveRequests = s.HelperSnapshot.ActiveRequests
			h.QueuedRequests = s.HelperSnapshot.QueuedRequests
			h.LastCompletedRequest = s.HelperSnapshot.LastCompletedRequest
		}
		if s.Reachable && s.ProtocolVersion >= 2 {
			if pins, pinErr := vpncore.QueryBinPins(svc, false); pinErr == nil {
				h.PinnedBins = pins
			}
		}
		drift, e := vpncore.ToolDrift(svc)
		h.ToolDrift = drift
		if e != nil {
			h.ToolDrift = append(h.ToolDrift, "tool manifest could not be inspected")
		}
		return h
	}
	d.Interfaces = func(context.Context) ([]diag.TUNInterfaceInfo, error) {
		ifs, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		out := []diag.TUNInterfaceInfo{}
		for _, in := range ifs {
			if !strings.HasPrefix(in.Name, "utun") && !strings.HasPrefix(in.Name, "tun") {
				continue
			}
			addrs, e := in.Addrs()
			if e != nil {
				return out, e
			}
			item := diag.TUNInterfaceInfo{Name: in.Name, Up: in.Flags&net.FlagUp != 0, MTU: in.MTU, Flags: in.Flags.String(), Role: "system"}
			for _, a := range addrs {
				item.Addresses = append(item.Addresses, a.String())
			}
			out = append(out, item)
		}
		return out, nil
	}
	d.Guard = func(context.Context) diag.GuardHealth {
		s, err := vpncore.FailClosedState(vpncore.DefaultServiceConfig())
		g := diag.GuardHealth{HelperEnabled: s.Enabled, PFEnabled: s.PFEnabled, AnchorLoaded: s.AnchorLoaded, Enforcing: s.Enforcing, TableEntries: s.TableEntries, LiveTableEntries: s.LiveTableEntries, TableMatches: s.TableMatches, PhysicalInterfaces: s.Interfaces, LastError: s.LastError, LastRecovery: s.LastRecovery, Error: s.LiveError}
		if err != nil {
			g.Error = err.Error()
		}
		return g
	}
	d.Sessions = func(context.Context) ([]diag.SessionHealth, error) {
		load()
		return diagnosticSessions(cfg, cfgErr == nil)
	}
	d.ScutilDNS = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").CombinedOutput()
		return string(out), err
	}
	d.RouteGet = func(ctx context.Context, ip string) (string, error) {
		args := []string{"-n", "get", ip}
		if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil && addr.Is6() {
			args = []string{"-n", "get", "-inet6", addr.String()}
		}
		out, err := exec.CommandContext(ctx, "/sbin/route", args...).CombinedOutput()
		return string(out), err
	}
	d.ResolveIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	d.ResolverFiles = func(context.Context) ([]string, error) {
		entries, err := os.ReadDir("/etc/resolver")
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		var paths []string
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, filepath.Join("/etc/resolver", e.Name()))
			}
		}
		return paths, err
	}
	return d
}

func resolveDiagnosticSingBoxConfigPath(cfg config.ProjectConfig) string {
	for _, selector := range cfg.Stack {
		serverName, profileName, _ := strings.Cut(selector, "/")
		srv, ok := cfg.Servers[serverName]
		if !ok || isOpenConnectServerCLI(srv) {
			continue
		}
		if eff, _, err := cfg.Effective(config.SelectionOptions{Server: serverName, Profile: profileName, AllowMissingProfile: true}); err == nil && eff.SingboxConfigPath() != "" {
			return eff.SingboxConfigPath()
		}
	}
	names := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if isOpenConnectServerCLI(cfg.Servers[name]) {
			continue
		}
		if eff, _, err := cfg.Effective(config.SelectionOptions{Server: name, AllowMissingProfile: true}); err == nil && eff.SingboxConfigPath() != "" {
			return eff.SingboxConfigPath()
		}
	}
	return cfg.SingboxConfigPath()
}

// Authentication diagnostics inspect only metadata, never credential contents,
// keychain values, subscription URLs or headers.
func diagnosticAuth(name string, cfg config.ProjectConfig) diag.AuthHealth {
	if cfg.SourceMode() == config.SourceModeOpenConnect || cfg.EngineType() == config.EngineOpenConnect {
		a := diag.AuthHealth{Server: name, Mode: config.SourceModeOpenConnect, Storage: "interactive", Status: "ok", Detail: "openconnect interactive/browser authentication configured"}
		if cfg.OpenConnect != nil && cfg.OpenConnect.Auth != nil {
			ocAuth := cfg.OpenConnect.Auth
			if ocAuth.UsernameKeychainAccount != "" || ocAuth.PasswordKeychainAccount != "" || ocAuth.TOTPKeychainAccount != "" ||
				(ocAuth.SecondFactor != nil && ocAuth.SecondFactor.TOTPKeychainAccount != "") {
				a.Storage = "keychain"
				a.Detail = "openconnect keychain references configured; secrets not read"
			}
		}
		return a
	}
	a := diag.AuthHealth{Server: name, Mode: cfg.SourceMode(), Storage: "missing", Status: "error", Detail: "no authentication storage configured"}
	if auth := cfg.Source.Auth; auth != nil {
		switch auth.Mode {
		case "keychain":
			a.Storage = "keychain"
			a.Status = "ok"
			a.Detail = "keychain reference configured; secret not read"
		case "file":
			a.Storage = "file"
			info, err := os.Lstat(expandAuthFilePath(auth.Path))
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 {
				a.Status = "ok"
				a.Detail = "restricted credential file present; contents not read"
			} else {
				a.Detail = "credential file missing, symlink, or permissions are not private"
			}
		}
	} else if cfg.Source.Keychain != nil {
		a.Storage = "keychain"
		a.Status = "ok"
		a.Detail = "keychain reference configured; secret not read"
	} else if cfg.SourceURL() != "" {
		a.Storage = "plaintext_url"
		a.Status = "warn"
		a.Detail = "source.url contains plaintext authentication; migrate to keychain or file"
	}
	return a
}
func inspectOpenConnectSessionHealth(name, cacheDir string) diag.SessionHealth {
	item := diag.SessionHealth{Name: name, Kind: "openconnect", State: "none"}
	current, err := openconnect.LoadCurrent(openconnect.ResolveCacheDir(cacheDir))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			item.State = "unknown"
			item.Error = "openconnect session cache could not be read"
		}
		return item
	}
	item.SessionID = current.ID
	item.PID = current.PID
	item.Interface = current.Interface
	item.Profile = current.Profile
	item.LogPath = current.LogPath
	alive, pid, e := openconnect.SessionAlive(current)
	item.PID = pid
	item.State = "stale"
	if alive {
		item.State = "active"
	}
	if e != nil {
		item.State = "unknown"
		item.Error = "openconnect process identity could not be verified"
	}
	return item
}
func diagnosticSessions(cfg config.ProjectConfig, present bool) ([]diag.SessionHealth, error) {
	var out []diag.SessionHealth
	type target struct{ name, cache, kind string }
	var targets []target
	var ocTargets []target
	if present {
		if len(cfg.Servers) == 0 {
			targets = append(targets, target{"default", cfg.CacheDir, cfg.EngineType()})
		} else {
			names := []string{}
			for name := range cfg.Servers {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				e, _, err := cfg.Effective(config.SelectionOptions{Server: name, AllowMissingProfile: true})
				if err != nil {
					out = append(out, diag.SessionHealth{Name: name, State: "unknown", Error: "server configuration unavailable"})
					continue
				}
				if isOpenConnectServerCLI(cfg.Servers[name]) {
					ocCache := ""
					if e.OpenConnect != nil {
						ocCache = e.OpenConnect.CacheDir
					}
					if ocCache == "" {
						ocCache = cfg.Servers[name].CacheDir
					}
					ocTargets = append(ocTargets, target{name, openconnect.ResolveCacheDir(ocCache), "openconnect"})
					continue
				}
				targets = append(targets, target{name, e.CacheDir, e.EngineType()})
			}
		}
	}
	for _, target := range targets {
		item := diag.SessionHealth{Name: target.name, Kind: target.kind, State: "none"}
		current, err := session.LoadCurrent(target.cache)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				item.State = "unknown"
				item.Error = "session cache could not be read"
			}
		} else {
			item.SessionID = current.ID
			item.PID = current.PID
			item.Interface = current.InterfaceName
			item.Profile = current.ProfileName
			item.LogPath = current.LogPath
			item.ConfigPath = current.ConfigPath
			if current.Engine != "" {
				item.Kind = current.Engine
			}
			alive, pid, e := session.SessionAlive(current)
			item.PID = pid
			item.State = "stale"
			if alive {
				item.State = "active"
			}
			if e != nil {
				item.State = "unknown"
				item.Error = "session process identity could not be verified"
			}
		}
		out = append(out, item)
	}
	seenOCCaches := map[string]bool{}
	for _, target := range ocTargets {
		seenOCCaches[target.cache] = true
		out = append(out, inspectOpenConnectSessionHealth(target.name, target.cache))
	}
	defaultOCCache := openconnect.ResolveCacheDir("")
	if !seenOCCaches[defaultOCCache] {
		out = append(out, inspectOpenConnectSessionHealth("openconnect", defaultOCCache))
	}
	return out, nil
}
func diagnosticArgs(args []string) ([]string, error) {
	var flags, pos []string
	values := map[string]bool{"config": true, "timeout": true, "http-scheme": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			pos = append(pos, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, equals := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if values[name] && !equals {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag needs a value: %s", arg)
			}
			i++
			flags = append(flags, args[i])
		}
	}
	return append(append(flags, "--"), pos...), nil
}
func (a *App) runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	path := fs.String("config", "", "Path to config file")
	asJSON := fs.Bool("json", false, "Print JSON")
	normalized, err := diagnosticArgs(args)
	if err != nil {
		fmt.Fprintln(a.stderr, err)
		return 2
	}
	if fs.Parse(normalized) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, "usage: tun-wave doctor [--config path] [--json]")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	report := diag.Doctor(ctx, diagnosticsDepsCLI(*path, 8*time.Second))
	if err := writeDiagnostic(a.stdout, *asJSON, report, diag.FormatDoctorText(report)); err != nil {
		fmt.Fprintln(a.stderr, err)
		return 1
	}
	if !report.Healthy {
		return 1
	}
	return 0
}
func (a *App) runTrace(args []string) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	path := fs.String("config", "", "Path to config file")
	asJSON := fs.Bool("json", false, "Print JSON")
	timeout := fs.Duration("timeout", 8*time.Second, "Overall probe timeout")
	scheme := fs.String("http-scheme", "https", "https or http")
	skip := fs.Bool("no-http", false, "Skip HTTP probe")
	normalized, err := diagnosticArgs(args)
	if err != nil {
		fmt.Fprintln(a.stderr, err)
		return 2
	}
	if fs.Parse(normalized) != nil {
		return 2
	}
	if fs.NArg() != 1 || *timeout <= 0 {
		fmt.Fprintln(a.stderr, "usage: tun-wave trace [--config path] [--json] [--timeout duration] [--http-scheme https|http] [--no-http] <host>")
		return 2
	}
	if _, _, err := diag.ParseTraceTarget(fs.Arg(0), *scheme); err != nil {
		fmt.Fprintln(a.stderr, err)
		return 2
	}
	report, err := diag.Trace(context.Background(), diagnosticsDepsCLI(*path, *timeout), diag.TraceOptions{Host: fs.Arg(0), Timeout: *timeout, HTTPScheme: *scheme, SkipHTTP: *skip})
	if err != nil {
		fmt.Fprintln(a.stderr, err)
		return 2
	}
	if err := writeDiagnostic(a.stdout, *asJSON, report, diag.FormatTraceText(report)); err != nil {
		fmt.Fprintln(a.stderr, err)
		return 1
	}
	if report.Verdict == "unhealthy" {
		return 1
	}
	return 0
}
func writeDiagnostic(w io.Writer, asJSON bool, report any, text string) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	_, err := io.WriteString(w, text)
	return err
}
