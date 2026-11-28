package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"multi-tun/desktop/internal/anyconnect/keychain"
	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
	"multi-tun/desktop/internal/vless/config"
)

type OpenConnectProvider struct {
	InterfacePresent func(string) bool
	Config           config.ProjectConfig
	ProgressWriter   io.Writer
	// Hooks are instance-local: offline tests never need host credential access.
	LoadConfig   func(string) (openconnectcfg.Config, string, error)
	LookupSecret func(string) (string, error)
	LookupIP     func(context.Context, string) ([]net.IPAddr, error)
	Connect      func(openconnect.ConnectOptions) (openconnect.ConnectResult, error)
	StopSession  func(string, time.Duration) (openconnect.CurrentSession, string, error)
	LoadSession  func(string) (openconnect.CurrentSession, error)
	SessionAlive func(openconnect.CurrentSession) (bool, int, error)
}
type openConnectPrepared struct {
	Options  openconnect.ConnectOptions
	CacheDir string
}

func (p *OpenConnectProvider) Kind() ProviderKind { return ProviderOpenConnect }
func (p *OpenConnectProvider) load(selector string) (openconnectcfg.Config, openconnectcfg.RuntimeSelection, string, error) {
	spec, err := ParseSelector(selector)
	if err != nil {
		return openconnectcfg.Config{}, openconnectcfg.RuntimeSelection{}, "", err
	}
	var cfg openconnectcfg.Config
	authMode := "aggregate"
	if srv, ok := p.Config.Servers[spec.Server]; ok {
		if !IsOpenConnectServer(srv) {
			return cfg, openconnectcfg.RuntimeSelection{}, "", errors.New("server is not openconnect")
		}
		oc := srv.OpenConnect
		if oc == nil {
			oc = &config.OpenConnectServerConfig{ServerURL: srv.Source.URL}
		}
		if oc.AuthMode != "" {
			authMode = oc.AuthMode
		}
		profiles := map[string]openconnectcfg.ProfileConfig{}
		for name, profile := range srv.Profiles {
			if profile.OpenConnect != nil {
				profiles[name] = *profile.OpenConnect
			} else {
				profiles[name] = openconnectcfg.ProfileConfig{Name: name}
			}
		}
		cfg = openconnectcfg.Config{CacheDir: oc.CacheDir, DefaultMode: oc.Mode, Servers: map[string]openconnectcfg.ServerConfig{spec.Server: {ServerURL: oc.ServerURL, Auth: oc.Auth, ClientMimicry: oc.ClientMimicry, SplitInclude: oc.SplitInclude, PAC: oc.PAC, Profiles: profiles}}}
		server := cfg.Servers[spec.Server]
		if server.ServerURL == "" {
			server.ServerURL = srv.Source.URL
			cfg.Servers[spec.Server] = server
		}
		if cfg.CacheDir == "" {
			cfg.CacheDir = srv.CacheDir
		}
		if cfg.CacheDir == "" {
			cfg.CacheDir = openconnect.DefaultCacheDir()
		}
		if spec.Profile == "" && p.Config.Current != nil && p.Config.Current.Server == spec.Server {
			spec.Profile = p.Config.Current.Profile
		}
	} else {
		load := p.LoadConfig
		if load == nil {
			load = openconnectcfg.LoadOptional
		}
		cfg, _, err = load(p.Config.OpenConnectConfigPath)
		if err != nil {
			return cfg, openconnectcfg.RuntimeSelection{}, "", err
		}
		if _, ok := cfg.Servers[spec.Server]; !ok {
			return cfg, openconnectcfg.RuntimeSelection{}, "", fmt.Errorf("unknown openconnect server %q", spec.Server)
		}
		if spec.Profile == "" {
			def := cfg.DefaultSelection()
			if def.ServerURL == spec.Server || def.ServerURL == cfg.Servers[spec.Server].ServerURL {
				spec.Profile = def.Profile
			}
		}
	}
	server := cfg.Servers[spec.Server]
	if spec.Profile == "" && len(server.Profiles) == 1 {
		for name := range server.Profiles {
			spec.Profile = name
		}
	}
	// An unambiguous suffix alias, such as outside -> ural-outside, preserves
	// the legacy profile's native name. Ambiguity is an explicit refusal.
	if spec.Profile != "" {
		if _, ok := server.Profiles[spec.Profile]; !ok {
			matches := []string{}
			for name, profile := range server.Profiles {
				if profile.Name == spec.Profile || profile.Profile == spec.Profile || strings.HasSuffix(name, "-"+spec.Profile) {
					matches = append(matches, name)
				}
			}
			sort.Strings(matches)
			if len(matches) == 1 {
				spec.Profile = matches[0]
			} else if len(matches) > 1 {
				return cfg, openconnectcfg.RuntimeSelection{}, "", errors.New("ambiguous openconnect profile alias")
			}
		}
	}
	selection, err := cfg.ResolveRuntimeSelection(openconnectcfg.SelectionOptions{ServerURL: spec.Server, Profile: spec.Profile})
	return cfg, selection, authMode, err
}
func IsOpenConnectServer(s config.ServerConfig) bool {
	return (s.Engine != nil && strings.EqualFold(strings.TrimSpace(s.Engine.Type), config.EngineOpenConnect)) || strings.EqualFold(strings.TrimSpace(s.Source.Mode), config.SourceModeOpenConnect)
}
func (p *OpenConnectProvider) Resolve(ctx context.Context, selector string) (MemberSpec, error) {
	spec, err := ParseSelector(selector)
	if err != nil {
		return spec, err
	}
	_, selection, _, err := p.load(selector)
	if err != nil {
		return spec, err
	}
	spec.Profile = selection.ProfileKey
	spec.Kind, spec.Role = ProviderOpenConnect, "overlay"
	return spec, nil
}
func (p *OpenConnectProvider) Prepare(ctx context.Context, spec MemberSpec, peers []PreparedMember) (PreparedMember, error) {
	cfg, sel, authMode, err := p.load(spec.Selector)
	if err != nil {
		return PreparedMember{}, err
	}
	pac := cfg.EffectivePAC(sel.ServerURL, sel.ProfileKey)
	if err := pac.Validate(); err != nil {
		return PreparedMember{}, err
	}
	script := pac.Script
	if pac.File != "" {
		// The same bounded, no-follow file loader used by the helper is exposed by
		// ResolvePAC so provider and legacy CLI materialize identical inputs.
		_, script, err = openconnect.ResolvePAC(pac)
		if err != nil {
			return PreparedMember{}, err
		}
	}
	split := openconnectcfg.SplitIncludeConfig{}
	mode := cfg.EffectiveMode(sel.ServerURL, sel.ProfileKey)
	if mode == "" {
		mode = openconnect.ConnectModeFull
	}
	if mode == openconnect.ConnectModeSplitInclude {
		split = cfg.EffectiveSplitInclude(sel.ServerURL, sel.ProfileKey)
	}
	mimic := cfg.EffectiveClientMimicry(sel.ServerURL)
	options := openconnect.ConnectOptions{Server: sel.ServerURL, Profile: sel.Profile, Auth: authMode, Mode: mode, CacheDir: openconnect.ResolveCacheDir(cfg.CacheDir), SuppressReconcile: true,
		IncludeRoutes: split.Routes, VPNDomains: split.VPNDomains, BypassSuffixes: split.BypassSuffixes, VPNNameservers: split.Nameservers,
		PACURL: pac.URL, PACScript: script, PACRewrites: pac.Rewrites, ProgressWriter: p.ProgressWriter,
		ClientMimicry:       openconnect.ClientMimicry{UserAgent: mimic.UserAgent, Version: mimic.Version, OS: mimic.OS, DeviceID: mimic.DeviceID, LocalHostname: mimic.LocalHostname, AuthMethods: mimic.AuthMethods, HTTPHeaders: mimic.HTTPHeaders},
		AuthFallbackServers: cfg.EffectiveAuthFallbackServers(sel.ServerURL)}
	if options.ProgressWriter == nil {
		options.ProgressWriter = io.Discard
	}
	home, _ := os.UserHomeDir()
	options.ProfilePaths = openconnect.DefaultProfileSearchPaths(home)
	auth := cfg.EffectiveAuth(sel.ServerURL)
	lookup := p.LookupSecret
	if lookup == nil {
		lookup = keychain.Get
	}
	read := func(account string) (string, error) {
		if account == "" {
			return "", nil
		}
		value, err := lookup(account)
		if err != nil {
			return "", errors.New("openconnect credential unavailable")
		}
		return value, nil
	}
	options.Credentials.Username = auth.Username
	if options.Credentials.Username == "" {
		options.Credentials.Username, err = read(auth.UsernameKeychainAccount)
		if err != nil {
			return PreparedMember{}, err
		}
	}
	options.Credentials.Password, err = read(auth.PasswordKeychainAccount)
	if err != nil {
		return PreparedMember{}, err
	}
	factor := auth.SecondFactor
	factorMode := ""
	account := auth.TOTPKeychainAccount
	if factor != nil {
		if strings.TrimSpace(factor.Mode) != "" {
			factorMode = strings.TrimSpace(factor.Mode)
		}
		if strings.TrimSpace(factor.TOTPKeychainAccount) != "" {
			account = strings.TrimSpace(factor.TOTPKeychainAccount)
		}
	}
	if factorMode == "" {
		if strings.TrimSpace(account) != "" {
			factorMode = openconnectcfg.SecondFactorModeTOTPAuto
		} else {
			factorMode = openconnectcfg.SecondFactorModeManualOTP
		}
	}
	switch factorMode {
	case openconnectcfg.SecondFactorModeManualOTP:
		options.Credentials.ManualOTPStdin = true
	case openconnectcfg.SecondFactorModeTOTPAuto:
		if account == "" {
			return PreparedMember{}, errors.New("TOTP account is required")
		}
		options.Credentials.TOTPSecret, err = read(account)
		if err != nil {
			return PreparedMember{}, err
		}
	default:
		return PreparedMember{}, errors.New("unknown openconnect second factor mode")
	}
	// Resolve all authentication gateways before Order-B's first reconciliation.
	// Failure refuses the operation before auth; routing an unexcluded gateway
	// through the existing TUN is never a best-effort fallback.
	gateways := []string{sel.ServerURL}
	gateways = append(gateways, options.AuthFallbackServers...)
	var excluded []string
	lookupIP := p.LookupIP
	if lookupIP == nil {
		lookupIP = net.DefaultResolver.LookupIPAddr
	}
	for _, gateway := range gateways {
		raw := gateway
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return PreparedMember{}, errors.New("invalid openconnect gateway URL")
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := lookupIP(lookupCtx, u.Hostname())
		cancel()
		if err != nil || len(ips) == 0 {
			return PreparedMember{}, errors.New("openconnect gateway resolution failed")
		}
		for _, ip := range ips {
			excluded = append(excluded, ipPrefix(ip.IP.String()))
			options.GatewayIPs = append(options.GatewayIPs, ip.IP.String())
		}
	}
	return PreparedMember{Spec: spec, Routing: RoutingFragment{RouteExcludes: unique(excluded), DirectProcess: []string{"openconnect"}}, Payload: openConnectPrepared{Options: options, CacheDir: options.CacheDir}}, nil
}
func ipPrefix(raw string) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()).String()
}
func (p *OpenConnectProvider) Start(ctx context.Context, m PreparedMember, r RoutingFragment, d DNSFragment) (MemberState, error) {
	if err := ctx.Err(); err != nil {
		return MemberState{}, err
	}
	payload, ok := m.Payload.(openConnectPrepared)
	if !ok {
		return MemberState{}, errors.New("invalid openconnect preparation")
	}
	connect := p.Connect
	if connect == nil {
		connect = openconnect.Connect
	}
	previous, previousErr := p.current(m.Spec)
	if previousErr != nil && !errors.Is(previousErr, os.ErrNotExist) {
		return MemberState{}, previousErr
	}
	result, err := connect(payload.Options)
	state := MemberState{Spec: m.Spec, Active: err == nil, Status: "active", SessionID: result.SessionID, PID: result.PID, Interface: result.Interface, LogPath: result.LogPath}
	if err != nil {
		state.Active = false
		state.Status = "failed"
		if partial, loadErr := p.current(m.Spec); loadErr == nil && partial.ID != "" && partial.ID != previous.ID {
			state.SessionID = partial.ID
			state.PID = partial.PID
			state.Interface = partial.Interface
			state.LogPath = partial.LogPath
			state.Active = true
		}

		return state, err
	}
	live, err := p.Status(ctx, m.Spec)
	if err != nil {
		return state, err
	}
	return live, nil
}
func (p *OpenConnectProvider) cache(spec MemberSpec) (string, error) {
	if server, ok := p.Config.Servers[spec.Server]; ok {
		if !IsOpenConnectServer(server) {
			return "", errors.New("openconnect configuration missing")
		}
		cache := ""
		if server.OpenConnect != nil {
			cache = server.OpenConnect.CacheDir
		}
		if cache == "" {
			cache = server.CacheDir
		}
		return openconnect.ResolveCacheDir(cache), nil
	}
	load := p.LoadConfig
	if load == nil {
		load = openconnectcfg.LoadOptional
	}
	cfg, _, err := load(p.Config.OpenConnectConfigPath)
	return openconnect.ResolveCacheDir(cfg.CacheDir), err
}
func (p *OpenConnectProvider) current(spec MemberSpec) (openconnect.CurrentSession, error) {
	cache, err := p.cache(spec)
	if err != nil {
		return openconnect.CurrentSession{}, err
	}
	load := p.LoadSession
	if load == nil {
		load = openconnect.LoadCurrent
	}
	return load(cache)
}
func (p *OpenConnectProvider) Status(ctx context.Context, spec MemberSpec) (MemberState, error) {
	current, err := p.current(spec)
	m := MemberState{Spec: spec, Status: "inactive"}
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	probe := spec.Selector
	var profiles map[string]openconnectcfg.ProfileConfig
	var expectedURL string
	if server, ok := p.Config.Servers[spec.Server]; ok {
		expectedURL = server.Source.URL
		if server.OpenConnect != nil && server.OpenConnect.ServerURL != "" {
			expectedURL = server.OpenConnect.ServerURL
		}
		profiles = map[string]openconnectcfg.ProfileConfig{}
		for name, profile := range server.Profiles {
			if profile.OpenConnect != nil {
				profiles[name] = *profile.OpenConnect
			} else {
				profiles[name] = openconnectcfg.ProfileConfig{Name: name}
			}
		}
	} else {
		load := p.LoadConfig
		if load == nil {
			load = openconnectcfg.LoadOptional
		}
		cfg, _, loadErr := load(p.Config.OpenConnectConfigPath)
		if loadErr != nil {
			return m, loadErr
		}
		server := cfg.Servers[spec.Server]
		profiles = server.Profiles
		expectedURL = server.ServerURL
		if expectedURL == "" {
			expectedURL = server.URL
		}
		if expectedURL == "" {
			expectedURL = spec.Server
		}
	}
	// Legacy servers can share a cache. A different gateway's record is not
	// this member, even when its native profile has no alias on this server.
	if current.Server != "" && !sameGateway(current.Server, expectedURL) {
		return m, nil
	}
	alive := p.SessionAlive
	if alive == nil {
		alive = openconnect.SessionAlive
	}
	active, _, err := alive(current)
	if err != nil {
		return m, err
	}
	if !active {
		return m, nil
	}
	if current.Profile != "" {
		matches := []string{}
		for name, profile := range profiles {
			native := profile.Name
			if native == "" {
				native = profile.Profile
			}
			if native == "" {
				native = name
			}
			if native == current.Profile {
				matches = append(matches, name)
			}
		}
		if len(matches) != 1 {
			return m, errors.New("cannot identify active openconnect profile alias")
		}
		probe = spec.Server + "/" + matches[0]
	}
	_, sel, _, err := p.load(probe)
	if err != nil {
		return m, err
	}
	if current.Server != "" && !sameGateway(current.Server, sel.ServerURL) {
		return m, nil
	}
	status := "active"
	present := p.InterfacePresent
	if present == nil {
		present = func(name string) bool { _, err := net.InterfaceByName(name); return err == nil }
	}
	if current.Interface == "" || !present(current.Interface) {
		status = "degraded"
	}
	m.Active, m.Status = active, status
	m.SessionID, m.PID, m.Interface, m.LogPath, m.PAC = current.ID, current.PID, current.Interface, current.LogPath, current.PAC
	if current.Profile != "" {
		m.Spec.Profile = sel.ProfileKey
		m.Spec.Selector = spec.Server + "/" + sel.ProfileKey
	}

	return m, nil
}
func (p *OpenConnectProvider) Stop(ctx context.Context, spec MemberSpec, force bool, timeout time.Duration) (MemberState, error) {
	m, err := p.Status(ctx, spec)
	if err != nil {
		return m, err
	}
	current, loadErr := p.current(spec)
	if errors.Is(loadErr, os.ErrNotExist) {
		return m, nil
	}
	if loadErr != nil {
		return m, loadErr
	}
	_, selected, _, selectErr := p.load(spec.Selector)
	if selectErr != nil {
		return m, selectErr
	}
	if !sameGateway(current.Server, selected.ServerURL) || (current.Profile != "" && current.Profile != selected.Profile) {
		return m, errors.New("openconnect session changed before stop")
	}
	cache, err := p.cache(spec)
	if err != nil {
		return m, err
	}
	stop := p.StopSession
	if stop == nil {
		stop = openconnect.StopWithoutReconcile
	}
	_, status, err := stop(cache, timeout)
	if err != nil {
		return m, err
	}
	m.Active = false
	m.Status = status
	return m, nil
}
func (p *OpenConnectProvider) Fragments(ctx context.Context, spec MemberSpec) (RoutingFragment, DNSFragment, error) {
	current, err := p.current(spec)
	if err != nil {
		return RoutingFragment{}, DNSFragment{}, err
	}
	r := RoutingFragment{IncludeRoutes: append([]string(nil), current.IncludeRoutes...), BypassSuffixes: append([]string(nil), current.BypassSuffixes...), DirectProcess: []string{"openconnect"}}
	r.RouteExcludes = append(r.RouteExcludes, current.IncludeRoutes...)
	for _, ip := range append(append([]string(nil), current.GatewayIPs...), current.VPNNameservers...) {
		r.RouteExcludes = append(r.RouteExcludes, ipPrefix(ip))
	}
	d := DNSFragment{Domains: append([]string(nil), current.VPNDomains...), BypassDomains: append([]string(nil), current.BypassSuffixes...), Nameservers: append([]string(nil), current.VPNNameservers...)}
	if emitted := openconnect.SessionOverlayDNS(current); emitted != nil {
		r.RouteExcludes = append(r.RouteExcludes, emitted.RouteExcludes...)
		d.Domains = append(d.Domains, emitted.Domains...)
		d.BypassDomains = append(d.BypassDomains, emitted.BypassDomains...)
		d.Nameservers = append(d.Nameservers, emitted.Nameservers...)
	}
	r, d = MergeFragments([]PreparedMember{{Routing: r, DNS: d}})
	return r, d, nil
}

func sameGateway(a, b string) bool {
	canonical := func(raw string) string {
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		host := strings.ToLower(parsed.Hostname())
		if port := parsed.Port(); port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		return parsed.Scheme + "://" + host + strings.TrimSuffix(parsed.EscapedPath(), "/") + "?" + parsed.RawQuery
	}
	return canonical(a) == canonical(b)
}
