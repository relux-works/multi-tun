package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/stack"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/singbox"
)

type stackController interface {
	StartStack(context.Context, []string, stack.StartStackOptions) (stack.StackReport, error)
	Up(context.Context, string, stack.UpOptions) (stack.StackReport, error)
	Down(context.Context, string, stack.DownOptions) (stack.StackReport, error)
	StopStack(context.Context, stack.DownOptions) (stack.StackReport, error)
	Status(context.Context) (stack.StackStatus, error)
}

var newStackCoordinatorCLI = func(a *App, cfg config.ProjectConfig, path string, refresh bool) (stackController, error) {
	return a.buildStackCoordinator(cfg, path, refresh)
}

func isOpenConnectServerCLI(s config.ServerConfig) bool { return stack.IsOpenConnectServer(s) }
func providerKind(s config.ServerConfig) stack.ProviderKind {
	if isOpenConnectServerCLI(s) {
		return stack.ProviderOpenConnect
	}
	if s.Engine != nil {
		switch strings.ToLower(strings.TrimSpace(s.Engine.Type)) {
		case config.EngineAWG:
			return stack.ProviderAmneziaAWG
		case config.EngineXray:
			return stack.ProviderXray
		case config.EngineVLESSReality:
			return stack.ProviderVLESSReality
		}
	}
	return stack.ProviderVLESS
}
func (a *App) buildStackCoordinator(cfg config.ProjectConfig, path string, refresh bool) (*stack.Coordinator, error) {
	oc := &stack.OpenConnectProvider{Config: cfg, ProgressWriter: a.stderr}
	resolver := func(ctx context.Context, selector string) (stack.MemberSpec, error) {
		spec, err := stack.ParseSelector(selector)
		if err != nil {
			return spec, err
		}
		srv, ok := cfg.Servers[spec.Server]
		if !ok || isOpenConnectServerCLI(srv) {
			return oc.Resolve(ctx, selector)
		}
		_, sel, err := cfg.Effective(config.SelectionOptions{Server: spec.Server, Profile: spec.Profile})
		if err != nil {
			return spec, err
		}
		spec.Profile = sel.Profile
		spec.Kind = providerKind(srv)
		spec.Role = "egress"
		return spec, nil
	}
	providers := map[stack.ProviderKind]stack.TunnelProvider{stack.ProviderOpenConnect: oc}
	for _, kind := range []stack.ProviderKind{stack.ProviderVLESS, stack.ProviderVLESSReality, stack.ProviderXray, stack.ProviderAmneziaAWG} {
		providers[kind] = &stack.TunProvider{ProviderKind: kind,
			PrepareFunc: func(ctx context.Context, spec stack.MemberSpec, peers []stack.PreparedMember) (stack.PreparedMember, error) {
				r, d := stack.MergeFragments(peers)
				payload, err := a.prepareStackTUN(ctx, cfg, path, spec, r, d, refresh)
				if err != nil {
					return stack.PreparedMember{}, err
				}
				return stack.PreparedMember{Spec: spec, Interface: payload.cfg.TunInterfaceName(), Payload: payload}, nil
			},
			StartFunc: func(ctx context.Context, prepared stack.PreparedMember, r stack.RoutingFragment, d stack.DNSFragment) (stack.MemberState, error) {
				payload, ok := prepared.Payload.(stackTUNPrepared)
				if !ok {
					return stack.MemberState{}, errors.New("invalid TUN preparation")
				}
				if err := ctx.Err(); err != nil {
					return stack.MemberState{}, err
				}
				if err := restoreFiles(payload.rendered); err != nil {
					return stack.MemberState{}, errors.Join(err, restoreFiles(payload.previous))
				}
				started, err := a.startPrepared(payload.cfg, payload.prepared)
				m := stackTUNState(prepared.Spec, &started, "active", err == nil)
				if err != nil {
					if restoreErr := restoreFiles(payload.previous); restoreErr != nil {
						err = errors.Join(err, restoreErr)
					}
					return m, err
				}
				a.refreshStackProtection(payload.cfg, started)
				return m, nil
			},
			StopFunc: func(ctx context.Context, spec stack.MemberSpec, force bool, timeout time.Duration) (stack.MemberState, error) {
				effective, _, err := cfg.Effective(config.SelectionOptions{Server: spec.Server, Profile: spec.Profile, AllowMissingProfile: true})
				if err != nil {
					return stack.MemberState{}, err
				}
				live, err := stackTUNStatus(ctx, effective, spec)
				if err != nil || !live.Active {
					return live, err
				}
				current, state, err := stopCurrentSessionFunc(effective.CacheDir, effective.LaunchOrDefault(), force, timeout)
				m := stackTUNState(spec, current, state, err != nil)
				return m, err
			},
			StatusFunc: func(ctx context.Context, spec stack.MemberSpec) (stack.MemberState, error) {
				effective, _, err := cfg.Effective(config.SelectionOptions{Server: spec.Server, Profile: spec.Profile, AllowMissingProfile: true})
				if err != nil {
					return stack.MemberState{}, err
				}
				return stackTUNStatus(ctx, effective, spec)
			},
			ReconcileFunc: func(ctx context.Context, spec stack.MemberSpec, r stack.RoutingFragment, d stack.DNSFragment) (stack.MemberState, error) {
				return a.reconcileStackTUN(ctx, cfg, path, spec, r, d)
			},
		}
	}
	var configured []stack.MemberSpec
	names := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		srv := cfg.Servers[name]
		profile := ""
		if cfg.Current != nil && cfg.Current.Server == name {
			profile = cfg.Current.Profile
		}
		if profile == "" && len(srv.Profiles) == 1 {
			for key := range srv.Profiles {
				profile = key
			}
		}
		selector := name
		if profile != "" {
			selector += "/" + profile
		}
		// Status can recover the actual profile from session metadata. Do not
		// resolve an unspecified profile here: multi-profile inactive servers are
		// still inspectable, and no credential/network work belongs in discovery.
		role := "egress"
		kind := providerKind(srv)
		if kind == stack.ProviderOpenConnect {
			role = "overlay"
		}
		configured = append(configured, stack.MemberSpec{Selector: selector, Server: name, Profile: profile, Kind: kind, Role: role})
	}
	return stack.NewCoordinator(stack.CoordinatorOptions{Providers: providers, Resolve: resolver, Configured: configured, StatePath: filepath.Join(cfg.CacheDir, "active-stack.json")}), nil
}

type stackTUNPrepared struct {
	cfg      config.ProjectConfig
	prepared preparedStart
	previous []fileSnapshot
	rendered []fileSnapshot
}

func explicitOverlay(r stack.RoutingFragment, d stack.DNSFragment) singbox.RenderOptions {
	// A non-nil render-options pointer with nil OverlayDNS deliberately disables
	// disk discovery when the coordinated stack has no overlays.
	if len(r.RouteExcludes) == 0 && len(d.Domains) == 0 && len(d.Nameservers) == 0 && len(d.BypassDomains) == 0 {
		return singbox.RenderOptions{}
	}
	return singbox.RenderOptions{OverlayDNS: &singbox.OverlayDNS{Domains: append([]string(nil), d.Domains...), BypassDomains: append([]string(nil), d.BypassDomains...), Nameservers: append([]string(nil), d.Nameservers...), RouteExcludes: append([]string(nil), r.RouteExcludes...)}}
}
func (a *App) prepareStackTUN(ctx context.Context, root config.ProjectConfig, path string, spec stack.MemberSpec, r stack.RoutingFragment, d stack.DNSFragment, refresh bool) (stackTUNPrepared, error) {
	if err := ctx.Err(); err != nil {
		return stackTUNPrepared{}, err
	}
	effective, sel, err := root.Effective(config.SelectionOptions{Server: spec.Server, Profile: spec.Profile})
	if err != nil {
		return stackTUNPrepared{}, err
	}
	effective.Routing.BypassSuffixes = append(append([]string(nil), effective.Routing.BypassSuffixes...), r.BypassSuffixes...)

	previous, err := snapshotFiles(effective.SingboxConfigPath(), effective.XrayConfigPath(), effective.AWGConfigPath())
	if err != nil {
		return stackTUNPrepared{}, err
	}
	overlay := explicitOverlay(r, d)
	prepared, err := a.prepareStart(effective, (startOptions{configPath: path, serverName: spec.Server, configProfile: spec.Profile, refresh: refresh, refreshSet: true, renderOptions: &overlay, routingFragment: &r}).withEffectiveSelection(sel))
	if err == nil {
		err = preflightReplacement(prepared)
	}
	if err == nil {
		launch := effective.LaunchOrDefault()
		var mode string
		mode, err = resolveLaunchModeCLI(effective.NetworkMode(), launch)
		if err == nil {
			launch.Mode = mode
			effective.Launch = &config.LaunchConfig{Mode: launch.Mode, Label: launch.Label, PlistPath: launch.PlistPath}
			err = preflightHelperSchema(mode, prepared)
		}
	}
	if err != nil {
		return stackTUNPrepared{}, errors.Join(err, restoreFiles(previous))
	}
	prepared.systemServers = append([]string(nil), d.SystemServers...)
	if len(prepared.tunAddresses) > 0 {
		effective.Network.TUN.Addresses = append([]string(nil), prepared.tunAddresses...)
	}
	rendered, err := snapshotFiles(effective.SingboxConfigPath(), effective.XrayConfigPath(), effective.AWGConfigPath())
	if err != nil {
		return stackTUNPrepared{}, errors.Join(err, restoreFiles(previous))
	}
	if err := restoreFiles(previous); err != nil {
		return stackTUNPrepared{}, err
	}
	return stackTUNPrepared{cfg: effective, prepared: prepared, previous: previous, rendered: rendered}, nil
}
func stackTUNState(spec stack.MemberSpec, current *session.CurrentSession, status string, active bool) stack.MemberState {
	m := stack.MemberState{Spec: spec, Status: status, Active: active}
	if current != nil {
		m.SessionID, m.PID, m.Interface, m.LogPath = current.ID, current.PID, current.InterfaceName, current.LogPath
	}
	return m
}
func stackTUNStatus(ctx context.Context, cfg config.ProjectConfig, spec stack.MemberSpec) (stack.MemberState, error) {
	if err := ctx.Err(); err != nil {
		return stack.MemberState{}, err
	}
	current, state, active, err := currentSessionStateForSelection(cfg.CacheDir, cfg.LaunchOrDefault())
	if err != nil {
		return stackTUNState(spec, current, state, false), err
	}
	if current != nil && active {
		if current.ResolvedServer != "" && current.ResolvedServer != spec.Server {
			return stackTUNState(spec, nil, "inactive", false), nil
		}
		// All aliases of one server share its cache. Recover the live alias rather
		// than treating the current config's default alias as the running member.
		if current.ResolvedAlias != "" {
			spec.Profile = current.ResolvedAlias
			spec.Selector = spec.Server + "/" + spec.Profile
		}
	}
	if active && current != nil {
		name := current.InterfaceName
		if name == "" {
			name = cfg.TunInterfaceName()
		}
		present, _, interfaceErr := interfaceStateStatus(name)
		if !present || interfaceErr != nil {
			state = "degraded"
		}
	}
	return stackTUNState(spec, current, state, active), nil
}
func (a *App) refreshStackProtection(cfg config.ProjectConfig, started session.CurrentSession) {
	if usesVPNCoreHelper(started.LaunchMode) {
		policy, err := cfg.FailClosedPolicy()
		a.refreshFailClosedAfterStart(policy, err, cfg.TunAddresses())
	}
}
func (a *App) reconcileStackTUN(ctx context.Context, root config.ProjectConfig, path string, spec stack.MemberSpec, r stack.RoutingFragment, d stack.DNSFragment) (stack.MemberState, error) {
	payload, err := a.prepareStackTUN(ctx, root, path, spec, r, d, false)
	if err != nil {
		return stack.MemberState{}, err
	}
	cfg := payload.cfg
	if err := restoreFiles(payload.rendered); err != nil {
		return stack.MemberState{}, errors.Join(err, restoreFiles(payload.previous))
	}
	stopped, state, err := stopCurrentSessionFunc(cfg.CacheDir, cfg.LaunchOrDefault(), false, 15*time.Second)
	if err != nil {
		return stackTUNState(spec, stopped, state, true), errors.Join(err, restoreFiles(payload.previous))
	}
	started, startErr := a.startPrepared(cfg, payload.prepared)
	if startErr != nil {
		if cleanupErr := stopFailedReplacement(cfg.CacheDir, cfg.LaunchOrDefault(), started, startErr, 5*time.Second); cleanupErr != nil {
			return stackTUNState(spec, &started, "failed", true), errors.Join(startErr, cleanupErr)
		}
		restoreErr := restoreFiles(payload.previous)
		if restoreErr == nil && stopped != nil {
			// The legacy recovery helper reconstructs the old start options and
			// refuses unsupported old sidecar records rather than guessing them.
			var oldConfig []byte
			existed := false
			for _, snap := range payload.previous {
				if snap.path == stopped.ConfigPath {
					oldConfig, existed = snap.data, snap.existed
				}
			}
			a.restorePreviousSession(cfg, []stopSessionResult{{target: sessionTarget{cacheDir: cfg.CacheDir, launch: cfg.LaunchOrDefault()}, stopped: stopped, state: state}}, stopped.ConfigPath, oldConfig, existed)
		}
		return stackTUNState(spec, &started, "failed", false), errors.Join(startErr, restoreErr)
	}
	a.refreshStackProtection(cfg, started)
	return stackTUNState(spec, &started, "active", true), nil
}

func shouldStartStack(cfg config.ProjectConfig, args []string) bool {
	if len(args) > 2 {
		return true
	}
	if len(args) >= 2 {
		for _, arg := range args {
			if strings.Contains(arg, "/") {
				return true
			}
		}
	}
	if len(args) == 2 {
		first, ok := cfg.Servers[args[0]]
		_, second := cfg.Servers[args[1]]
		_, profile := first.Profiles[args[1]]
		if ok && second && !profile {
			return true
		}
	}
	if len(args) == 1 {
		server, _, _ := strings.Cut(args[0], "/")
		return isOpenConnectServerCLI(cfg.Servers[server])
	}
	return len(args) == 0 && len(cfg.Stack) > 0
}
func (a *App) maybeStackStart(args []string) (bool, int) {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "")
	server := fs.String("server", "", "")
	profile := fs.String("profile", "", "")
	selector := fs.String("selector", "", "")
	transport := fs.String("transport", "", "")
	output := fs.String("output", "", "")
	refresh := fs.Bool("refresh", true, "")
	if fs.Parse(reorderStackFlags(args)) != nil {
		return false, 0
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return false, 0
	}
	positions := fs.Args()
	stackMode := shouldStartStack(cfg, positions)
	if len(positions) == 0 && (*server != "" || *profile != "" || *selector != "" || *transport != "" || *output != "") {
		stackMode = false
	}
	if len(positions) == 0 && *selector == "" && *transport == "" && *output == "" {
		selected := *server
		if selected == "" && cfg.Current != nil {
			selected = cfg.Current.Server
		}
		if isOpenConnectServerCLI(cfg.Servers[selected]) && (len(cfg.Stack) == 0 || *server != "" || *profile != "") {
			stackMode = true
			value := selected
			if *profile != "" {
				value += "/" + *profile
			} else if cfg.Current != nil && cfg.Current.Server == selected && cfg.Current.Profile != "" {
				value += "/" + cfg.Current.Profile
			}
			positions = []string{value}
		}
	}
	if len(positions) == 1 && !stackMode {
		name, _, _ := strings.Cut(positions[0], "/")
		if _, ok := cfg.Servers[name]; !ok && *server == "" && *profile == "" && *selector == "" {
			oc := stack.OpenConnectProvider{Config: cfg}
			if _, err := oc.Resolve(context.Background(), positions[0]); err == nil {
				stackMode = true
			}
		}
	}
	if !stackMode {
		return false, 0
	}
	if *selector != "" || *transport != "" || *output != "" || (*server != "" && len(fs.Args()) > 0) || (*profile != "" && len(fs.Args()) > 0) {
		fmt.Fprintln(a.stderr, "start failed: stack selectors cannot be combined with single-profile overrides")
		return true, 2
	}
	if len(positions) == 0 {
		positions = cfg.Stack
	}
	coordinator, err := newStackCoordinatorCLI(a, cfg, *path, *refresh)
	if err != nil {
		return true, a.printStackResult("start", stack.StackReport{}, err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, err := coordinator.StartStack(ctx, positions, stack.StartStackOptions{Refresh: *refresh})
	return true, a.printStackResult("start", report, err)
}
func (a *App) runStackMember(command string, args []string) int {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	path := fs.String("config", "", "Path to config file")
	refresh := fs.Bool("refresh", false, "Refresh the source")
	replace := fs.Bool("replace", false, "Replace the active egress")
	force := fs.Bool("force", false, "Force teardown")
	timeout := fs.Duration("timeout", 20*time.Second, "Stop timeout")
	if fs.Parse(reorderStackFlags(args)) != nil {
		return 2
	}
	invalid := false
	fs.Visit(func(f *flag.Flag) {
		if (command == "down" && (f.Name == "refresh" || f.Name == "replace")) || (command == "up" && f.Name == "force") {
			invalid = true
		}
	})
	if invalid {
		fmt.Fprintf(a.stderr, "%s failed: unsupported flag\n", command)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(a.stderr, "usage: tun-wave %s [flags] server[/profile]\n", command)
		return 2
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return a.printStackResult(command, stack.StackReport{}, err)
	}
	coordinator, err := newStackCoordinatorCLI(a, cfg, *path, *refresh)
	if err != nil {
		return a.printStackResult(command, stack.StackReport{}, err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var report stack.StackReport
	if command == "up" {
		report, err = coordinator.Up(ctx, fs.Arg(0), stack.UpOptions{Refresh: *refresh, Replace: *replace, Timeout: *timeout})
	} else {
		report, err = coordinator.Down(ctx, fs.Arg(0), stack.DownOptions{Force: *force, Timeout: *timeout})
	}
	return a.printStackResult(command, report, err)
}
func (a *App) printStackResult(command string, report stack.StackReport, err error) int {
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", command, err)
		return 1
	}
	if err := json.NewEncoder(a.stdout).Encode(report); err != nil {
		fmt.Fprintf(a.stderr, "%s output failed: %v\n", command, err)
		return 1
	}
	return 0
}
func (a *App) maybeStackStop(path, server string, args []string, force bool, timeout time.Duration) (bool, int) {
	if len(args) > 1 {
		return false, 0
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return false, 0
	}
	selected := server
	if selected == "" && len(args) == 1 {
		selected = args[0]
	}
	if server != "" && len(args) > 0 {
		return false, 0
	}
	name, _, _ := strings.Cut(selected, "/")
	tracked := fileExists(filepath.Join(cfg.CacheDir, "active-stack.json"))
	hasOC := false
	for _, srv := range cfg.Servers {
		hasOC = hasOC || isOpenConnectServerCLI(srv)
	}
	legacyOC := false
	if selected != "" {
		if _, ok := cfg.Servers[name]; !ok {
			oc := stack.OpenConnectProvider{Config: cfg}
			_, resolveErr := oc.Resolve(context.Background(), selected)
			legacyOC = resolveErr == nil
		}
	}
	if !tracked && !hasOC && !legacyOC && !strings.Contains(selected, "/") {
		return false, 0
	}
	if selected != "" && !tracked && !legacyOC && !isOpenConnectServerCLI(cfg.Servers[name]) {
		return false, 0
	}
	coordinator, err := newStackCoordinatorCLI(a, cfg, path, false)
	if err != nil {
		return true, a.printStackResult("stop", stack.StackReport{}, err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var report stack.StackReport
	if selected != "" {
		report, err = coordinator.Down(ctx, selected, stack.DownOptions{Force: force, Timeout: timeout})
	} else {
		report, err = coordinator.StopStack(ctx, stack.DownOptions{Force: force, Timeout: timeout})
	}
	if err != nil {
		return true, a.printStackResult("stop", report, err)
	}
	if selected == "" {
		// Retain the legacy cache scan for sessions lacking a stack record.
		if _, err := stopConfiguredSessions(path, force, timeout); err != nil {
			return true, a.printStackResult("stop", report, err)
		}
	}
	return true, a.printStackResult("stop", report, nil)
}
func (a *App) runPACServe(args []string) int {
	options, err := openconnect.ParsePACServeArgs(args)
	if err != nil {
		fmt.Fprintf(a.stderr, "%s: %v\n", openconnect.PACServeCommand, err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := openconnect.ServePAC(ctx, options, a.stderr); err != nil {
		fmt.Fprintf(a.stderr, "%s: %v\n", openconnect.PACServeCommand, err)
		return 1
	}
	return 0
}

// applyCoordinatedRouting completes the renderer's route-only case. Its DNS
// normalizer deliberately drops overlays without DNS domains/nameservers, but
// Order B must install gateway exclusions before any overlay DNS exists.
// This transforms the single rendered document before publication; it does not
// render or start the data plane a second time and never synthesizes DNS rules.
func applyCoordinatedRouting(data []byte, r stack.RoutingFragment) ([]byte, []string, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	var exclusions []string
	for _, raw := range r.RouteExcludes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid overlay route exclusion %q", raw)
		}
		exclusions = append(exclusions, p.Masked().String())
	}
	var addresses []string
	inbounds, _ := doc["inbounds"].([]any)
	for _, value := range inbounds {
		inbound, ok := value.(map[string]any)
		if !ok || inbound["type"] != "tun" {
			continue
		}
		excludes := append([]string(nil), exclusions...)
		if old, ok := inbound["route_exclude_address"].([]any); ok {
			for _, v := range old {
				if s, ok := v.(string); ok {
					excludes = append(excludes, s)
				}
			}
		}
		sort.Strings(excludes)
		excludes = compactStrings(excludes)
		var prefixes []netip.Prefix
		for _, raw := range excludes {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, nil, err
			}
			prefixes = append(prefixes, p)
		}
		old, _ := inbound["address"].([]any)
		for _, v := range old {
			raw, ok := v.(string)
			if !ok {
				return nil, nil, errors.New("invalid rendered TUN address")
			}
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, nil, err
			}
			conflicts := func(candidate netip.Prefix) bool {
				for _, excluded := range prefixes {
					if candidate.Overlaps(excluded) {
						return true
					}
				}
				return false
			}
			if conflicts(p) {
				if !p.Addr().Is4() {
					return nil, nil, errors.New("overlay conflicts with IPv6 TUN subnet")
				}
				found := false
				for subnet := 0; subnet < 256; subnet++ {
					candidate := netip.MustParsePrefix(fmt.Sprintf("198.18.%d.1/30", subnet))
					if !conflicts(candidate) {
						raw = candidate.String()
						found = true
						break
					}
				}
				if !found {
					return nil, nil, errors.New("no non-conflicting TUN subnet available")
				}
			}
			addresses = append(addresses, raw)
		}
		inbound["address"] = addresses
		if len(excludes) > 0 {
			inbound["route_exclude_address"] = excludes
		}
	}
	if len(r.DirectProcess) > 0 {
		route, ok := doc["route"].(map[string]any)
		if !ok {
			return nil, nil, errors.New("rendered route configuration missing")
		}
		rules, _ := route["rules"].([]any)
		names := compactStrings(append([]string(nil), r.DirectProcess...))
		route["rules"] = append([]any{map[string]any{"process_name": names, "action": "route", "outbound": "direct"}}, rules...)
	}
	result, err := json.MarshalIndent(doc, "", "  ")
	return append(result, '\n'), addresses, err
}
func compactStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if v != "" && !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

func (a *App) maybeStackStatus(path, server, profile string, args []string) (bool, int) {
	cfg, err := loadConfig(path)
	if err != nil {
		return false, 0
	}
	selected := server
	if selected == "" && len(args) == 1 {
		selected, profile, _ = strings.Cut(args[0], "/")
	}
	hasOC := false
	for _, srv := range cfg.Servers {
		hasOC = hasOC || isOpenConnectServerCLI(srv)
	}
	if selected != "" && !isOpenConnectServerCLI(cfg.Servers[selected]) {
		return false, 0
	}
	if selected == "" && !hasOC && len(cfg.Stack) == 0 && !fileExists(filepath.Join(cfg.CacheDir, "active-stack.json")) {
		return false, 0
	}
	coordinator, err := newStackCoordinatorCLI(a, cfg, path, false)
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return true, 1
	}
	status, err := coordinator.Status(context.Background())
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return true, 1
	}
	if selected != "" {
		members := status.Members[:0]
		for _, m := range status.Members {
			if m.Spec.Server == selected && (profile == "" || m.Spec.Profile == profile) {
				members = append(members, m)
			}
		}
		status.Members = members
	}
	if err := json.NewEncoder(a.stdout).Encode(status); err != nil {
		fmt.Fprintf(a.stderr, "status output failed: %v\n", err)
		return true, 1
	}
	return true, 0
}

func reorderStackFlags(args []string) []string {
	var flags, positions []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positions = append(positions, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			positions = append(positions, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") || name == "force" || name == "refresh" || name == "replace" || name == "h" || name == "help" {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positions...)
}
