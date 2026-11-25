package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/singbox"
	"multi-tun/desktop/internal/vless/subscription"
	"multi-tun/desktop/internal/vless/xray"
)

type startOptions struct {
	configPath      string
	serverName      string
	configProfile   string
	profileSelector string
	transport       string
	outputPath      string
	refresh         bool
	refreshSet      bool
	match           *config.ProfileMatch
	pick            string
}

type sessionTarget struct {
	label    string
	cacheDir string
	launch   config.PrivilegedLaunchConfig
}

type stopSessionResult struct {
	target  sessionTarget
	stopped *session.CurrentSession
	state   string
}

var stopCurrentSessionFunc = stopCurrentSession
var startSessionFunc = session.Start
var lookPathFunc = exec.LookPath
var profileProbeDialContext = (&net.Dialer{}).DialContext
var currentSessionStateForSelection = currentSessionState

// preflightReplacement checks what session start needs and can be verified
// without touching the network or the running tunnel, so reconnect fails
// before it stops anything. Route checks cannot run here: while the old
// tunnel is up the new upstream legitimately routes through it.
var (
	resolveLaunchModeCLI    = session.ResolveLaunchMode
	validateHelperConfigCLI = vpncore.ValidateSingBoxConfig
	readFileCLI             = os.ReadFile
	writeRestoredConfigCLI  = func(path string, data []byte) error { return os.WriteFile(path, data, 0o600) }
	removeRenderedConfigCLI = func(path string) error {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
)

// preflightHelperSchema refuses, before anything is stopped, a rendered
// sing-box config that the vpn-core helper would refuse to start. launchMode is
// the mode resolved once for this reconnect; for every engine the sing-box
// config at prepared.target (the full config, or the Xray engine's TUN
// frontend) is what the helper launches.
func preflightHelperSchema(launchMode string, prepared preparedStart) error {
	if launchMode != config.LaunchModeHelper {
		return nil
	}
	data, err := readFileCLI(prepared.target)
	if err != nil {
		return fmt.Errorf("read rendered config for the helper check: %w", err)
	}
	if err := validateHelperConfigCLI(data); err != nil {
		return fmt.Errorf("the vpn-core helper would refuse the new config: %w", err)
	}
	return nil
}

// fileSnapshot is a config file's state before rendering.
type fileSnapshot struct {
	path    string
	data    []byte
	existed bool
}

// snapshotFiles records the current bytes (or absence) of each distinct path.
// A read failure other than absence is returned: such a file could not be put
// back after a refused replacement.
func snapshotFiles(paths ...string) ([]fileSnapshot, error) {
	seen := map[string]bool{}
	var out []fileSnapshot
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		data, err := readFileCLI(p)
		switch {
		case err == nil:
			out = append(out, fileSnapshot{path: p, data: data, existed: true})
		case errors.Is(err, os.ErrNotExist):
			out = append(out, fileSnapshot{path: p})
		default:
			return nil, fmt.Errorf("cannot read the current config %s: %w", p, err)
		}
	}
	return out, nil
}

// restoreFiles puts every snapshotted file back and reports each failure.
func restoreFiles(snaps []fileSnapshot) error {
	var errs []error
	for _, s := range snaps {
		if err := restoreRenderedTarget(s.path, s.data, s.existed); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.path, err))
		}
	}
	return errors.Join(errs...)
}

// restoreRenderedTarget puts the replacement's target back to its state before
// rendering: the previous bytes, or no file when none existed.
func restoreRenderedTarget(target string, previous []byte, existed bool) error {
	if existed {
		return writeRestoredConfigCLI(target, previous)
	}
	return removeRenderedConfigCLI(target)
}

// restorePreviousSession brings the stopped session back after a refused
// replacement start. It restarts the single stopped sing-box session with its
// own recorded start options (mode, launch mode, interface, bypass list, TUN
// addresses, overlay and system DNS, log limit, resolution) in its own cache
// dir. A record without recorded start options (written by an older build),
// sidecars or several sessions are reported for a manual start.
func (a *App) restorePreviousSession(cfg config.ProjectConfig, stopped []stopSessionResult, previousTarget string, previousConfig []byte, previousExisted bool) {
	if len(stopped) == 0 {
		fmt.Fprintln(a.stderr, "no previous session was running")
		return
	}
	prev := stopped[0].stopped
	if len(stopped) != 1 || prev == nil || prev.Engine != config.EngineSingbox || prev.ConfigPath != previousTarget || !previousExisted || len(prev.Sidecars) != 0 || !prev.StartOptionsRecorded {
		fmt.Fprintln(a.stderr, "the previous session was stopped and could not be restored automatically; start it with `vless-tun start`")
		return
	}
	if err := writeRestoredConfigCLI(previousTarget, previousConfig); err != nil {
		fmt.Fprintf(a.stderr, "restore previous config failed: %v; start it with `vless-tun start`\n", err)
		return
	}
	profile := model.Profile{ID: prev.ProfileID, Name: prev.ProfileName}
	if host, port, err := net.SplitHostPort(prev.ProfileEndpoint); err == nil {
		profile.Host = host
		profile.Port, _ = strconv.Atoi(port)
	}
	opts := restoreStartOptions(cfg, prev)
	restored, err := startSessionFunc(stopped[0].target.cacheDir, previousTarget, profile, opts)
	if err != nil {
		fmt.Fprintf(a.stderr, "restore of the previous session failed: %v; start it with `vless-tun start`\n", err)
		return
	}
	fmt.Fprintf(a.stderr, "previous session restored as %s (pid=%d, profile %s)\n", restored.ID, restored.PID, restored.ProfileName)
}

// restoreStartOptions builds the restart options entirely from the stopped
// session's record (callers require StartOptionsRecorded); only the
// privileged launch label and plist come from the config.
func restoreStartOptions(cfg config.ProjectConfig, prev *session.CurrentSession) session.StartOptions {
	launch := cfg.LaunchOrDefault()
	if prev.LaunchMode != "" {
		launch.Mode = prev.LaunchMode
	}
	return session.StartOptions{
		Mode:              prev.Mode,
		Engine:            config.EngineSingbox,
		BypassSuffixes:    append([]string(nil), prev.BypassSuffixes...),
		InterfaceName:     prev.InterfaceName,
		TunAddresses:      append([]string(nil), prev.TunAddresses...),
		OverlayDNSActive:  prev.OverlayDNSActive,
		OverlayDNSDomains: append([]string(nil), prev.OverlayDNSDomains...),
		SystemDNSServers:  append([]string(nil), prev.SystemDNSServers...),
		PrivilegedLaunch:  launch,
		LogMaxLines:       prev.LogMaxLines,
		ResolvedServer:    prev.ResolvedServer,
		ResolvedAlias:     prev.ResolvedAlias,
		ResolvedName:      prev.ResolvedProfileName,
		ResolvedID:        prev.ResolvedProfileID,
		ResolutionReason:  prev.ResolutionReason,
		SnapshotFetchedAt: prev.SnapshotFetchedAt,
	}
}

func preflightReplacement(prepared preparedStart) error {
	if _, err := lookPathFunc("sing-box"); err != nil {
		return fmt.Errorf("sing-box executable not found: %w", err)
	}
	for _, sidecar := range prepared.sidecars {
		if _, err := lookPathFunc(sidecar.Executable); err != nil {
			return fmt.Errorf("%s executable not found: %w", sidecar.Name, err)
		}
	}
	return nil
}

func (a *App) runStart(args []string) int {
	return a.runStartCommand("start", args)
}

func (a *App) runRun(args []string) int {
	return a.runStartCommand("run", args)
}

func (a *App) runStartCommand(commandName string, args []string) int {
	options, exitCode, err := a.parseStartOptions(commandName, args, true)
	if err != nil {
		return exitCode
	}

	cfg, selection, err := loadEffectiveConfig(options.configPath, config.SelectionOptions{
		Server:    options.serverName,
		Profile:   options.configProfile,
		Selector:  options.profileSelector,
		Transport: options.transport,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}
	options = options.withEffectiveSelection(selection)
	if warning := runtimeLoggingPerformanceWarning(cfg); warning != "" {
		fmt.Fprintf(a.stderr, "warning: %s\n", warning)
	}
	launchCfg := cfg.LaunchOrDefault()

	if current, state, alive, err := currentSessionState(cfg.CacheDir, launchCfg); err == nil && current != nil && alive {
		fmt.Fprintf(a.stderr, "%s failed: vless-tun session %s is already %s (pid=%d)\n", commandName, current.ID, state, current.PID)
		return 1
	}

	prepared, err := a.prepareStart(cfg, options)
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}

	if current, state, alive, err := currentSessionState(cfg.CacheDir, launchCfg); err == nil && current != nil && !alive {
		if err := cleanupStaleCurrentSession(cfg.CacheDir, launchCfg); err != nil {
			fmt.Fprintf(a.stderr, "%s failed: cleanup stale session: %v\n", commandName, err)
			return 1
		}
	} else if err == nil && current != nil && alive {
		fmt.Fprintf(a.stderr, "%s failed: vless-tun session %s is already %s (pid=%d)\n", commandName, current.ID, state, current.PID)
		return 1
	}

	a.applyFailClosedBeforeStart(cfg)
	started, err := startSessionFunc(cfg.CacheDir, prepared.target, prepared.profile, session.StartOptions{
		Mode:              cfg.NetworkMode(),
		Engine:            prepared.engine,
		BypassSuffixes:    cfg.BypassSuffixes(),
		InterfaceName:     cfg.TunInterfaceName(),
		TunAddresses:      cfg.TunAddresses(),
		OverlayDNSActive:  prepared.renderOptions.OverlayDNS != nil,
		OverlayDNSDomains: overlayDNSDomains(prepared.renderOptions),
		SystemDNSServers:  systemDNSServers(cfg),
		PrivilegedLaunch:  cfg.LaunchOrDefault(),
		Sidecars:          prepared.sidecars,
		LogMaxLines:       cfg.LogMaxLines(),
		ResolvedServer:    prepared.resolvedServer(),
		ResolvedAlias:     prepared.resolvedAlias(),
		ResolvedName:      prepared.resolvedName(),
		ResolvedID:        prepared.resolvedID(),
		ResolutionReason:  prepared.resolution.Reason,
		SnapshotFetchedAt: prepared.snapshotFetchedAt,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}

	fmt.Fprintf(a.stdout, "started vless-tun session %s\n", started.ID)
	printProfileResolution(a.stdout, prepared)
	fmt.Fprintf(a.stdout, "pid=%d profile=%s (%s)\n", started.PID, started.ProfileName, started.ProfileID)
	fmt.Fprintf(a.stdout, "engine=%s\n", started.Engine)
	fmt.Fprintf(a.stdout, "mode=%s\n", started.Mode)
	fmt.Fprintf(a.stdout, "launch_mode=%s\n", started.LaunchMode)
	fmt.Fprintf(a.stdout, "config=%s\n", started.ConfigPath)
	if prepared.xrayTarget != "" {
		fmt.Fprintf(a.stdout, "xray_config=%s\n", prepared.xrayTarget)
	}
	printSidecarStarts(a.stdout, started.Sidecars)
	fmt.Fprintf(a.stdout, "log=%s\n", started.LogPath)
	fmt.Fprintln(a.stdout, "use `vless-tun status` to inspect state and `vless-tun stop` to stop it")
	if usesVPNCoreHelper(started.LaunchMode) {
		policy, perr := cfg.FailClosedPolicy()
		a.refreshFailClosedAfterStart(policy, perr, cfg.TunAddresses())
	}
	return 0
}

// usesVPNCoreHelper reports whether the session runs through the shared
// vpn-core helper, which is the only component that enforces fail_closed.
func usesVPNCoreHelper(launchMode string) bool {
	return launchMode == "helper" || launchMode == "launchd"
}

func (a *App) runReconnect(args []string) int {
	fs := flag.NewFlagSet("reconnect", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias; in legacy flat configs this remains a profile selector")
	profileSelector := fs.String("selector", "", "Subscription profile selector by id, name, endpoint, transport, or substring")
	transport := fs.String("transport", "", "Subscription profile transport: tcp or grpc")
	outputPath := fs.String("output", "", "Override render.output_path")
	refresh := fs.Bool("refresh", true, "Fetch subscription before rendering and reconnecting")
	force := fs.Bool("force", false, "Escalate from SIGTERM to SIGKILL if sing-box does not stop in time")
	timeout := fs.Duration("timeout", 5*time.Second, "How long to wait after SIGTERM before failing or forcing")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	selectionOptions, err := commandServerProfileSelection(*serverName, *profileName, *profileSelector, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 2
	}
	selectionOptions.Transport = strings.TrimSpace(*transport)

	cfg, selection, err := loadEffectiveConfig(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 1
	}
	if warning := runtimeLoggingPerformanceWarning(cfg); warning != "" {
		fmt.Fprintf(a.stderr, "warning: %s\n", warning)
	}

	// Keep the config the running session was started from: rendering the
	// replacement overwrites that file, and a refused start must be able to
	// bring the previous session back.
	previousTarget := cfg.SingboxConfigPath()
	if *outputPath != "" {
		previousTarget = *outputPath
	}
	// Snapshot every config file rendering may overwrite (the sing-box config and
	// the Xray config), so any refusal before the stop can put them back.
	snaps, snapErr := snapshotFiles(previousTarget, cfg.XrayConfigPath())
	if snapErr != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", snapErr)
		fmt.Fprintln(a.stderr, "running sessions were left untouched")
		return 1
	}
	previousConfig, previousExisted := snaps[0].data, snaps[0].existed
	refuseBeforeStop := func(err error) int {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		fmt.Fprintln(a.stderr, "running sessions were left untouched")
		if rerr := restoreFiles(snaps); rerr != nil {
			fmt.Fprintf(a.stderr, "but restoring the previous config files failed: %v\n", rerr)
		}
		return 1
	}
	// Resolve the launch mode once; the preflight and the start use the same
	// mode, so a helper that appears or disappears in between cannot slip a
	// config past the schema check.
	launch := cfg.LaunchOrDefault()
	launchMode, launchModeErr := resolveLaunchModeCLI(cfg.NetworkMode(), launch)
	if launchModeErr != nil {
		// Without a resolved mode the helper check cannot be done; stop nothing.
		fmt.Fprintf(a.stderr, "reconnect failed: cannot resolve the launch mode: %v\n", launchModeErr)
		fmt.Fprintln(a.stderr, "running sessions were left untouched")
		return 1
	}
	launch.Mode = launchMode

	// Prepare the replacement before stopping anything: a refresh that drops the
	// selected profile, or any render error, must leave the running tunnel alone.
	prepared, err := a.prepareStart(cfg, startOptions{
		configPath:      *configPath,
		serverName:      selectionOptions.Server,
		configProfile:   selectionOptions.Profile,
		profileSelector: selectionOptions.Selector,
		transport:       firstNonEmptyLocal(selectionOptions.Transport, *transport),
		outputPath:      *outputPath,
		refresh:         *refresh,
		refreshSet:      true,
	}.withEffectiveSelection(selection))
	if err != nil {
		return refuseBeforeStop(err)
	}
	if err := preflightReplacement(prepared); err != nil {
		return refuseBeforeStop(err)
	}
	if err := preflightHelperSchema(launchMode, prepared); err != nil {
		return refuseBeforeStop(err)
	}

	stoppedSessions, err := stopConfiguredSessions(*configPath, *force, *timeout)
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		for _, result := range stoppedSessions {
			if result.stopped != nil && result.stopped.LogPath != "" {
				fmt.Fprintf(a.stderr, "log=%s\n", result.stopped.LogPath)
			}
		}
		return 1
	}

	a.applyFailClosedBeforeStart(cfg)
	startOpts := session.StartOptions{
		Mode:              cfg.NetworkMode(),
		Engine:            prepared.engine,
		BypassSuffixes:    cfg.BypassSuffixes(),
		InterfaceName:     cfg.TunInterfaceName(),
		TunAddresses:      cfg.TunAddresses(),
		OverlayDNSActive:  prepared.renderOptions.OverlayDNS != nil,
		OverlayDNSDomains: overlayDNSDomains(prepared.renderOptions),
		SystemDNSServers:  systemDNSServers(cfg),
		PrivilegedLaunch:  launch,
		Sidecars:          prepared.sidecars,
		LogMaxLines:       cfg.LogMaxLines(),
		ResolvedServer:    prepared.resolvedServer(),
		ResolvedAlias:     prepared.resolvedAlias(),
		ResolvedName:      prepared.resolvedName(),
		ResolvedID:        prepared.resolvedID(),
		ResolutionReason:  prepared.resolution.Reason,
		SnapshotFetchedAt: prepared.snapshotFetchedAt,
	}
	started, err := startSessionFunc(cfg.CacheDir, prepared.target, prepared.profile, startOpts)
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		// A failed start can still leave a replacement running or recorded (for
		// example when its liveness is unknown). Stop whatever it left before
		// bringing the previous session back; if that cannot be confirmed, do not
		// start a second session.
		if _, _, serr := stopCurrentSessionFunc(cfg.CacheDir, launch, true, *timeout); serr != nil {
			fmt.Fprintf(a.stderr, "the replacement may still be running (%v); the previous session was not restored; inspect with `vless-tun status`\n", serr)
			return 1
		}
		a.restorePreviousSession(cfg, stoppedSessions, previousTarget, previousConfig, previousExisted)
		return 1
	}

	fmt.Fprintf(a.stdout, "reconnected vless-tun session %s\n", started.ID)
	printProfileResolution(a.stdout, prepared)
	if len(stoppedSessions) == 0 {
		fmt.Fprintln(a.stdout, "previous_session: none")
	} else {
		for _, result := range stoppedSessions {
			label := result.target.label
			if label == "" {
				fmt.Fprintf(a.stdout, "previous_session: %s (%s)\n", result.stopped.ID, result.state)
				continue
			}
			fmt.Fprintf(a.stdout, "previous_session: %s %s (%s)\n", label, result.stopped.ID, result.state)
		}
	}
	fmt.Fprintf(a.stdout, "pid=%d profile=%s (%s)\n", started.PID, started.ProfileName, started.ProfileID)
	fmt.Fprintf(a.stdout, "engine=%s\n", started.Engine)
	fmt.Fprintf(a.stdout, "mode=%s\n", started.Mode)
	fmt.Fprintf(a.stdout, "launch_mode=%s\n", started.LaunchMode)
	fmt.Fprintf(a.stdout, "config=%s\n", started.ConfigPath)
	if prepared.xrayTarget != "" {
		fmt.Fprintf(a.stdout, "xray_config=%s\n", prepared.xrayTarget)
	}
	printSidecarStarts(a.stdout, started.Sidecars)
	fmt.Fprintf(a.stdout, "log=%s\n", started.LogPath)
	fmt.Fprintln(a.stdout, "use `vless-tun status` to inspect state and `vless-tun stop` to stop it")
	if usesVPNCoreHelper(started.LaunchMode) {
		policy, perr := cfg.FailClosedPolicy()
		a.refreshFailClosedAfterStart(policy, perr, cfg.TunAddresses())
	}
	return 0
}

func (a *App) runStop(args []string) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	force := fs.Bool("force", false, "Escalate from SIGTERM to SIGKILL if sing-box does not stop in time")
	timeout := fs.Duration("timeout", 5*time.Second, "How long to wait after SIGTERM before failing or forcing")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	selectionOptions, err := commandServerSelection(*serverName, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		return 2
	}

	targets, err := sessionTargetsForConfig(*configPath, selectionOptions.Server)
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		return 1
	}

	stoppedAny := false
	for _, target := range targets {
		stopped, state, err := stopCurrentSessionFunc(target.cacheDir, target.launch, *force, *timeout)
		if err != nil {
			fmt.Fprintf(a.stderr, "stop failed")
			if target.label != "" {
				fmt.Fprintf(a.stderr, " for %s", target.label)
			}
			fmt.Fprintf(a.stderr, ": %v\n", err)
			if stopped != nil && stopped.LogPath != "" {
				fmt.Fprintf(a.stderr, "log=%s\n", stopped.LogPath)
			}
			return 1
		}
		if stopped == nil {
			continue
		}
		stoppedAny = true
		printStopResult(a.stdout, target.label, stopped, state)
	}

	if !stoppedAny {
		fmt.Fprintln(a.stdout, "no current session file found")
	}
	return 0
}

type preparedStart struct {
	profile           model.Profile
	engine            string
	target            string
	xrayTarget        string
	sidecars          []session.SidecarOptions
	renderOptions     singbox.RenderOptions
	resolution        subscription.ProfileResolution
	resolutionServer  string
	resolutionAlias   string
	snapshotFetchedAt *time.Time
}

func (a *App) parseStartOptions(name string, args []string, refreshDefault bool) (startOptions, int, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias; in legacy flat configs this remains a profile selector")
	profileSelector := fs.String("selector", "", "Subscription profile selector by id, name, endpoint, transport, or substring")
	transport := fs.String("transport", "", "Subscription profile transport: tcp or grpc")
	outputPath := fs.String("output", "", "Override render.output_path")
	refresh := fs.Bool("refresh", refreshDefault, "Fetch subscription before rendering and starting")

	if err := fs.Parse(args); err != nil {
		return startOptions{}, 2, err
	}
	refreshSet := false
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == "refresh" {
			refreshSet = true
		}
	})
	selectionOptions, err := commandServerProfileSelection(*serverName, *profileName, *profileSelector, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", name, err)
		return startOptions{}, 2, err
	}

	return startOptions{
		configPath:      *configPath,
		serverName:      selectionOptions.Server,
		configProfile:   selectionOptions.Profile,
		profileSelector: selectionOptions.Selector,
		transport:       firstNonEmptyLocal(selectionOptions.Transport, *transport),
		outputPath:      *outputPath,
		refresh:         *refresh,
		refreshSet:      refreshSet,
	}, 0, nil
}

func (a *App) prepareStart(cfg config.ProjectConfig, options startOptions) (preparedStart, error) {
	snapshot, refreshed, err := a.loadStartSnapshot(cfg, effectiveStartRefresh(cfg, options))
	if err != nil {
		return preparedStart{}, err
	}

	policy, err := probeSelectionPolicy(options.configPath, options.serverName, options.configProfile, options.match, options.pick)
	if err != nil {
		return preparedStart{}, err
	}
	resolution, err := resolveProfileWithPolicy(snapshot.Profiles, cfg.DefaultProfileSelector(), cfg.DefaultProfileTransport(), options.match, options.pick, policy)
	if err != nil {
		return preparedStart{}, formatProfileSelectionError(err, snapshot.Profiles, cfg.DefaultProfileSelector(), cfg.DefaultProfileTransport(), options, refreshed)
	}
	profile := resolution.Profile

	renderOptions := resolveRenderOptionsCLI(cfg.NetworkMode())
	target := cfg.SingboxConfigPath()
	if options.outputPath != "" {
		target = options.outputPath
	}
	engine := cfg.EngineType()
	var data []byte
	var xrayData []byte
	var xrayTarget string
	var sidecars []session.SidecarOptions
	switch engine {
	case config.EngineSingbox:
		data, err = singbox.RenderWithOptions(cfg, profile, renderOptions)
	case config.EngineXray:
		xrayTarget = cfg.XrayConfigPath()
		xrayData, err = xray.Render(cfg, profile)
		if err != nil {
			return preparedStart{}, err
		}
		data, err = singbox.RenderXrayFrontendWithOptions(cfg, profile, renderOptions)
		if err != nil {
			return preparedStart{}, err
		}
		if err := xray.Write(xrayTarget, xrayData); err != nil {
			return preparedStart{}, err
		}
		sidecars = []session.SidecarOptions{
			{
				Name:       "xray",
				Executable: cfg.XrayExecutable(),
				Args:       []string{"run", "-c", xrayTarget},
			},
		}
	default:
		err = fmt.Errorf("unsupported engine %q", engine)
	}
	if err != nil {
		return preparedStart{}, err
	}
	if err := singbox.Write(target, data); err != nil {
		return preparedStart{}, err
	}

	prepared := preparedStart{
		profile:          profile,
		engine:           engine,
		target:           target,
		xrayTarget:       xrayTarget,
		sidecars:         sidecars,
		renderOptions:    renderOptions,
		resolution:       resolution,
		resolutionServer: options.serverName,
		resolutionAlias:  options.configProfile,
	}
	if resolution.Matched && !snapshot.FetchedAt.IsZero() {
		fetchedAt := snapshot.FetchedAt
		prepared.snapshotFetchedAt = &fetchedAt
	}
	return prepared, nil
}

func (options startOptions) withEffectiveSelection(selection config.EffectiveSelection) startOptions {
	if strings.TrimSpace(options.serverName) == "" {
		options.serverName = selection.Server
	}
	if strings.TrimSpace(options.configProfile) == "" {
		options.configProfile = selection.Profile
	}
	if strings.TrimSpace(options.profileSelector) == "" {
		options.profileSelector = selection.Selector
	}
	if strings.TrimSpace(options.transport) == "" {
		options.transport = selection.Transport
	}
	if options.match == nil {
		options.match = selection.Match
	}
	if strings.TrimSpace(options.pick) == "" {
		options.pick = selection.Pick
	}
	return options
}

func subscriptionMatch(match *config.ProfileMatch) *subscription.ProfileMatch {
	if match == nil {
		return nil
	}
	return &subscription.ProfileMatch{
		Country:     match.Country,
		NamePattern: match.NamePattern,
		Exclude:     append([]string(nil), match.Exclude...),
		Transport:   match.Transport,
	}
}

type profileSelectionPolicy struct {
	skipProbe  bool
	stickyID   string
	skipReason string
}

func resolveProfileWithPolicy(profiles []model.Profile, selector, transport string, match *config.ProfileMatch, pick string, policy profileSelectionPolicy) (subscription.ProfileResolution, error) {
	return subscription.ResolveProfileWithOptions(profiles, subscription.SelectOptions{
		Selector:   selector,
		Transport:  transport,
		Match:      subscriptionMatch(match),
		Pick:       pick,
		SkipProbe:  policy.skipProbe,
		StickyID:   policy.stickyID,
		SkipReason: policy.skipReason,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return profileProbeDialContext(ctx, network, address)
		},
	})
}

func probeSelectionPolicy(configPath, serverName, alias string, match *config.ProfileMatch, pick string) (profileSelectionPolicy, error) {
	if match == nil || !strings.EqualFold(strings.TrimSpace(pick), "probe") {
		return profileSelectionPolicy{}, nil
	}
	targets, err := sessionTargetsForConfig(configPath, "")
	if err != nil {
		return profileSelectionPolicy{}, err
	}

	policy := profileSelectionPolicy{}
	for _, target := range targets {
		current, _, alive, err := currentSessionStateForSelection(target.cacheDir, target.launch)
		if err != nil {
			return profileSelectionPolicy{}, fmt.Errorf("inspect running vless-tun session in %s: %w", target.cacheDir, err)
		}
		if !alive {
			continue
		}
		policy.skipProbe = true
		policy.skipReason = "probe skipped while a tunnel is up"
		if current != nil && current.ResolvedServer == serverName && current.ResolvedAlias == alias {
			policy.stickyID = current.ResolvedProfileID
		}
	}
	return policy, nil
}

func printProfileResolution(out io.Writer, prepared preparedStart) {
	if !prepared.resolution.Matched {
		return
	}
	fmt.Fprintf(out, "resolved: %s/%s -> %s (%s) via %s\n", prepared.resolutionServer, prepared.resolutionAlias, prepared.profile.DisplayName(), prepared.profile.ID, prepared.resolution.Reason)
}

func (prepared preparedStart) resolvedName() string {
	if !prepared.resolution.Matched {
		return ""
	}
	return prepared.profile.DisplayName()
}

func (prepared preparedStart) resolvedServer() string {
	if !prepared.resolution.Matched {
		return ""
	}
	return prepared.resolutionServer
}

func (prepared preparedStart) resolvedAlias() string {
	if !prepared.resolution.Matched {
		return ""
	}
	return prepared.resolutionAlias
}

func (prepared preparedStart) resolvedID() string {
	if !prepared.resolution.Matched {
		return ""
	}
	return prepared.profile.ID
}

func formatProfileSelectionError(cause error, profiles []model.Profile, selector string, transport string, options startOptions, refreshed bool) error {
	var builder strings.Builder
	sourceLabel := "cached"
	if refreshed {
		sourceLabel = "refreshed"
	}
	serverName := strings.TrimSpace(options.serverName)
	configProfile := strings.TrimSpace(options.configProfile)
	if serverName != "" && configProfile != "" {
		fmt.Fprintf(&builder, "configured profile %q for server %q did not match any %s subscription profile", configProfile, serverName, sourceLabel)
	} else if serverName != "" {
		fmt.Fprintf(&builder, "configured server %q did not match any %s subscription profile", serverName, sourceLabel)
	} else {
		fmt.Fprintf(&builder, "profile selection did not match any %s subscription profile", sourceLabel)
	}
	trimmedSelector := strings.TrimSpace(selector)
	if trimmedSelector != "" {
		fmt.Fprintf(&builder, "\nselector: %s", trimmedSelector)
	}
	trimmedTransport := strings.TrimSpace(transport)
	if trimmedTransport != "" {
		fmt.Fprintf(&builder, "\ntransport: %s", trimmedTransport)
	}
	if options.match != nil {
		if encoded, err := json.Marshal(options.match); err == nil {
			fmt.Fprintf(&builder, "\nmatch: %s", encoded)
		}
		fmt.Fprintf(&builder, "\npick: %s", firstNonEmptyLocal(options.pick, "only"))
	}
	if cause != nil {
		fmt.Fprintf(&builder, "\nreason: %v", cause)
	}
	if len(profiles) > 0 {
		builder.WriteString("\n\navailable profiles:")
		for idx, profile := range profiles {
			if idx >= 20 {
				fmt.Fprintf(&builder, "\n- ... %d more", len(profiles)-idx)
				break
			}
			fmt.Fprintf(&builder, "\n- %s", formatProfile(profile))
		}
	}
	if serverName != "" && configProfile != "" {
		if options.match != nil {
			fmt.Fprintf(&builder, "\n\nupdate config: servers.%s.profiles.%s.match or servers.%s.profiles.%s.pick", serverName, configProfile, serverName, configProfile)
		} else {
			fmt.Fprintf(&builder, "\n\nupdate config: servers.%s.profiles.%s.transport = \"tcp\" or \"grpc\", and add selector when transport is ambiguous", serverName, configProfile)
			fmt.Fprintf(&builder, "\nor update config: servers.%s.profiles.%s.selector = \"<id, name, endpoint, transport, or substring from available profiles>\"", serverName, configProfile)
		}
	} else {
		builder.WriteString("\n\nupdate the selected profile selector or transport in config")
	}
	if serverName != "" {
		fmt.Fprintf(&builder, "\nor run: vless-tun list %s", serverName)
	} else {
		builder.WriteString("\nor run: vless-tun list")
	}
	return errors.New(builder.String())
}

func effectiveStartRefresh(cfg config.ProjectConfig, options startOptions) bool {
	if options.refreshSet {
		return options.refresh
	}
	return true
}

func stopCurrentSession(cacheDir string, launch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (*session.CurrentSession, string, error) {
	stopped, state, err := session.Stop(cacheDir, launch, force, timeout)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "none", nil
	}
	if err != nil {
		return &stopped, state, err
	}
	return &stopped, state, nil
}

func cleanupStaleCurrentSession(cacheDir string, launch config.PrivilegedLaunchConfig) error {
	_, _, err := stopCurrentSessionFunc(cacheDir, launch, true, 1500*time.Millisecond)
	return err
}

func stopConfiguredSessions(configPath string, force bool, timeout time.Duration) ([]stopSessionResult, error) {
	targets, err := sessionTargetsForConfig(configPath, "")
	if err != nil {
		return nil, err
	}

	results := make([]stopSessionResult, 0, len(targets))
	for _, target := range targets {
		stopped, state, err := stopCurrentSessionFunc(target.cacheDir, target.launch, force, timeout)
		if stopped != nil {
			results = append(results, stopSessionResult{
				target:  target,
				stopped: stopped,
				state:   state,
			})
		}
		if err != nil {
			label := target.label
			if label == "" {
				return results, err
			}
			return results, fmt.Errorf("%s: %w", label, err)
		}
	}
	return results, nil
}

func sessionTargetsForConfig(configPath, serverName string) ([]sessionTarget, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	launch := cfg.LaunchOrDefault()
	if len(cfg.Servers) == 0 {
		if strings.TrimSpace(serverName) != "" {
			return nil, errors.New("server selection requires a config with servers")
		}
		effective, _, err := cfg.Effective(config.SelectionOptions{})
		if err != nil {
			return nil, err
		}
		return []sessionTarget{{
			cacheDir: effective.CacheDir,
			launch:   launch,
		}}, nil
	}

	if strings.TrimSpace(serverName) != "" {
		server, ok := cfg.Servers[strings.TrimSpace(serverName)]
		if !ok {
			return nil, errors.New("selected server " + strings.TrimSpace(serverName) + " is not configured")
		}
		cacheDir := firstNonEmptyLocal(server.CacheDir, cfg.CacheDir)
		if cacheDir == "" {
			return nil, errors.New("selected server " + strings.TrimSpace(serverName) + " has no cache_dir")
		}
		return []sessionTarget{{
			label:    strings.TrimSpace(serverName),
			cacheDir: cacheDir,
			launch:   launch,
		}}, nil
	}

	targets := make([]sessionTarget, 0, len(cfg.Servers))
	seen := map[string]struct{}{}
	for name, server := range cfg.Servers {
		cacheDir := firstNonEmptyLocal(server.CacheDir, cfg.CacheDir)
		if cacheDir == "" {
			continue
		}
		if _, ok := seen[cacheDir]; ok {
			continue
		}
		seen[cacheDir] = struct{}{}
		targets = append(targets, sessionTarget{
			label:    name,
			cacheDir: cacheDir,
			launch:   launch,
		})
	}
	if len(targets) == 0 {
		return nil, errors.New("no vless session cache directories are configured")
	}
	return targets, nil
}

func stopTargetsForConfig(configPath, serverName string) ([]sessionTarget, error) {
	return sessionTargetsForConfig(configPath, serverName)
}

func firstNonEmptyLocal(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func printStopResult(out io.Writer, label string, stopped *session.CurrentSession, state string) {
	if label != "" {
		fmt.Fprintf(out, "server: %s\n", label)
	}
	switch state {
	case "stopped", "killed":
		fmt.Fprintf(out, "%s vless-tun session %s (pid=%d)\n", state, stopped.ID, stopped.PID)
	case "stale":
		fmt.Fprintf(out, "cleared stale session %s (pid=%d)\n", stopped.ID, stopped.PID)
	default:
		fmt.Fprintf(out, "stop result=%s for session %s (pid=%d)\n", state, stopped.ID, stopped.PID)
	}
	if stopped.LogPath != "" {
		fmt.Fprintf(out, "log=%s\n", stopped.LogPath)
	}
}

func printSidecarStarts(out io.Writer, sidecars []session.SidecarSession) {
	for _, sidecar := range sidecars {
		fmt.Fprintf(out, "sidecar=%s pid=%d", sidecar.Name, sidecar.PID)
		if sidecar.LogPath != "" {
			fmt.Fprintf(out, " log=%s", sidecar.LogPath)
		}
		fmt.Fprintln(out)
	}
}

func systemDNSServers(cfg config.ProjectConfig) []string {
	values := []string{cfg.ProxyResolver().Address}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func overlayDNSDomains(options singbox.RenderOptions) []string {
	if options.OverlayDNS == nil {
		return nil
	}
	return append([]string(nil), options.OverlayDNS.Domains...)
}
