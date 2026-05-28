package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/singbox"
	"multi-tun/desktop/internal/vless/subscription"
)

type startOptions struct {
	configPath      string
	serverName      string
	configProfile   string
	profileSelector string
	outputPath      string
	refresh         bool
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

func (a *App) runStart(args []string) int {
	return a.runStartCommand("start", args)
}

func (a *App) runRun(args []string) int {
	return a.runStartCommand("run", args)
}

func (a *App) runStartCommand(commandName string, args []string) int {
	options, exitCode, err := a.parseStartOptions(commandName, args, false)
	if err != nil {
		return exitCode
	}

	cfg, _, err := loadEffectiveConfig(options.configPath, config.SelectionOptions{
		Server:   options.serverName,
		Profile:  options.configProfile,
		Selector: options.profileSelector,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}
	launchCfg := cfg.LaunchOrDefault()

	if current, state, alive, err := currentSessionState(cfg.CacheDir, launchCfg); err == nil && current != nil && alive {
		fmt.Fprintf(a.stderr, "%s failed: sing-box session %s is already %s (pid=%d)\n", commandName, current.ID, state, current.PID)
		return 1
	}

	prepared, err := a.prepareStart(cfg, options)
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}

	if current, state, alive, err := currentSessionState(cfg.CacheDir, launchCfg); err == nil && current != nil && !alive {
		_ = session.ClearCurrent(cfg.CacheDir)
	} else if err == nil && current != nil && alive {
		fmt.Fprintf(a.stderr, "%s failed: sing-box session %s is already %s (pid=%d)\n", commandName, current.ID, state, current.PID)
		return 1
	}

	started, err := session.Start(cfg.CacheDir, prepared.target, prepared.profile, session.StartOptions{
		Mode:              cfg.NetworkMode(),
		BypassSuffixes:    cfg.BypassSuffixes(),
		InterfaceName:     cfg.TunInterfaceName(),
		TunAddresses:      cfg.TunAddresses(),
		OverlayDNSActive:  prepared.renderOptions.OverlayDNS != nil,
		OverlayDNSDomains: overlayDNSDomains(prepared.renderOptions),
		SystemDNSServers:  systemDNSServers(cfg),
		PrivilegedLaunch:  cfg.LaunchOrDefault(),
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}

	fmt.Fprintf(a.stdout, "started sing-box session %s\n", started.ID)
	fmt.Fprintf(a.stdout, "pid=%d profile=%s (%s)\n", started.PID, started.ProfileName, started.ProfileID)
	fmt.Fprintf(a.stdout, "mode=%s\n", started.Mode)
	fmt.Fprintf(a.stdout, "launch_mode=%s\n", started.LaunchMode)
	fmt.Fprintf(a.stdout, "config=%s\n", started.ConfigPath)
	fmt.Fprintf(a.stdout, "log=%s\n", started.LogPath)
	fmt.Fprintln(a.stdout, "use `vless-tun status` to inspect state and `vless-tun stop` to stop it")
	return 0
}

func (a *App) runReconnect(args []string) int {
	fs := flag.NewFlagSet("reconnect", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias; in legacy flat configs this remains a profile selector")
	profileSelector := fs.String("selector", "", "Subscription profile selector by id, name, endpoint, or substring")
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

	cfg, _, err := loadEffectiveConfig(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 1
	}

	prepared, err := a.prepareStart(cfg, startOptions{
		configPath:      *configPath,
		serverName:      selectionOptions.Server,
		configProfile:   selectionOptions.Profile,
		profileSelector: selectionOptions.Selector,
		outputPath:      *outputPath,
		refresh:         *refresh,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 1
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

	started, err := session.Start(cfg.CacheDir, prepared.target, prepared.profile, session.StartOptions{
		Mode:              cfg.NetworkMode(),
		BypassSuffixes:    cfg.BypassSuffixes(),
		InterfaceName:     cfg.TunInterfaceName(),
		TunAddresses:      cfg.TunAddresses(),
		OverlayDNSActive:  prepared.renderOptions.OverlayDNS != nil,
		OverlayDNSDomains: overlayDNSDomains(prepared.renderOptions),
		SystemDNSServers:  systemDNSServers(cfg),
		PrivilegedLaunch:  cfg.LaunchOrDefault(),
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "reconnected sing-box session %s\n", started.ID)
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
	fmt.Fprintf(a.stdout, "mode=%s\n", started.Mode)
	fmt.Fprintf(a.stdout, "launch_mode=%s\n", started.LaunchMode)
	fmt.Fprintf(a.stdout, "config=%s\n", started.ConfigPath)
	fmt.Fprintf(a.stdout, "log=%s\n", started.LogPath)
	fmt.Fprintln(a.stdout, "use `vless-tun status` to inspect state and `vless-tun stop` to stop it")
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
	profile       model.Profile
	target        string
	renderOptions singbox.RenderOptions
}

func (a *App) parseStartOptions(name string, args []string, refreshDefault bool) (startOptions, int, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias; in legacy flat configs this remains a profile selector")
	profileSelector := fs.String("selector", "", "Subscription profile selector by id, name, endpoint, or substring")
	outputPath := fs.String("output", "", "Override render.output_path")
	refresh := fs.Bool("refresh", refreshDefault, "Fetch subscription before rendering and starting")

	if err := fs.Parse(args); err != nil {
		return startOptions{}, 2, err
	}
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
		outputPath:      *outputPath,
		refresh:         *refresh,
	}, 0, nil
}

func (a *App) prepareStart(cfg config.ProjectConfig, options startOptions) (preparedStart, error) {
	snapshot, err := a.loadSnapshot(cfg, options.refresh)
	if err != nil {
		return preparedStart{}, err
	}

	profile, err := subscription.SelectProfile(snapshot.Profiles, cfg.DefaultProfileSelector())
	if err != nil {
		return preparedStart{}, err
	}

	renderOptions := resolveRenderOptions(cfg.NetworkMode())
	data, err := singbox.RenderWithOptions(cfg, profile, renderOptions)
	if err != nil {
		return preparedStart{}, err
	}

	target := cfg.SingboxConfigPath()
	if options.outputPath != "" {
		target = options.outputPath
	}
	if err := singbox.Write(target, data); err != nil {
		return preparedStart{}, err
	}

	return preparedStart{
		profile:       profile,
		target:        target,
		renderOptions: renderOptions,
	}, nil
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
		fmt.Fprintf(out, "%s sing-box session %s (pid=%d)\n", state, stopped.ID, stopped.PID)
	case "stale":
		fmt.Fprintf(out, "cleared stale session %s (pid=%d)\n", stopped.ID, stopped.PID)
	default:
		fmt.Fprintf(out, "stop result=%s for session %s (pid=%d)\n", state, stopped.ID, stopped.PID)
	}
	if stopped.LogPath != "" {
		fmt.Fprintf(out, "log=%s\n", stopped.LogPath)
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
