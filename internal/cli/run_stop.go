package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"multi-tun/internal/config"
	"multi-tun/internal/model"
	"multi-tun/internal/session"
	"multi-tun/internal/singbox"
	"multi-tun/internal/subscription"
)

type startOptions struct {
	configPath      string
	profileSelector string
	outputPath      string
	refresh         bool
}

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

	cfg, err := loadConfig(options.configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}

	if current, state, alive, err := currentSessionState(cfg.CacheDir); err == nil && current != nil && alive {
		fmt.Fprintf(a.stderr, "%s failed: sing-box session %s is already %s (pid=%d)\n", commandName, current.ID, state, current.PID)
		return 1
	}

	prepared, err := a.prepareStart(cfg, options)
	if err != nil {
		fmt.Fprintf(a.stderr, "%s failed: %v\n", commandName, err)
		return 1
	}

	if current, state, alive, err := currentSessionState(cfg.CacheDir); err == nil && current != nil && !alive {
		_ = session.ClearCurrent(cfg.CacheDir)
	} else if err == nil && current != nil && alive {
		fmt.Fprintf(a.stderr, "%s failed: sing-box session %s is already %s (pid=%d)\n", commandName, current.ID, state, current.PID)
		return 1
	}

	started, err := session.Start(cfg.CacheDir, prepared.target, prepared.profile, session.StartOptions{
		Mode:             cfg.Render.ModeOrDefault(),
		BypassSuffixes:   cfg.Render.BypassSuffixes,
		TunAddresses:     append([]string(nil), cfg.Render.TunAddresses...),
		OverlayDNSActive: prepared.renderOptions.OverlayDNS != nil,
		PrivilegedLaunch: cfg.Render.PrivilegedLaunchOrDefault(),
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
	profileSelector := fs.String("profile", "", "Profile selector by id, name, or substring")
	outputPath := fs.String("output", "", "Override render.output_path")
	refresh := fs.Bool("refresh", true, "Fetch subscription before rendering and reconnecting")
	force := fs.Bool("force", false, "Escalate from SIGTERM to SIGKILL if sing-box does not stop in time")
	timeout := fs.Duration("timeout", 5*time.Second, "How long to wait after SIGTERM before failing or forcing")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 1
	}

	prepared, err := a.prepareStart(cfg, startOptions{
		configPath:      *configPath,
		profileSelector: *profileSelector,
		outputPath:      *outputPath,
		refresh:         *refresh,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 1
	}

	stopped, state, err := stopCurrentSession(cfg.CacheDir, *force, *timeout)
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		if stopped != nil && stopped.LogPath != "" {
			fmt.Fprintf(a.stderr, "log=%s\n", stopped.LogPath)
		}
		return 1
	}

	started, err := session.Start(cfg.CacheDir, prepared.target, prepared.profile, session.StartOptions{
		Mode:             cfg.Render.ModeOrDefault(),
		BypassSuffixes:   cfg.Render.BypassSuffixes,
		TunAddresses:     append([]string(nil), cfg.Render.TunAddresses...),
		OverlayDNSActive: prepared.renderOptions.OverlayDNS != nil,
		PrivilegedLaunch: cfg.Render.PrivilegedLaunchOrDefault(),
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "reconnect failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "reconnected sing-box session %s\n", started.ID)
	if stopped != nil {
		fmt.Fprintf(a.stdout, "previous_session: %s (%s)\n", stopped.ID, state)
	} else {
		fmt.Fprintln(a.stdout, "previous_session: none")
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
	force := fs.Bool("force", false, "Escalate from SIGTERM to SIGKILL if sing-box does not stop in time")
	timeout := fs.Duration("timeout", 5*time.Second, "How long to wait after SIGTERM before failing or forcing")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		return 1
	}

	stopped, state, err := stopCurrentSession(cfg.CacheDir, *force, *timeout)
	if err != nil {
		fmt.Fprintf(a.stderr, "stop failed: %v\n", err)
		if stopped != nil && stopped.LogPath != "" {
			fmt.Fprintf(a.stderr, "log=%s\n", stopped.LogPath)
		}
		return 1
	}
	if stopped == nil {
		fmt.Fprintln(a.stdout, "no current session file found")
		return 0
	}

	switch state {
	case "stopped", "killed":
		fmt.Fprintf(a.stdout, "%s sing-box session %s (pid=%d)\n", state, stopped.ID, stopped.PID)
	case "stale":
		fmt.Fprintf(a.stdout, "cleared stale session %s (pid=%d)\n", stopped.ID, stopped.PID)
	default:
		fmt.Fprintf(a.stdout, "stop result=%s for session %s (pid=%d)\n", state, stopped.ID, stopped.PID)
	}
	fmt.Fprintf(a.stdout, "log=%s\n", stopped.LogPath)
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
	profileSelector := fs.String("profile", "", "Profile selector by id, name, or substring")
	outputPath := fs.String("output", "", "Override render.output_path")
	refresh := fs.Bool("refresh", refreshDefault, "Fetch subscription before rendering and starting")

	if err := fs.Parse(args); err != nil {
		return startOptions{}, 2, err
	}

	return startOptions{
		configPath:      *configPath,
		profileSelector: *profileSelector,
		outputPath:      *outputPath,
		refresh:         *refresh,
	}, 0, nil
}

func (a *App) prepareStart(cfg config.ProjectConfig, options startOptions) (preparedStart, error) {
	snapshot, err := a.loadSnapshot(cfg, options.refresh)
	if err != nil {
		return preparedStart{}, err
	}

	selector := options.profileSelector
	if selector == "" {
		selector = cfg.SelectedProfile
	}
	profile, err := subscription.SelectProfile(snapshot.Profiles, selector)
	if err != nil {
		return preparedStart{}, err
	}

	renderOptions := resolveRenderOptions(cfg.Render.ModeOrDefault())
	data, err := singbox.RenderWithOptions(cfg, profile, renderOptions)
	if err != nil {
		return preparedStart{}, err
	}

	target := cfg.Render.OutputPath
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

func stopCurrentSession(cacheDir string, force bool, timeout time.Duration) (*session.CurrentSession, string, error) {
	stopped, state, err := session.Stop(cacheDir, force, timeout)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "none", nil
	}
	if err != nil {
		return &stopped, state, err
	}
	return &stopped, state, nil
}
