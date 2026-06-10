package cli

import (
	"flag"
	"fmt"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
)

func (a *App) runDiagnose(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "config":
			return a.runDiagnoseConfig(args[1:])
		case "tunnel":
			return a.runDiagnoseTunnel(args[1:])
		}
	}
	return a.runDiagnoseTunnel(args)
}

func (a *App) runDiagnoseTunnel(args []string) int {
	fs := flag.NewFlagSet("diagnose tunnel", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(a.stderr, "diagnose failed: unexpected argument %q; use `vless-tun diagnose config [server [profile]]` for config selection checks\n", fs.Args()[0])
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "diagnose failed: %v\n", err)
		return 1
	}
	targets, err := sessionTargetsForConfig(*configPath, "")
	if err != nil {
		fmt.Fprintf(a.stderr, "diagnose failed: %v\n", err)
		return 1
	}

	launchCfg := cfg.LaunchOrDefault()
	fmt.Fprintf(a.stdout, "diagnostic: tunnel\n")
	fmt.Fprintf(a.stdout, "mode: %s\n", cfg.NetworkMode())
	fmt.Fprintf(a.stdout, "engine: %s\n", cfg.EngineType())
	fmt.Fprintf(a.stdout, "logging_level: %s\n", cfg.LogLevel())
	fmt.Fprintf(a.stdout, "logging_max_lines: %d\n", cfg.LogMaxLines())
	printConfiguredLaunch(a.stdout, launchCfg)

	for _, target := range targets {
		if target.label != "" {
			fmt.Fprintf(a.stdout, "server: %s\n", target.label)
		}
		current, currentState, alive, currentErr := currentSessionState(target.cacheDir, target.launch)
		fmt.Fprintf(a.stdout, "session: %s\n", currentState)
		if currentErr != nil {
			fmt.Fprintf(a.stdout, "session_error: %v\n", currentErr)
		}
		printCurrentSession(a.stdout, current)
		if current != nil && !alive && current.LogPath != "" {
			if last := session.LastRelevantLogLine(current.LogPath); last != "" {
				fmt.Fprintf(a.stdout, "last_log_line: %s\n", last)
			}
		}
	}

	return a.printVPNCoreDiagnostics(launchCfg)
}

func (a *App) runDiagnoseConfig(args []string) int {
	fs := flag.NewFlagSet("diagnose config", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias")
	profileSelector := fs.String("selector", "", "Subscription profile selector by id, name, endpoint, or substring")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	selectionOptions, err := commandServerProfileSelection(*serverName, *profileName, *profileSelector, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "diagnose config failed: %v\n", err)
		return 2
	}
	selectionOptions.AllowMissingProfile = true

	cfg, selection, err := loadEffectiveConfig(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "diagnose config failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "diagnostic: config\n")
	fmt.Fprintf(a.stdout, "mode: %s\n", cfg.NetworkMode())
	if selection.Server != "" {
		fmt.Fprintf(a.stdout, "server: %s\n", selection.Server)
	}
	if selection.Profile != "" {
		fmt.Fprintf(a.stdout, "config_profile: %s\n", selection.Profile)
	}
	if selection.Selector != "" {
		fmt.Fprintf(a.stdout, "profile_selector: %s\n", selection.Selector)
	}
	fmt.Fprintf(a.stdout, "source_mode: %s\n", cfg.SourceMode())
	fmt.Fprintf(a.stdout, "cache_dir: %s\n", cfg.CacheDir)
	fmt.Fprintf(a.stdout, "engine: %s\n", cfg.EngineType())
	fmt.Fprintf(a.stdout, "logging_level: %s\n", cfg.LogLevel())
	fmt.Fprintf(a.stdout, "logging_max_lines: %d\n", cfg.LogMaxLines())
	fmt.Fprintf(a.stdout, "rendered_config: %s (%s)\n", cfg.SingboxConfigPath(), stateLabel(fileExists(cfg.SingboxConfigPath())))
	if cfg.EngineType() == config.EngineXray || fileExists(cfg.XrayConfigPath()) {
		fmt.Fprintf(a.stdout, "xray_config: %s (%s)\n", cfg.XrayConfigPath(), stateLabel(fileExists(cfg.XrayConfigPath())))
		fmt.Fprintf(a.stdout, "xray_executable: %s\n", cfg.XrayExecutable())
		fmt.Fprintf(a.stdout, "xray_socks: %s:%d\n", cfg.XraySocksListen(), cfg.XraySocksPort())
	}
	fmt.Fprintf(a.stdout, "bypasses: %s\n", formatBypasses(cfg.BypassSuffixes()))
	printConfiguredLaunch(a.stdout, cfg.LaunchOrDefault())
	return 0
}

func printConfiguredLaunch(out interface{ Write([]byte) (int, error) }, launchCfg config.PrivilegedLaunchConfig) {
	fmt.Fprintf(out, "configured_launch_mode: %s\n", launchCfg.Mode)
	if launchCfg.Mode == config.LaunchModeHelper || launchCfg.Mode == config.LaunchModeLaunchd {
		coreCfg := vpncore.DefaultServiceConfig()
		fmt.Fprintf(out, "vpn_core_label: %s\n", coreCfg.Label)
		fmt.Fprintf(out, "vpn_core_plist: %s\n", coreCfg.PlistPath)
		fmt.Fprintf(out, "vpn_core_socket: %s\n", coreCfg.SocketPath)
	} else {
		fmt.Fprintf(out, "launch_label: %s\n", launchCfg.Label)
		fmt.Fprintf(out, "launch_plist: %s\n", launchCfg.PlistPath)
	}
}

func printCurrentSession(out interface{ Write([]byte) (int, error) }, current *session.CurrentSession) {
	if current == nil {
		return
	}
	if current.ID != "" {
		fmt.Fprintf(out, "session_id: %s\n", current.ID)
	}
	fmt.Fprintf(out, "session_launch_mode: %s\n", current.LaunchMode)
	fmt.Fprintf(out, "pid: %d\n", current.PID)
	if current.Engine != "" {
		fmt.Fprintf(out, "session_engine: %s\n", current.Engine)
	}
	if current.LogPath != "" {
		fmt.Fprintf(out, "log_file: %s\n", current.LogPath)
	}
	if current.LogMaxLines > 0 {
		fmt.Fprintf(out, "log_max_lines: %d\n", current.LogMaxLines)
	}
	for _, sidecar := range current.Sidecars {
		fmt.Fprintf(out, "sidecar: %s pid=%d log=%s\n", sidecar.Name, sidecar.PID, sidecar.LogPath)
	}
}

func (a *App) printVPNCoreDiagnostics(launchCfg config.PrivilegedLaunchConfig) int {
	if launchCfg.Mode != config.LaunchModeLaunchd && launchCfg.Mode != config.LaunchModeHelper {
		fmt.Fprintln(a.stdout, "vpn_core: not_configured")
		return 0
	}

	status, err := vpncore.InspectService(vpncore.DefaultServiceConfig())
	if err != nil {
		fmt.Fprintf(a.stderr, "diagnose failed: %v\n", err)
		return 1
	}
	if !status.Reachable {
		fmt.Fprintln(a.stdout, "vpn_core: missing")
		return 0
	}
	fmt.Fprintln(a.stdout, "vpn_core: reachable")
	fmt.Fprintf(a.stdout, "vpn_core_label: %s\n", status.Label)
	fmt.Fprintf(a.stdout, "vpn_core_socket: %s\n", status.SocketPath)
	fmt.Fprintf(a.stdout, "vpn_core_pid: %d\n", status.DaemonPID)
	if status.Compatibility != "" {
		fmt.Fprintf(a.stdout, "vpn_core_compatibility: %s\n", status.Compatibility)
	}
	return 0
}
