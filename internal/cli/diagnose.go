package cli

import (
	"flag"
	"fmt"

	"multi-tun/internal/config"
	"multi-tun/internal/session"
	"multi-tun/internal/vpncore"
)

func (a *App) runDiagnose(args []string) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "diagnose failed: %v\n", err)
		return 1
	}

	launchCfg := cfg.Render.PrivilegedLaunchOrDefault()
	fmt.Fprintf(a.stdout, "mode: %s\n", cfg.Render.ModeOrDefault())
	fmt.Fprintf(a.stdout, "configured_launch_mode: %s\n", launchCfg.Mode)
	if launchCfg.Mode == config.LaunchModeHelper || launchCfg.Mode == config.LaunchModeLaunchd {
		coreCfg := vpncore.DefaultServiceConfig()
		fmt.Fprintf(a.stdout, "vpn_core_label: %s\n", coreCfg.Label)
		fmt.Fprintf(a.stdout, "vpn_core_plist: %s\n", coreCfg.PlistPath)
		fmt.Fprintf(a.stdout, "vpn_core_socket: %s\n", coreCfg.SocketPath)
	} else {
		fmt.Fprintf(a.stdout, "launch_label: %s\n", launchCfg.Label)
		fmt.Fprintf(a.stdout, "launch_plist: %s\n", launchCfg.PlistPath)
	}

	current, currentState, alive, currentErr := currentSessionState(cfg.CacheDir)
	fmt.Fprintf(a.stdout, "session: %s\n", currentState)
	if currentErr != nil {
		fmt.Fprintf(a.stdout, "session_error: %v\n", currentErr)
	}
	if current != nil {
		fmt.Fprintf(a.stdout, "session_id: %s\n", current.ID)
		fmt.Fprintf(a.stdout, "session_launch_mode: %s\n", current.LaunchMode)
		fmt.Fprintf(a.stdout, "pid: %d\n", current.PID)
		fmt.Fprintf(a.stdout, "log_file: %s\n", current.LogPath)
	}

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

	if current != nil && !alive && current.LogPath != "" {
		if last := session.LastRelevantLogLine(current.LogPath); last != "" {
			fmt.Fprintf(a.stdout, "last_log_line: %s\n", last)
		}
	}

	return 0
}
