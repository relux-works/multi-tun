package cli

import (
	"flag"
	"fmt"

	"vpn-config/internal/config"
	"vpn-config/internal/session"
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
	fmt.Fprintf(a.stdout, "launch_label: %s\n", launchCfg.Label)
	fmt.Fprintf(a.stdout, "launch_plist: %s\n", launchCfg.PlistPath)

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

	if launchCfg.Mode != config.LaunchModeLaunchd {
		fmt.Fprintln(a.stdout, "launchd_service: not_configured")
		return 0
	}

	status, err := session.InspectLaunchd(launchCfg.Label)
	if err != nil {
		fmt.Fprintf(a.stderr, "diagnose failed: %v\n", err)
		return 1
	}
	if !status.Found {
		fmt.Fprintln(a.stdout, "launchd_service: missing")
		return 0
	}

	state := status.State
	if state == "" {
		state = "unknown"
	}
	fmt.Fprintf(a.stdout, "launchd_service: %s\n", state)
	fmt.Fprintf(a.stdout, "launchd_pid: %d\n", status.PID)

	if current != nil && !alive && current.LogPath != "" {
		if last := session.LastRelevantLogLine(current.LogPath); last != "" {
			fmt.Fprintf(a.stdout, "last_log_line: %s\n", last)
		}
	}

	return 0
}
