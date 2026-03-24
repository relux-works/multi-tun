package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"vpn-config/internal/config"
	"vpn-config/internal/model"
	"vpn-config/internal/session"
	"vpn-config/internal/subscription"
)

func (a *App) runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	refresh := fs.Bool("refresh", false, "Fetch subscription before reading status")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}

	snapshot, snapshotErr := a.loadSnapshot(cfg, *refresh)
	current, currentState, sessionAlive, sessionErr := currentSessionState(cfg.CacheDir)
	mode := cfg.Render.ModeOrDefault()
	interfacePresent := false
	var interfaceAddrs []string
	var interfaceErr error
	if mode == config.RenderModeTun {
		interfacePresent, interfaceAddrs, interfaceErr = interfaceState(cfg.Render.InterfaceName)
	}

	connection := deriveConnectionStatus(mode, sessionAlive, interfacePresent)
	renderedPresent := fileExists(cfg.Render.OutputPath)

	fmt.Fprintf(a.stdout, "connection: %s\n", connection)
	fmt.Fprintf(a.stdout, "mode: %s\n", mode)
	fmt.Fprintf(a.stdout, "session: %s\n", currentState)
	if sessionErr != nil {
		fmt.Fprintf(a.stdout, "session_error: %v\n", sessionErr)
	}
	if current != nil {
		fmt.Fprintf(a.stdout, "session_id: %s\n", current.ID)
		fmt.Fprintf(a.stdout, "pid: %d\n", current.PID)
		fmt.Fprintf(a.stdout, "launch_mode: %s\n", current.LaunchMode)
		fmt.Fprintf(a.stdout, "started_at: %s\n", current.StartedAt.Format("2006-01-02T15:04:05Z07:00"))
		fmt.Fprintf(a.stdout, "log_file: %s\n", current.LogPath)
		if current.LaunchMode == config.LaunchModeLaunchd {
			fmt.Fprintf(a.stdout, "launch_label: %s\n", current.LaunchLabel)
		}
	}
	switch mode {
	case config.RenderModeTun:
		fmt.Fprintf(a.stdout, "interface: %s (%s)\n", cfg.Render.InterfaceName, stateLabel(interfacePresent))
		if interfaceErr == nil && len(interfaceAddrs) > 0 {
			fmt.Fprintf(a.stdout, "interface_addrs: %s\n", strings.Join(interfaceAddrs, ", "))
		}
		if interfaceErr != nil && !errors.Is(interfaceErr, errInterfaceNotFound) {
			fmt.Fprintf(a.stdout, "interface_error: %v\n", interfaceErr)
		}
	case config.RenderModeSystemProxy:
		fmt.Fprintf(a.stdout, "proxy_listener: %s:%d\n", cfg.Render.ProxyListenAddress, cfg.Render.ProxyListenPort)
	}
	fmt.Fprintf(a.stdout, "rendered_config: %s (%s)\n", cfg.Render.OutputPath, stateLabel(renderedPresent))
	fmt.Fprintf(a.stdout, "bypasses: %s\n", formatBypasses(cfg.Render.BypassSuffixes))
	if currentState == "stale" && current != nil {
		if last := session.LastRelevantLogLine(current.LogPath); last != "" {
			fmt.Fprintf(a.stdout, "last_log_line: %s\n", last)
		}
	}

	if snapshotErr != nil {
		fmt.Fprintf(a.stdout, "cache: unavailable (%v)\n", snapshotErr)
		return 0
	}

	profile, err := subscription.SelectProfile(snapshot.Profiles, cfg.SelectedProfile)
	if err != nil {
		fmt.Fprintf(a.stdout, "selected_profile: unresolved (%v)\n", err)
	} else {
		fmt.Fprintf(a.stdout, "selected_profile: %s\n", formatProfile(profile))
	}

	fmt.Fprintf(a.stdout, "profiles: %d\n", len(snapshot.Profiles))
	for _, cachedProfile := range snapshot.Profiles {
		fmt.Fprintf(a.stdout, "- %s\n", formatProfile(cachedProfile))
	}

	return 0
}

func currentSessionState(cacheDir string) (*session.CurrentSession, string, bool, error) {
	current, err := session.LoadCurrent(cacheDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "none", false, nil
	}
	if err != nil {
		return nil, "unknown", false, err
	}

	alive, pid, err := session.SessionAlive(current)
	if err != nil {
		return &current, "unknown", false, err
	}
	if pid > 0 {
		current.PID = pid
	}
	if alive {
		return &current, "active", true, nil
	}
	return &current, "stale", false, nil
}

func deriveConnectionStatus(mode string, sessionAlive bool, interfacePresent bool) string {
	if mode == config.RenderModeSystemProxy {
		if sessionAlive {
			return "up"
		}
		return "down"
	}
	switch {
	case sessionAlive && interfacePresent:
		return "up"
	case sessionAlive || interfacePresent:
		return "degraded"
	default:
		return "down"
	}
}

func formatProfile(profile model.Profile) string {
	return fmt.Sprintf("%s | %s | %s | %s", profile.ID, profile.DisplayName(), profile.Endpoint(), profile.Network)
}

func stateLabel(state bool) string {
	if state {
		return "present"
	}
	return "missing"
}

func formatBypasses(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var errInterfaceNotFound = errors.New("interface not found")

func interfaceState(name string) (bool, []string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		if strings.Contains(err.Error(), "no such network interface") {
			return false, nil, errInterfaceNotFound
		}
		return false, nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return true, nil, err
	}

	values := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		values = append(values, addr.String())
	}
	return true, values, nil
}
