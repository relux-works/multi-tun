package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/subscription"
)

var currentSessionStateStatus = currentSessionState

func (a *App) runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	configPath := fs.String("config", "", "Path to config file")
	serverName := fs.String("server", "", "Configured VLESS server name")
	profileName := fs.String("profile", "", "Configured VLESS profile alias; in legacy flat configs this remains a profile selector")
	profileSelector := fs.String("selector", "", "Subscription profile selector by id, name, endpoint, or substring")
	refresh := fs.Bool("refresh", false, "Fetch subscription before reading status")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	explicitSelection := statusSelectionExplicit(*serverName, *profileName, *profileSelector, fs.Args())
	selectionOptions, err := commandServerProfileSelection(*serverName, *profileName, *profileSelector, fs.Args())
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 2
	}
	if !explicitSelection {
		if activeSelection, ok, err := activeStatusSelection(*configPath); err != nil {
			fmt.Fprintf(a.stderr, "status failed: %v\n", err)
			return 1
		} else if ok {
			selectionOptions.Server = activeSelection
		}
	}

	cfg, selection, err := loadEffectiveConfig(*configPath, selectionOptions)
	if err != nil {
		fmt.Fprintf(a.stderr, "status failed: %v\n", err)
		return 1
	}

	snapshot, snapshotErr := a.loadSnapshot(cfg, *refresh)
	launchCfg := cfg.LaunchOrDefault()
	current, currentState, sessionAlive, sessionErr := currentSessionState(cfg.CacheDir, launchCfg)
	mode := cfg.NetworkMode()
	interfacePresent := false
	var interfaceAddrs []string
	var interfaceErr error
	if mode == config.RenderModeTun {
		interfacePresent, interfaceAddrs, interfaceErr = interfaceState(cfg.TunInterfaceName())
	}

	connection := deriveConnectionStatus(sessionAlive, interfacePresent)
	renderedPresent := fileExists(cfg.SingboxConfigPath())
	xrayRenderedPresent := fileExists(cfg.XrayConfigPath())

	fmt.Fprintf(a.stdout, "connection: %s\n", connection)
	fmt.Fprintf(a.stdout, "mode: %s\n", mode)
	fmt.Fprintf(a.stdout, "engine: %s\n", cfg.EngineType())
	if selection.Server != "" {
		fmt.Fprintf(a.stdout, "server: %s\n", selection.Server)
	}
	if selection.Profile != "" {
		fmt.Fprintf(a.stdout, "config_profile: %s\n", selection.Profile)
	}
	fmt.Fprintf(a.stdout, "session: %s\n", currentState)
	if sessionErr != nil {
		fmt.Fprintf(a.stdout, "session_error: %v\n", sessionErr)
	}
	if current != nil {
		if current.ID != "" {
			fmt.Fprintf(a.stdout, "session_id: %s\n", current.ID)
		}
		fmt.Fprintf(a.stdout, "pid: %d\n", current.PID)
		if current.Engine != "" {
			fmt.Fprintf(a.stdout, "session_engine: %s\n", current.Engine)
		}
		fmt.Fprintf(a.stdout, "launch_mode: %s\n", current.LaunchMode)
		if !current.StartedAt.IsZero() {
			fmt.Fprintf(a.stdout, "started_at: %s\n", current.StartedAt.Format("2006-01-02T15:04:05Z07:00"))
		}
		if current.LogPath != "" {
			fmt.Fprintf(a.stdout, "log_file: %s\n", current.LogPath)
		}
		if current.LaunchMode == config.LaunchModeLaunchd {
			fmt.Fprintf(a.stdout, "launch_label: %s\n", current.LaunchLabel)
		}
		for _, sidecar := range current.Sidecars {
			fmt.Fprintf(a.stdout, "sidecar: %s pid=%d (%s)\n", sidecar.Name, sidecar.PID, stateLabel(sidecarAlive(sidecar)))
			if sidecar.LogPath != "" {
				fmt.Fprintf(a.stdout, "sidecar_log: %s\n", sidecar.LogPath)
			}
		}
		if len(current.DNSHandoffServers) > 0 {
			switch current.DNSHandoffMode {
			case "scutil":
				fmt.Fprintf(a.stdout, "dns_handoff: scutil %s -> %s\n", current.DNSHandoffInterface, strings.Join(current.DNSHandoffServers, ", "))
			default:
				if current.DNSHandoffService != "" {
					fmt.Fprintf(a.stdout, "dns_handoff: %s -> %s\n", current.DNSHandoffService, strings.Join(current.DNSHandoffServers, ", "))
				}
			}
			if current.DNSHandoffRestoreAuto {
				fmt.Fprintln(a.stdout, "dns_handoff_restore: automatic")
			} else if len(current.DNSHandoffRestoreServers) > 0 {
				fmt.Fprintf(a.stdout, "dns_handoff_restore: %s\n", strings.Join(current.DNSHandoffRestoreServers, ", "))
			}
		}
	}
	if mode == config.RenderModeTun {
		fmt.Fprintf(a.stdout, "interface: %s (%s)\n", cfg.TunInterfaceName(), stateLabel(interfacePresent))
		if interfaceErr == nil && len(interfaceAddrs) > 0 {
			fmt.Fprintf(a.stdout, "interface_addrs: %s\n", strings.Join(interfaceAddrs, ", "))
		}
		if interfaceErr != nil && !errors.Is(interfaceErr, errInterfaceNotFound) {
			fmt.Fprintf(a.stdout, "interface_error: %v\n", interfaceErr)
		}
	}
	fmt.Fprintf(a.stdout, "rendered_config: %s (%s)\n", cfg.SingboxConfigPath(), stateLabel(renderedPresent))
	if cfg.EngineType() == config.EngineXray || xrayRenderedPresent {
		fmt.Fprintf(a.stdout, "xray_config: %s (%s)\n", cfg.XrayConfigPath(), stateLabel(xrayRenderedPresent))
	}
	fmt.Fprintf(a.stdout, "bypasses: %s\n", formatBypasses(cfg.BypassSuffixes()))
	if currentState == "stale" && current != nil {
		if last := session.LastRelevantLogLine(current.LogPath); last != "" {
			fmt.Fprintf(a.stdout, "last_log_line: %s\n", last)
		}
	}

	if snapshotErr != nil {
		fmt.Fprintf(a.stdout, "cache: unavailable (%v)\n", snapshotErr)
		return 0
	}

	profile, err := subscription.SelectProfile(snapshot.Profiles, cfg.DefaultProfileSelector())
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

func statusSelectionExplicit(serverFlag, profileFlag, selectorFlag string, args []string) bool {
	if strings.TrimSpace(serverFlag) != "" || strings.TrimSpace(profileFlag) != "" || strings.TrimSpace(selectorFlag) != "" {
		return true
	}
	return len(args) > 0
}

func activeStatusSelection(configPath string) (string, bool, error) {
	targets, err := sessionTargetsForConfig(configPath, "")
	if err != nil {
		return "", false, err
	}

	var active string
	for _, target := range targets {
		if strings.TrimSpace(target.label) == "" {
			continue
		}
		_, _, alive, err := currentSessionStateStatus(target.cacheDir, target.launch)
		if err != nil {
			return "", false, err
		}
		if !alive {
			continue
		}
		if active != "" {
			return "", false, nil
		}
		active = target.label
	}
	return active, active != "", nil
}

func sidecarAlive(sidecar session.SidecarSession) bool {
	alive, err := session.ProcessAlive(sidecar.PID)
	return err == nil && alive
}

func currentSessionState(cacheDir string, launch config.PrivilegedLaunchConfig) (*session.CurrentSession, string, bool, error) {
	current, err := session.ResolveCurrent(cacheDir, launch)
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

func deriveConnectionStatus(sessionAlive bool, interfacePresent bool) string {
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
