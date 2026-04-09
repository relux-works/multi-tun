package openconnect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const cmdTimeout = 5 * time.Second

var (
	vpnBinaryCandidates = []string{
		"/opt/cisco/secureclient/bin/vpn",
		"/opt/cisco/anyconnect/bin/vpn",
	}
	pathStat   = os.Stat
	runCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}

	stateRegex = regexp.MustCompile(`>>\s*state:\s*(.+)`)
	hostsRegex = regexp.MustCompile(`>+\s*\d+\.\s*(.+)`)
)

type State string

const (
	StateConnected    State = "connected"
	StateDisconnected State = "disconnected"
	StateNotInstalled State = "not_installed"
	StateUnknown      State = "unknown"
)

type ConnectionInfo struct {
	State      State
	ServerAddr string
	Duration   string
	ClientAddr string
	TunnelMode string
	BytesSent  string
	BytesRecv  string
}

type CLIProfile struct {
	Name string
}

func ResolveVPNBinary() (string, error) {
	for _, candidate := range vpnBinaryCandidates {
		if _, err := pathStat(candidate); err == nil {
			return candidate, nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("checking %s: %w", candidate, err)
		}
	}
	return "", nil
}

func DetectState() (State, string, error) {
	vpnBinary, err := ResolveVPNBinary()
	if err != nil {
		return StateUnknown, "", err
	}
	if vpnBinary == "" {
		return StateNotInstalled, "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := runCommand(ctx, vpnBinary, "state")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StateUnknown, vpnBinary, fmt.Errorf("vpn state timed out after %s", cmdTimeout)
		}
		return StateUnknown, vpnBinary, fmt.Errorf("running vpn state: %w", err)
	}

	return parseState(string(out)), vpnBinary, nil
}

func GetConnectionInfo() (*ConnectionInfo, string, error) {
	vpnBinary, err := ResolveVPNBinary()
	if err != nil {
		return nil, "", err
	}
	if vpnBinary == "" {
		return nil, "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := runCommand(ctx, vpnBinary, "stats")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, vpnBinary, fmt.Errorf("vpn stats timed out after %s", cmdTimeout)
		}
		if len(out) == 0 {
			return nil, vpnBinary, fmt.Errorf("running vpn stats: %w", err)
		}
	}

	return parseStats(string(out)), vpnBinary, nil
}

func ListProfiles() ([]CLIProfile, string, error) {
	vpnBinary, err := ResolveVPNBinary()
	if err != nil {
		return nil, "", err
	}
	if vpnBinary == "" {
		return nil, "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := runCommand(ctx, vpnBinary, "hosts")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, vpnBinary, fmt.Errorf("vpn hosts timed out after %s", cmdTimeout)
		}
		if len(out) == 0 {
			return nil, vpnBinary, fmt.Errorf("running vpn hosts: %w", err)
		}
	}

	return parseHosts(string(out)), vpnBinary, nil
}

func parseState(output string) State {
	match := stateRegex.FindStringSubmatch(output)
	if match == nil {
		return StateUnknown
	}

	switch strings.TrimSpace(strings.ToLower(match[1])) {
	case "connected", "reconnecting":
		return StateConnected
	case "disconnected", "connecting":
		return StateDisconnected
	default:
		return StateUnknown
	}
}

func parseStats(output string) *ConnectionInfo {
	info := &ConnectionInfo{}
	kv := parseKeyValue(output)

	switch strings.ToLower(kv["connection state"]) {
	case "connected":
		info.State = StateConnected
	case "disconnected":
		info.State = StateDisconnected
	default:
		info.State = StateUnknown
	}

	info.ServerAddr = kv["server address"]
	info.ClientAddr = kv["client address (ipv4)"]
	info.TunnelMode = kv["tunnel mode (ipv4)"]
	info.Duration = kv["duration"]
	info.BytesSent = kv["bytes sent"]
	info.BytesRecv = kv["bytes received"]
	return info
}

func parseKeyValue(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key != "" && value != "" && value != "Not Available" {
			result[strings.ToLower(key)] = value
		}
	}
	return result
}

func parseHosts(output string) []CLIProfile {
	profiles := []CLIProfile{}
	for _, line := range strings.Split(output, "\n") {
		match := hostsRegex.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		profiles = append(profiles, CLIProfile{Name: name})
	}
	return profiles
}
