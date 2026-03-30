package session

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"

	"multi-tun/internal/config"
	"multi-tun/internal/vpncore"
)

const (
	networksetupPath = "/usr/sbin/networksetup"
	routePath        = "/sbin/route"
)

var (
	defaultRouteGetSession = func() ([]byte, error) {
		return execCommand(routePath, "-n", "get", "default").CombinedOutput()
	}
	networkServiceOrderSession = func() ([]byte, error) {
		return execCommand(networksetupPath, "-listnetworkserviceorder").CombinedOutput()
	}
	networkDNSServersSession = func(service string) ([]byte, error) {
		return execCommand(networksetupPath, "-getdnsservers", service).CombinedOutput()
	}
	setDNSServersPrivilegedSession = func(launchMode, logPath, service string, servers []string) error {
		args := []string{"-setdnsservers", service}
		if len(servers) == 0 {
			args = append(args, "Empty")
		} else {
			args = append(args, servers...)
		}
		return runPrivilegedLoggedCommand(launchMode, logPath, append([]string{networksetupPath}, args...))
	}
)

var (
	defaultInterfacePattern     = regexp.MustCompile(`(?m)^\s*interface:\s+(\S+)\s*$`)
	networkServiceNamePattern   = regexp.MustCompile(`^\((?:\d+|\*)\)\s+(.+)$`)
	networkServiceDevicePattern = regexp.MustCompile(`^\(Hardware Port: .*?, Device: ([^)]+)\)$`)
)

func applySystemDNSHandoff(current *CurrentSession, options StartOptions) error {
	if !shouldApplySystemDNSHandoff(current.Mode, options) {
		return nil
	}

	dnsServer, err := tunnelDNSServer(options.TunAddresses)
	if err != nil {
		return err
	}

	device, err := currentDefaultInterface()
	if err != nil {
		return err
	}

	service, err := currentNetworkService(device)
	if err != nil {
		return err
	}

	restoreServers, restoreAuto, err := currentDNSServers(service)
	if err != nil {
		return err
	}

	appendSessionLog(current.LogPath, "dns_handoff_apply_begin service=%s target=%s restore=%s\n", service, dnsServer, formatRestoreServers(restoreServers, restoreAuto))
	if err := setDNSServersPrivilegedSession(current.LaunchMode, current.LogPath, service, []string{dnsServer}); err != nil {
		appendSessionLog(current.LogPath, "dns_handoff_apply_failed service=%s target=%s err=%v\n", service, dnsServer, err)
		return err
	}
	appendSessionLog(current.LogPath, "dns_handoff_apply_ok service=%s target=%s\n", service, dnsServer)

	current.DNSHandoffService = service
	current.DNSHandoffServer = dnsServer
	current.DNSHandoffRestoreServers = append([]string(nil), restoreServers...)
	current.DNSHandoffRestoreAuto = restoreAuto
	return nil
}

func restoreSystemDNSHandoff(current CurrentSession) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if strings.TrimSpace(current.DNSHandoffService) == "" || strings.TrimSpace(current.DNSHandoffServer) == "" {
		return nil
	}

	appendSessionLog(current.LogPath, "dns_handoff_restore_begin service=%s restore=%s\n", current.DNSHandoffService, formatRestoreServers(current.DNSHandoffRestoreServers, current.DNSHandoffRestoreAuto))
	servers := append([]string(nil), current.DNSHandoffRestoreServers...)
	if current.DNSHandoffRestoreAuto {
		servers = nil
	}
	if err := setDNSServersPrivilegedSession(current.LaunchMode, current.LogPath, current.DNSHandoffService, servers); err != nil {
		appendSessionLog(current.LogPath, "dns_handoff_restore_failed service=%s err=%v\n", current.DNSHandoffService, err)
		return err
	}
	appendSessionLog(current.LogPath, "dns_handoff_restore_ok service=%s\n", current.DNSHandoffService)
	return nil
}

func shouldApplySystemDNSHandoff(mode string, options StartOptions) bool {
	if os.Getenv("VLESS_TUN_ENABLE_DNS_HANDOFF") != "1" {
		return false
	}
	return runtime.GOOS == "darwin" && mode == config.RenderModeTun && options.OverlayDNSActive
}

func tunnelDNSServer(tunAddresses []string) (string, error) {
	for _, address := range tunAddresses {
		host := strings.TrimSpace(address)
		if host == "" {
			continue
		}
		if strings.Contains(host, "/") {
			ip, _, err := net.ParseCIDR(host)
			if err == nil && ip != nil && ip.To4() != nil {
				return ip.String(), nil
			}
			continue
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 tun address available for DNS handoff")
}

func currentDefaultInterface() (string, error) {
	out, err := defaultRouteGetSession()
	if err != nil {
		return "", fmt.Errorf("route default lookup: %w", err)
	}
	return parseDefaultInterface(string(out))
}

func currentNetworkService(device string) (string, error) {
	out, err := networkServiceOrderSession()
	if err != nil {
		return "", fmt.Errorf("network service order: %w", err)
	}
	return parseNetworkServiceOrder(string(out), device)
}

func currentDNSServers(service string) ([]string, bool, error) {
	out, err := networkDNSServersSession(service)
	if err != nil {
		return nil, false, fmt.Errorf("get dns servers for %s: %w", service, err)
	}
	return parseDNSServers(string(out), service)
}

func parseDefaultInterface(output string) (string, error) {
	matches := defaultInterfacePattern.FindStringSubmatch(output)
	if len(matches) != 2 {
		return "", fmt.Errorf("default interface not found in route output")
	}
	return strings.TrimSpace(matches[1]), nil
}

func parseNetworkServiceOrder(output, device string) (string, error) {
	device = strings.TrimSpace(device)
	if device == "" {
		return "", fmt.Errorf("network device is required")
	}

	var currentService string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if matches := networkServiceNamePattern.FindStringSubmatch(line); len(matches) == 2 {
			currentService = strings.TrimSpace(matches[1])
			continue
		}
		if matches := networkServiceDevicePattern.FindStringSubmatch(line); len(matches) == 2 && currentService != "" {
			if strings.TrimSpace(matches[1]) == device {
				return currentService, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan network service order: %w", err)
	}
	return "", fmt.Errorf("network service for device %s not found", device)
}

func parseDNSServers(output, service string) ([]string, bool, error) {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("scan dns servers for %s: %w", service, err)
	}
	if len(lines) == 0 {
		return nil, true, nil
	}
	if strings.Contains(lines[0], "There aren't any DNS Servers set on") {
		return nil, true, nil
	}
	return lines, false, nil
}

func runPrivilegedLoggedCommand(launchMode, logPath string, command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("missing privileged command")
	}

	switch launchMode {
	case config.LaunchModeHelper:
		return vpncore.Run(vpncore.DefaultServiceConfig(), append([]string(nil), command...), "", logPath)
	case config.LaunchModeDirect:
		return runLoggedCommand(command, logPath)
	case config.LaunchModeSudo:
		if err := ensureSudo(); err != nil {
			return fmt.Errorf("sudo authentication: %w", err)
		}
		return runLoggedCommand(append([]string{"sudo"}, command...), logPath)
	default:
		return fmt.Errorf("system DNS handoff is unsupported for launch mode %q", launchMode)
	}
}

func runLoggedCommand(command []string, logPath string) error {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	cmd := execCommand(command[0], command[1:]...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	return cmd.Run()
}

func appendSessionLog(path, format string, args ...any) {
	if strings.TrimSpace(path) == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, format, args...)
}

func formatRestoreServers(servers []string, automatic bool) string {
	if automatic {
		return "automatic"
	}
	if len(servers) == 0 {
		return "none"
	}
	return strings.Join(servers, ",")
}
