package session

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
)

const (
	networksetupPath       = "/usr/sbin/networksetup"
	routePath              = "/sbin/route"
	scutilPath             = "/usr/sbin/scutil"
	dnsHandoffModeScutil   = "scutil"
	dnsHandoffModeFallback = "networksetup"
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
	runScutilPrivilegedSession = func(launchMode, logPath, stdinData string) error {
		return runPrivilegedLoggedCommandWithInput(launchMode, logPath, []string{scutilPath}, stdinData)
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

	dnsServers := normalizeDNSServerList(options.SystemDNSServers)
	if len(dnsServers) == 0 {
		return fmt.Errorf("no system DNS servers configured for overlay handoff")
	}

	if err := applyScutilDNSHandoff(current, options, dnsServers); err == nil {
		return nil
	} else {
		appendSessionLog(current.LogPath, "dns_handoff_scutil_failed interface=%s err=%v\n", strings.TrimSpace(options.InterfaceName), err)
	}

	return applyNetworkServiceDNSHandoff(current, dnsServers)
}

func applyScutilDNSHandoff(current *CurrentSession, options StartOptions, dnsServers []string) error {
	interfaceName := strings.TrimSpace(options.InterfaceName)
	if interfaceName == "" {
		return fmt.Errorf("missing tun interface name")
	}
	tunnelIPv4 := firstTunnelIPv4Address(options.TunAddresses)
	if tunnelIPv4 == "" {
		return fmt.Errorf("missing tun IPv4 address")
	}
	searchDomains := normalizeDNSDomainList(options.OverlayDNSDomains)
	if len(searchDomains) == 0 {
		return fmt.Errorf("missing overlay DNS domains")
	}

	serviceID := dnsHandoffServiceID(current.ID)
	stdinData := buildScutilApplyInput(serviceID, interfaceName, tunnelIPv4, dnsServers, searchDomains)
	appendSessionLog(current.LogPath, "dns_handoff_apply_begin method=%s interface=%s target=%s search=%s\n", dnsHandoffModeScutil, interfaceName, strings.Join(dnsServers, ","), strings.Join(searchDomains, ","))
	if err := runScutilPrivilegedSession(current.LaunchMode, current.LogPath, stdinData); err != nil {
		appendSessionLog(current.LogPath, "dns_handoff_apply_failed method=%s interface=%s err=%v\n", dnsHandoffModeScutil, interfaceName, err)
		return err
	}
	appendSessionLog(current.LogPath, "dns_handoff_apply_ok method=%s interface=%s service_id=%s target=%s\n", dnsHandoffModeScutil, interfaceName, serviceID, strings.Join(dnsServers, ","))

	current.DNSHandoffMode = dnsHandoffModeScutil
	current.DNSHandoffService = ""
	current.DNSHandoffServiceID = serviceID
	current.DNSHandoffInterface = interfaceName
	current.DNSHandoffServers = append([]string(nil), dnsServers...)
	current.DNSHandoffRestoreServers = nil
	current.DNSHandoffRestoreAuto = false
	return nil
}

func applyNetworkServiceDNSHandoff(current *CurrentSession, dnsServers []string) error {
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

	appendSessionLog(current.LogPath, "dns_handoff_apply_begin method=%s service=%s target=%s restore=%s\n", dnsHandoffModeFallback, service, strings.Join(dnsServers, ","), formatRestoreServers(restoreServers, restoreAuto))
	if err := setDNSServersPrivilegedSession(current.LaunchMode, current.LogPath, service, dnsServers); err != nil {
		appendSessionLog(current.LogPath, "dns_handoff_apply_failed method=%s service=%s target=%s err=%v\n", dnsHandoffModeFallback, service, strings.Join(dnsServers, ","), err)
		return err
	}
	appendSessionLog(current.LogPath, "dns_handoff_apply_ok method=%s service=%s target=%s\n", dnsHandoffModeFallback, service, strings.Join(dnsServers, ","))

	current.DNSHandoffMode = dnsHandoffModeFallback
	current.DNSHandoffService = service
	current.DNSHandoffServiceID = ""
	current.DNSHandoffInterface = ""
	current.DNSHandoffServers = append([]string(nil), dnsServers...)
	current.DNSHandoffRestoreServers = append([]string(nil), restoreServers...)
	current.DNSHandoffRestoreAuto = restoreAuto
	return nil
}

func restoreSystemDNSHandoff(current CurrentSession) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if len(current.DNSHandoffServers) == 0 {
		return nil
	}

	switch {
	case current.DNSHandoffMode == dnsHandoffModeScutil || strings.TrimSpace(current.DNSHandoffServiceID) != "":
		serviceID := strings.TrimSpace(current.DNSHandoffServiceID)
		if serviceID == "" {
			return nil
		}
		appendSessionLog(current.LogPath, "dns_handoff_restore_begin method=%s interface=%s service_id=%s\n", dnsHandoffModeScutil, current.DNSHandoffInterface, serviceID)
		if err := runScutilPrivilegedSession(current.LaunchMode, current.LogPath, buildScutilRemoveInput(serviceID)); err != nil {
			appendSessionLog(current.LogPath, "dns_handoff_restore_failed method=%s service_id=%s err=%v\n", dnsHandoffModeScutil, serviceID, err)
			return err
		}
		appendSessionLog(current.LogPath, "dns_handoff_restore_ok method=%s service_id=%s\n", dnsHandoffModeScutil, serviceID)
		return nil
	case strings.TrimSpace(current.DNSHandoffService) != "":
		appendSessionLog(current.LogPath, "dns_handoff_restore_begin method=%s service=%s restore=%s\n", dnsHandoffModeFallback, current.DNSHandoffService, formatRestoreServers(current.DNSHandoffRestoreServers, current.DNSHandoffRestoreAuto))
		servers := append([]string(nil), current.DNSHandoffRestoreServers...)
		if current.DNSHandoffRestoreAuto {
			servers = nil
		}
		if err := setDNSServersPrivilegedSession(current.LaunchMode, current.LogPath, current.DNSHandoffService, servers); err != nil {
			appendSessionLog(current.LogPath, "dns_handoff_restore_failed method=%s service=%s err=%v\n", dnsHandoffModeFallback, current.DNSHandoffService, err)
			return err
		}
		appendSessionLog(current.LogPath, "dns_handoff_restore_ok method=%s service=%s\n", dnsHandoffModeFallback, current.DNSHandoffService)
		return nil
	default:
		return nil
	}
}

func shouldApplySystemDNSHandoff(mode string, options StartOptions) bool {
	if os.Getenv("VLESS_TUN_ENABLE_DNS_HANDOFF") == "0" {
		return false
	}
	return runtime.GOOS == "darwin" && mode == config.RenderModeTun && options.OverlayDNSActive && len(normalizeDNSServerList(options.SystemDNSServers)) > 0
}

func normalizeDNSServerList(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			continue
		}
		value = ip.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeDNSDomainList(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
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

func firstTunnelIPv4Address(addresses []string) string {
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		host := address
		if idx := strings.Index(host, "/"); idx >= 0 {
			host = host[:idx]
		}
		ip := net.ParseIP(strings.TrimSpace(host))
		if ip == nil || ip.To4() == nil {
			continue
		}
		return ip.String()
	}
	return ""
}

func dnsHandoffServiceID(sessionID string) string {
	sum := sha1.Sum([]byte("vless-tun:dns-handoff:" + strings.TrimSpace(sessionID)))
	token := strings.ToUpper(hex.EncodeToString(sum[:16]))
	return fmt.Sprintf("%s-%s-%s-%s-%s", token[0:8], token[8:12], token[12:16], token[16:20], token[20:32])
}

func buildScutilApplyInput(serviceID, interfaceName, tunnelIPv4 string, dnsServers, searchDomains []string) string {
	var b strings.Builder
	b.WriteString("d.init\n")
	fmt.Fprintf(&b, "d.add ConfirmedServiceID %s\n", serviceID)
	fmt.Fprintf(&b, "d.add InterfaceName %s\n", interfaceName)
	if len(searchDomains) > 0 {
		fmt.Fprintf(&b, "d.add DomainName %s\n", searchDomains[0])
		b.WriteString("d.add SearchDomains *")
		for _, domain := range searchDomains {
			fmt.Fprintf(&b, " %s", domain)
		}
		b.WriteString("\n")
	}
	b.WriteString("d.add ServerAddresses *")
	for _, server := range dnsServers {
		fmt.Fprintf(&b, " %s", server)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "set State:/Network/Service/%s/DNS\n", serviceID)
	if tunnelIPv4 != "" {
		b.WriteString("d.init\n")
		fmt.Fprintf(&b, "d.add Addresses * %s\n", tunnelIPv4)
		fmt.Fprintf(&b, "d.add InterfaceName %s\n", interfaceName)
		fmt.Fprintf(&b, "d.add Router %s\n", tunnelIPv4)
		fmt.Fprintf(&b, "set State:/Network/Service/%s/IPv4\n", serviceID)
	}
	return b.String()
}

func buildScutilRemoveInput(serviceID string) string {
	return fmt.Sprintf("remove State:/Network/Service/%s/DNS\nremove State:/Network/Service/%s/IPv4\n", serviceID, serviceID)
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
	return runPrivilegedLoggedCommandWithInput(launchMode, logPath, command, "")
}

func runPrivilegedLoggedCommandWithInput(launchMode, logPath string, command []string, stdinData string) error {
	if len(command) == 0 {
		return fmt.Errorf("missing privileged command")
	}

	switch launchMode {
	case config.LaunchModeHelper:
		return vpncore.Run(vpncore.DefaultServiceConfig(), append([]string(nil), command...), stdinData, logPath)
	case config.LaunchModeDirect:
		return runLoggedCommand(command, stdinData, logPath)
	case config.LaunchModeSudo:
		if err := ensureSudo(); err != nil {
			return fmt.Errorf("sudo authentication: %w", err)
		}
		return runLoggedCommand(append([]string{"sudo"}, command...), stdinData, logPath)
	default:
		return fmt.Errorf("system DNS handoff is unsupported for launch mode %q", launchMode)
	}
}

func runLoggedCommand(command []string, stdinData, logPath string) error {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	cmd := execCommand(command[0], command[1:]...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
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
