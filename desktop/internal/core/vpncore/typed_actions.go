package vpncore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const typedCommandTimeoutVPNCore = 20 * time.Second

var (
	tokenPatternVPNCore      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	uuidPatternVPNCore       = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	interfacePatternVPNCore  = regexp.MustCompile(`^[a-z0-9]{1,15}$`)
	filterWordPatternVPNCore = regexp.MustCompile(`^[A-Za-z0-9.:/]+$`)

	networkServiceOrderVPNCore = func() ([]byte, error) {
		return runTypedCommand("/usr/sbin/networksetup", []string{"-listnetworkserviceorder"}, "")
	}
	resolverDirVPNCore = "/etc/resolver"
	lookupUserVPNCore  = user.LookupId
	chownVPNCore       = os.Chown
)

var forbiddenSingBoxKeys = map[string]struct{}{
	"path": {}, "output": {}, "cache_file": {}, "external_controller": {},
	"external_ui": {}, "download_detour": {}, "store_rdrc": {},
}

// validateSingBoxConfig checks a client-supplied sing-box config and returns
// the canonical bytes root may hand to sing-box. sing-box matches JSON keys
// case-insensitively, so every check here is case-insensitive, objects whose
// keys collide ignoring case are refused, and the re-encoded tree (not the
// client bytes) is what gets written, so duplicate keys cannot make the
// validator and sing-box see different values.
func validateSingBoxConfig(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("config_json is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("decode sing-box config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode sing-box config: %w", err)
	}
	if err := rejectSingBoxKeys(root, "$"); err != nil {
		return nil, err
	}
	allowed := map[string]struct{}{"log": {}, "dns": {}, "inbounds": {}, "outbounds": {}, "route": {}}
	for key := range root {
		if _, ok := allowed[strings.ToLower(key)]; !ok {
			return nil, fmt.Errorf("sing-box top-level key %q is not allowed", key)
		}
	}
	if logValue, ok := lookupFold(root, "log").(map[string]any); ok {
		if lookupFold(logValue, "output") != nil {
			return nil, errors.New("sing-box log.output is not allowed")
		}
	}
	if route, ok := lookupFold(root, "route").(map[string]any); ok {
		if values := lookupFold(route, "rule_set"); values != nil {
			entries, ok := values.([]any)
			if !ok {
				return nil, errors.New("sing-box route.rule_set must be an array")
			}
			for _, entry := range entries {
				object, ok := entry.(map[string]any)
				if !ok || lookupFold(object, "type") != "inline" {
					return nil, errors.New("sing-box rule_set entries must have type inline")
				}
			}
		}
	}
	if values := lookupFold(root, "inbounds"); values != nil {
		inbounds, ok := values.([]any)
		if !ok {
			return nil, errors.New("sing-box inbounds must be an array")
		}
		for _, value := range inbounds {
			inbound, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("sing-box inbound must be an object")
			}
			typeName, _ := lookupFold(inbound, "type").(string)
			switch typeName {
			case "tun":
			case "mixed", "socks", "http":
				listen, _ := lookupFold(inbound, "listen").(string)
				addr, err := netip.ParseAddr(listen)
				if err != nil || !addr.IsLoopback() {
					return nil, fmt.Errorf("sing-box %s inbound listen must be a loopback IP", typeName)
				}
			default:
				return nil, fmt.Errorf("sing-box inbound type %q is not allowed", typeName)
			}
		}
	}
	canonical, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("encode sing-box config: %w", err)
	}
	return canonical, nil
}

// lookupFold returns the value of key in object ignoring case. Callers rely on
// rejectSingBoxKeys having refused case-colliding keys, so at most one matches.
func lookupFold(object map[string]any, key string) any {
	for name, value := range object {
		if strings.EqualFold(name, key) {
			return value
		}
	}
	return nil
}

func rejectSingBoxKeys(value any, location string) error {
	switch typed := value.(type) {
	case map[string]any:
		seen := make(map[string]string, len(typed))
		for key, child := range typed {
			folded := strings.ToLower(key)
			if previous, dup := seen[folded]; dup {
				return fmt.Errorf("sing-box keys %s.%s and %s.%s collide ignoring case", location, previous, location, key)
			}
			seen[folded] = key
			if _, forbidden := forbiddenSingBoxKeys[folded]; forbidden {
				return fmt.Errorf("sing-box key %s.%s is not allowed", location, key)
			}
			if err := rejectSingBoxKeys(child, location+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			if err := rejectSingBoxKeys(child, fmt.Sprintf("%s[%d]", location, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *serviceDaemon) newRuntimeDir() (string, error) {
	if d.cfg.RuntimeDir == "" {
		return "", errors.New("vpn core runtime directory is required")
	}
	if err := ensureRuntimeDirectory(d.cfg.RuntimeDir, 0o711); err != nil {
		return "", err
	}
	base := filepath.Join(d.cfg.RuntimeDir, "s")
	if err := ensureRuntimeDirectory(base, 0o711); err != nil {
		return "", fmt.Errorf("create runtime base: %w", err)
	}
	dir, err := os.MkdirTemp(base, "session-")
	if err != nil {
		return "", fmt.Errorf("create runtime session: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func ensureRuntimeDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime path %s is not a real directory", path)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("runtime directory %s mode is %o, want %o", path, info.Mode().Perm(), mode)
	}
	if os.Geteuid() == 0 {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("runtime directory %s is not root-owned", path)
		}
	}
	return nil
}

func (d *serviceDaemon) handleSingBoxStart(request Request, logFile *os.File) (int, string, error) {
	if logFile == nil {
		return 0, "", errors.New("singbox.start requires a log file descriptor")
	}
	canonical, err := validateSingBoxConfig(request.ConfigJSON)
	if err != nil {
		return 0, "", err
	}
	dir, err := d.newRuntimeDir()
	if err != nil {
		return 0, "", err
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, canonical, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return 0, "", err
	}
	writer := newPassedLogWriter(logFile, request.LogMaxLines)
	cmd := execCommandVPNCore(d.cfg.ToolPath("sing-box"), "run", "-c", configPath)
	cmd.Stdout = writer
	cmd.Stderr = writer
	return d.startManagedChild(cmd, request.SetPGID, "", func() {
		_ = writer.Close()
		_ = os.RemoveAll(dir)
	})
}

func (d *serviceDaemon) startManagedChild(cmd *exec.Cmd, setPGID bool, resultPath string, cleanup func()) (int, string, error) {
	if setPGID {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		cleanup()
		return 0, "", err
	}
	pid := cmd.Process.Pid
	handle, err := d.children.add(pid, setPGID, resultPath)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cleanup()
		return 0, "", err
	}
	if err := watchProcessExitVPNCore(pid, func() {
		d.children.removeBeforeReap(handle, func() {
			_ = cmd.Wait()
			cleanup()
		})
	}); err != nil {
		d.children.remove(handle)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cleanup()
		return 0, "", fmt.Errorf("watch spawned process %d: %w", pid, err)
	}
	return pid, handle, nil
}

func validateSCUtilInput(stdin string) error {
	if len(stdin) == 0 || len(stdin) > maxRequestBytesVPNCore/2 {
		return errors.New("scutil stdin is empty or too large")
	}
	scanner := bufio.NewScanner(strings.NewReader(stdin))
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			return fmt.Errorf("scutil line %d is empty", lineCount)
		}
		valid := false
		switch {
		case len(fields) == 1 && (fields[0] == "d.init" || fields[0] == "quit"):
			valid = true
		case len(fields) == 3 && fields[0] == "d.add" && (fields[1] == "ConfirmedServiceID" || fields[1] == "InterfaceName"):
			valid = tokenPatternVPNCore.MatchString(fields[2])
		case len(fields) >= 4 && fields[0] == "d.add" && fields[1] == "ServerAddresses" && fields[2] == "*":
			valid = allIPs(fields[3:], false)
		case len(fields) == 4 && fields[0] == "d.add" && fields[1] == "Addresses" && fields[2] == "*":
			valid = allIPs(fields[3:], true)
		case len(fields) == 3 && fields[0] == "d.add" && fields[1] == "Router":
			valid = allIPs(fields[2:], true)
		case len(fields) == 2 && (fields[0] == "set" || fields[0] == "remove"):
			valid = validSCUtilStateKey(fields[1])
		}
		if !valid {
			return fmt.Errorf("scutil line %d is outside the allowed grammar", lineCount)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func allIPs(values []string, ipv4Only bool) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil || (ipv4Only && !addr.Is4()) {
			return false
		}
	}
	return true
}

func validSCUtilStateKey(value string) bool {
	const prefix = "State:/Network/Service/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	rest := strings.TrimPrefix(value, prefix)
	parts := strings.Split(rest, "/")
	return len(parts) == 2 && uuidPatternVPNCore.MatchString(parts[0]) && (parts[1] == "DNS" || parts[1] == "IPv4")
}

func (d *serviceDaemon) handleSCUtil(request Request) error {
	if err := validateSCUtilInput(request.Stdin); err != nil {
		return err
	}
	output, err := runTypedCommand("/usr/sbin/scutil", nil, request.Stdin)
	if err != nil {
		return fmt.Errorf("scutil: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func validateNetworkSetup(service string, servers []string, serviceOrder []byte) error {
	if service == "" || strings.IndexFunc(service, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("network service name is empty or contains control characters")
	}
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(serviceOrder))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if index := strings.Index(line, ") "); index >= 0 && strings.TrimSpace(line[index+2:]) == service {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("network service %q is not present in service order", service)
	}
	if len(servers) == 0 {
		return errors.New("dns servers must contain IP addresses or the literal Empty")
	}
	if len(servers) == 1 && servers[0] == "Empty" {
		return nil
	}
	if !allIPs(servers, false) {
		return errors.New("dns servers must be IP addresses or the literal Empty")
	}
	return nil
}

func (d *serviceDaemon) handleNetworkSetup(request Request) error {
	order, err := networkServiceOrderVPNCore()
	if err != nil {
		return fmt.Errorf("list network services: %w", err)
	}
	if err := validateNetworkSetup(request.Service, request.Servers, order); err != nil {
		return err
	}
	args := append([]string{"-setdnsservers", request.Service}, request.Servers...)
	output, err := runTypedCommand("/usr/sbin/networksetup", args, "")
	if err != nil {
		return fmt.Errorf("networksetup: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runTypedCommand(name string, args []string, stdin string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), typedCommandTimeoutVPNCore)
	defer cancel()
	cmd := execCommandContextVPNCore(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("timed out after %s", typedCommandTimeoutVPNCore)
	}
	return output, err
}

func (d *serviceDaemon) handleResolverCleanup() error {
	entries, err := os.ReadDir(resolverDirVPNCore)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(resolverDirVPNCore, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		line, readErr := bufio.NewReader(io.LimitReader(file, 4096)).ReadString('\n')
		closeErr := file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if strings.HasPrefix(line, "# Added by openconnect-tun DNS shim") || strings.HasPrefix(line, "# Added by openconnect-tun public bypass") {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func buildTCPDumpCommand(interfaceName string, filter []string, applePCAPNG bool, username, outputPath string) ([]string, error) {
	if !interfacePatternVPNCore.MatchString(interfaceName) {
		return nil, errors.New("tcpdump interface must match [a-z0-9]{1,15}")
	}
	if len(filter) == 0 || len(filter) > 128 {
		return nil, errors.New("tcpdump filter must contain 1..128 words")
	}
	for _, word := range filter {
		if !filterWordPatternVPNCore.MatchString(word) {
			return nil, fmt.Errorf("tcpdump filter word %q is not allowed", word)
		}
	}
	args := []string{"/usr/sbin/tcpdump", "-i", interfaceName, "-s", "0", "-U"}
	if applePCAPNG {
		args = append(args, "--apple-pcapng")
	}
	if username != "" {
		args = append(args, "-Z", username)
	}
	args = append(args, "-w", outputPath)
	args = append(args, filter...)
	return args, nil
}

func (d *serviceDaemon) handleTCPDumpStart(request Request) (int, string, error) {
	if !request.RunAsUser {
		return 0, "", errors.New("tcpdump.start requires run_as_user=true")
	}
	username := ""
	account, err := lookupUserVPNCore(strconv.Itoa(d.clientUID))
	if err != nil {
		return 0, "", fmt.Errorf("resolve client uid %d: %w", d.clientUID, err)
	}
	username = account.Username
	dir, err := d.newRuntimeDir()
	if err != nil {
		return 0, "", err
	}
	outputPath := filepath.Join(dir, "capture.pcap")
	command, err := buildTCPDumpCommand(request.Interface, request.Filter, request.ApplePCAPNG, username, outputPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return 0, "", err
	}
	cmd := execCommandVPNCore(command[0], command[1:]...)
	return d.startManagedChild(cmd, false, outputPath, func() {
		if err := chownVPNCore(outputPath, d.clientUID, d.clientGID); err == nil {
			_ = chownVPNCore(dir, d.clientUID, d.clientGID)
		}
	})
}
