package vpncore

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

// OpenConnectStartRequest is the complete privileged OpenConnect launch schema.
// Cookie travels over the authenticated Unix socket and the child's stdin only.
type OpenConnectStartRequest struct {
	ServerURL     string `json:"server_url"`
	Protocol      string `json:"protocol,omitempty"`
	ScriptPath    string `json:"script_path"`
	PIDFilePath   string `json:"pid_file_path,omitempty"`
	Cookie        string `json:"cookie"`
	UserAgent     string `json:"user_agent,omitempty"`
	OS            string `json:"os,omitempty"`
	VersionString string `json:"version_string,omitempty"`
	LocalHostname string `json:"local_hostname,omitempty"`
}

var openConnectBinaryVPNCore = func() (string, error) {
	for _, path := range []string{"/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect"} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !(pathWithinOpenConnect(resolved, "/opt/homebrew") || pathWithinOpenConnect(resolved, "/usr/local")) {
			continue
		}
		owner, ownerErr := openConnectHomebrewUIDVPNCore(resolved)
		if ownerErr != nil {
			owner = 0
		}
		if noSymlinksOpenConnect(resolved, false) == nil && validateOpenConnectExecutable(resolved, owner, true) == nil {
			return resolved, nil
		}
	}
	return "", errors.New("trusted openconnect binary is unavailable")
}
var openConnectHomebrewUIDVPNCore = func(binary string) (uint32, error) {
	prefix := "/opt/homebrew"
	if pathWithinOpenConnect(binary, "/usr/local") {
		prefix = "/usr/local/Homebrew"
	}
	info, err := os.Lstat(prefix)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return 0, errors.New("homebrew ownership unavailable")
	}
	return stat.Uid, nil
}

func pathWithinOpenConnect(path, dir string) bool {
	relative, err := filepath.Rel(dir, path)
	return err == nil && relative != "." && filepath.IsLocal(relative)
}

// Check every existing component, including parents of an optional output file.
// Checking only the leaf would allow a symlinked runtime directory to escape.
func noSymlinksOpenConnect(path string, allowMissingLeaf bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return errors.New("openconnect path must be clean and absolute")
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for i, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if allowMissingLeaf && i == len(components)-1 && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return errors.New("openconnect path component is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("openconnect path must not contain symlinks")
		}
		if i < len(components)-1 && !info.IsDir() {
			return errors.New("openconnect path parent is not a directory")
		}
	}
	return nil
}

func validateOpenConnectStart(req OpenConnectStartRequest, uid int) error {
	if len(req.ServerURL) > 8192 || strings.IndexFunc(req.ServerURL, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return errors.New("openconnect server URL contains invalid characters")
	}
	parsed, err := url.Parse(req.ServerURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || strings.Contains(req.ServerURL, "#") || parsed.Opaque != "" {
		return errors.New("openconnect requires an HTTPS server URL without userinfo or fragment")
	}
	if req.Protocol != "" && req.Protocol != "anyconnect" {
		return errors.New("unsupported openconnect protocol")
	}
	if req.Cookie == "" || len(req.Cookie) > 16*1024 || strings.ContainsAny(req.Cookie, "\r\n\x00") {
		return errors.New("openconnect cookie is empty, oversized, or contains forbidden delimiters")
	}
	for _, value := range []string{req.UserAgent, req.OS, req.VersionString, req.LocalHostname} {
		if len(value) > 128 || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r > 126 }) >= 0 {
			return errors.New("openconnect client identity must contain at most 128 printable ASCII characters")
		}
	}
	client, err := lookupUserVPNCore(strconv.Itoa(uid))
	if err != nil || client == nil || !filepath.IsAbs(client.HomeDir) {
		return errors.New("openconnect client home is unavailable")
	}
	allowed := false
	for _, prefix := range []string{filepath.Join(client.HomeDir, ".cache/openconnect-tun/sessions"), filepath.Join(client.HomeDir, ".local/bin"), "/opt/homebrew", "/usr/local"} {
		if pathWithinOpenConnect(req.ScriptPath, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("openconnect script is outside allowed directories")
	}
	if err := noSymlinksOpenConnect(req.ScriptPath, false); err != nil {
		return err
	}
	if err := validateOpenConnectExecutable(req.ScriptPath, uint32(uid), false); err != nil {
		return errors.New("openconnect script must be a regular client- or root-owned file without group/world write permission")
	}
	if req.PIDFilePath != "" {
		if !pathWithinOpenConnect(req.PIDFilePath, filepath.Join(client.HomeDir, ".cache/openconnect-tun/runtime")) {
			return errors.New("openconnect pid file is outside the client runtime directory")
		}
		if err := noSymlinksOpenConnect(req.PIDFilePath, true); err != nil {
			return err
		}
		if info, err := os.Lstat(req.PIDFilePath); err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ok || (stat.Uid != 0 && stat.Uid != uint32(uid)) {
				return errors.New("openconnect pid file is insecure")
			}
		}
	}
	return nil
}

func validateOpenConnectExecutable(path string, owner uint32, executable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("openconnect executable unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ok || (stat.Uid != 0 && stat.Uid != owner) || (executable && info.Mode().Perm()&0o111 == 0) {
		return errors.New("openconnect executable has unsafe type, owner, or permissions")
	}
	return nil
}

func openConnectArgs(req OpenConnectStartRequest) []string {
	args := []string{"--cookie-on-stdin", "--protocol=anyconnect"}
	if req.PIDFilePath != "" {
		args = append(args, "--pid-file="+req.PIDFilePath)
	}
	for _, option := range []struct{ flag, value string }{{"--useragent", req.UserAgent}, {"--os", req.OS}, {"--version-string", req.VersionString}, {"--local-hostname", req.LocalHostname}} {
		if option.value != "" {
			args = append(args, option.flag, option.value)
		}
	}
	// OpenConnect interprets --script as a shell command. Preserve a literal
	// filename even when a legitimate path contains spaces or shell punctuation.
	script := req.ScriptPath
	if strings.IndexFunc(script, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-", r))
	}) >= 0 {
		script = "'" + strings.ReplaceAll(script, "'", "'\"'\"'") + "'"
	}
	return append(args, "--script", script, req.ServerURL)
}

func (d *serviceDaemon) handleOpenConnectStart(request Request, logFile *os.File) (int, string, error) {
	return d.startOpenConnect(request, logFile, true, "")
}

func (d *serviceDaemon) startOpenConnect(request Request, logFile *os.File, setPGID bool, slot string) (int, string, error) {
	if request.OpenConnect == nil || logFile == nil {
		return 0, "", errors.New("openconnect.start requires typed options and a log descriptor")
	}
	req := *request.OpenConnect
	if err := validateOpenConnectStart(req, d.clientUID); err != nil {
		return 0, "", err
	}
	binary, err := openConnectBinaryVPNCore()
	if err != nil {
		return 0, "", errors.New("trusted openconnect binary is unavailable")
	}
	owner, ownerErr := openConnectHomebrewUIDVPNCore(binary)
	if ownerErr != nil {
		owner = 0
	} // A missing Homebrew installation admits root ownership only.
	if err := noSymlinksOpenConnect(binary, false); err != nil {
		return 0, "", err
	}
	if err := validateOpenConnectExecutable(binary, owner, true); err != nil {
		return 0, "", err
	}
	cmd := execCommandVPNCore(binary, openConnectArgs(req)...)
	// os/exec supplies an anonymous pipe for this reader, closing it after copying.
	cmd.Stdin = strings.NewReader(req.Cookie + "\n")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	pid, handle, err := d.startManagedChildWithSlot(cmd, setPGID, "", slot, func() { _ = logFile.Close() }, "openconnect")
	if err != nil {
		return 0, "", errors.New("openconnect child could not be started")
	}
	return pid, handle, nil
}
