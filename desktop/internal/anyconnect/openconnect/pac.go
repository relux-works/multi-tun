package openconnect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
)

const (
	// PACServeCommand is the hidden openconnect-tun subcommand the connect
	// wrapper starts to serve a local PAC script on loopback.
	PACServeCommand = "__pac-serve"

	pacScriptFileName   = "proxy.pac"
	pacMaxScriptBytes   = 1 << 20
	pacContentType      = "application/x-ns-proxy-autoconfig"
	defaultNetworksetup = "/usr/sbin/networksetup"
)

// pacBackupPath keeps the system auto-proxy settings that were active before
// openconnect-tun replaced them. It lives in a root-owned directory so that it
// survives reboots (the replaced settings are persistent too) and a crashed
// session's original values are restored by the next disconnect.
var pacBackupPath = "/var/db/openconnect-tun/pac-proxy-backup.tsv"

// pacProxySpec is the PAC the connect wrapper sets as the system auto-proxy
// URL while the tunnel is up. Exactly one of URL and ScriptPath is set.
type pacProxySpec struct {
	URL          string
	ScriptPath   string
	ServerBinary string
	UpstreamURL  string
	RewritesPath string
	Rewrites     []openconnectcfg.PACRewriteRule
}

func pacSpecForConnect(options ConnectOptions) (*pacProxySpec, error) {
	if err := (openconnectcfg.PACConfig{URL: options.PACURL, Script: options.PACScript, Rewrites: options.PACRewrites}).Validate(); err != nil {
		return nil, err
	}
	url := strings.TrimSpace(options.PACURL)
	script := options.PACScript
	if url != "" && strings.TrimSpace(script) != "" {
		return nil, errors.New("pac: set only one of url and script")
	}
	if url != "" {
		if strings.ContainsAny(url, "\n\r\t") {
			return nil, errors.New("pac: url must not contain control characters")
		}
		if len(options.PACRewrites) > 0 {
			return &pacProxySpec{UpstreamURL: url, Rewrites: options.PACRewrites}, nil
		}
		return &pacProxySpec{URL: url}, nil
	}
	if strings.TrimSpace(script) == "" && len(options.PACRewrites) == 0 {
		return nil, nil
	}
	if len(script) > pacMaxScriptBytes {
		return nil, fmt.Errorf("pac: script is %d bytes, limit is %d", len(script), pacMaxScriptBytes)
	}
	return &pacProxySpec{Rewrites: options.PACRewrites}, nil
}

// ResolvePAC loads an upstream source; rewrites are applied by Connect once
// the session helper directory exists (and dynamically for HTTP upstreams).
func ResolvePAC(cfg openconnectcfg.PACConfig) (string, string, error) {
	if err := cfg.Validate(); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(cfg.URL) != "" {
		return strings.TrimSpace(cfg.URL), "", nil
	}
	if cfg.File != "" {
		data, err := readPACScript(cfg.File)
		return "", string(data), err
	}
	if len(cfg.Script) > pacMaxScriptBytes {
		return "", "", errors.New("pac: script exceeds 1 MiB")
	}
	return "", cfg.Script, nil
}

// preparePACScript creates the session helper directory and writes the local
// PAC there. An error stops the connect: an unusable pac never starts a tunnel
// without it.
func preparePACScript(spec *pacProxySpec, helperDir string, script string) error {
	if spec == nil || spec.URL != "" {
		return nil
	}
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		return fmt.Errorf("create script helper dir: %w", err)
	}
	return materializePACScript(spec, helperDir, script)
}

// materializePACScript writes the PAC body next to the wrapper and records the
// binary that serves it.
func materializePACScript(spec *pacProxySpec, helperDir string, script string) error {
	if spec == nil || spec.URL != "" {
		return nil
	}
	path := filepath.Join(helperDir, pacScriptFileName)
	if spec.UpstreamURL != "" {
		spec.RewritesPath = filepath.Join(helperDir, "pac-rewrites.json")
		data, err := json.Marshal(spec.Rewrites)
		if err != nil {
			return err
		}
		if err := os.WriteFile(spec.RewritesPath, data, 0o644); err != nil {
			return err
		}
	} else if len(spec.Rewrites) > 0 {
		var err error
		script, err = RewritePACScript(script, spec.Rewrites)
		if err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		return fmt.Errorf("write pac script: %w", err)
	}
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate openconnect-tun binary for pac server: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(binary); err == nil {
		binary = resolved
	}
	spec.ScriptPath = path
	spec.ServerBinary = binary
	return nil
}

// pacProxyShellBlock returns the wrapper variables and functions that set the
// PAC on every enabled network service on connect and restore the previous
// auto-proxy settings on disconnect. Restore also runs when this session has no
// PAC, so a backup left by a crashed session is put back.
func pacProxyShellBlock(spec *pacProxySpec, backupPath string, networksetup string) string {
	url, scriptPath, serverBinary := "", "", ""
	upstreamURL, rewritesPath := "", ""
	if spec != nil {
		url, scriptPath, serverBinary = spec.URL, spec.ScriptPath, spec.ServerBinary
		upstreamURL, rewritesPath = spec.UpstreamURL, spec.RewritesPath
	}
	return `pac_upstream_url=` + shellQuote(upstreamURL) + `
pac_rewrites_file=` + shellQuote(rewritesPath) + `
pac_url=` + shellQuote(url) + `
pac_script_file=` + shellQuote(scriptPath) + `
pac_server_bin=` + shellQuote(serverBinary) + `
pac_backup_file=` + shellQuote(backupPath) + `
pac_networksetup=` + shellQuote(networksetup) + `
pac_port_file="$helper_dir/pac-port"
pac_pid_file="$helper_dir/pac-server.pid"
pac_services_file="$helper_dir/pac-services"
pac_tab=$(printf '\t')
pac_effective_url=""

pac_log() {
  printf 'vpnc_wrapper_pac: %s\n' "$*" >> "$log_file" 2>&1
}

pac_listing() {
  pac_listed=$("$pac_networksetup" -listallnetworkservices < /dev/null 2>/dev/null) || return 1
  printf '%s\n' "$pac_listed" | sed -e 1d -e '/^$/d'
}

# pac_services prints the enabled services. It fails when networksetup fails,
# so a failed listing is never read as "no services".
pac_services() {
  pac_listing > "$pac_services_file.raw" || { rm -f "$pac_services_file.raw"; return 1; }
  sed -e '/^\*/d' "$pac_services_file.raw"
  rm -f "$pac_services_file.raw"
}

# pac_all_services prints every service, disabled ones without their "*".
pac_all_services() {
  pac_listing > "$pac_services_file.raw" || { rm -f "$pac_services_file.raw"; return 1; }
  sed -e 's/^\*//' "$pac_services_file.raw"
  rm -f "$pac_services_file.raw"
}

pac_in_list() {
  while IFS= read -r pac_item; do
    if [ "$pac_item" = "$1" ]; then
      return 0
    fi
  done < "$2"
  return 1
}

pac_in_backup() {
  while IFS="$pac_tab" read -r pac_item pac_rest; do
    if [ "$pac_item" = "$1" ]; then
      return 0
    fi
  done < "$2"
  return 1
}

# pac_backup records the current settings of every enabled service in the
# backup and leaves that service list in $pac_services_file for apply. A
# backup left by a crashed session is kept as is; services that are not in it
# yet are appended with their current settings.
pac_backup() {
  mkdir -p "$(dirname "$pac_backup_file")" || return 1
  chmod 700 "$(dirname "$pac_backup_file")" 2>/dev/null
  pac_services > "$pac_services_file" || return 1
  if [ ! -s "$pac_services_file" ]; then
    pac_log "backup_no_services"
    return 1
  fi
  pac_tmp="$pac_backup_file.tmp.$$"
  rm -f "$pac_tmp"
  if [ -s "$pac_backup_file" ]; then
    cp "$pac_backup_file" "$pac_tmp" || { rm -f "$pac_tmp"; return 1; }
    pac_log "backup_kept $pac_backup_file"
  else
    : > "$pac_tmp" || return 1
  fi
  while IFS= read -r pac_svc; do
    [ -n "$pac_svc" ] || continue
    if pac_in_backup "$pac_svc" "$pac_tmp"; then
      continue
    fi
    if ! pac_out=$("$pac_networksetup" -getautoproxyurl "$pac_svc" < /dev/null 2>/dev/null); then
      rm -f "$pac_tmp"
      return 1
    fi
    pac_prev_url=$(printf '%s\n' "$pac_out" | sed -n 's/^URL: //p' | head -n 1)
    pac_prev_enabled=$(printf '%s\n' "$pac_out" | sed -n 's/^Enabled: //p' | head -n 1)
    printf '%s\t%s\t%s\n' "$pac_svc" "${pac_prev_enabled:-No}" "${pac_prev_url:-(null)}" >> "$pac_tmp" || { rm -f "$pac_tmp"; return 1; }
    pac_log "backup_add $pac_svc"
  done < "$pac_services_file"
  mv -f "$pac_tmp" "$pac_backup_file" || { rm -f "$pac_tmp"; return 1; }
  pac_log "backup_saved $pac_backup_file"
}

pac_stop_server() {
  [ -f "$pac_pid_file" ] || return 0
  pac_pid=$(cat "$pac_pid_file" 2>/dev/null)
  case "$pac_pid" in
    ''|*[!0-9]*) ;;
    *)
      case "$(ps -p "$pac_pid" -o command= 2>/dev/null)" in
        *` + PACServeCommand + `*) kill "$pac_pid" 2>/dev/null && pac_log "server_stopped $pac_pid" ;;
      esac
      ;;
  esac
  rm -f "$pac_pid_file" "$pac_port_file"
}

pac_start_server() {
  pac_stop_server
  [ -x "$pac_server_bin" ] || return 1
  [ -f "$pac_script_file" ] || return 1
  case "${VPNPID:-}" in
    ''|0|*[!0-9]*)
      pac_log "server_skip: VPNPID is not set"
      return 1
      ;;
  esac
  if [ -n "$pac_upstream_url" ]; then
    "$pac_server_bin" ` + PACServeCommand + ` --upstream-url "$pac_upstream_url" --rewrites-file "$pac_rewrites_file" --port-file "$pac_port_file" --watch-pid "$VPNPID" < /dev/null >> "$log_file" 2>&1 &
  else
    "$pac_server_bin" ` + PACServeCommand + ` --file "$pac_script_file" --port-file "$pac_port_file" --watch-pid "$VPNPID" < /dev/null >> "$log_file" 2>&1 &
  fi
  printf '%s\n' "$!" > "$pac_pid_file"
  pac_i=0
  while [ "$pac_i" -lt 50 ]; do
    if [ -s "$pac_port_file" ]; then
      pac_port=$(cat "$pac_port_file" 2>/dev/null)
      case "$pac_port" in
        ''|*[!0-9]*) return 1 ;;
      esac
      pac_effective_url="http://127.0.0.1:$pac_port/` + pacScriptFileName + `"
      return 0
    fi
    sleep 0.1
    pac_i=$((pac_i + 1))
  done
  return 1
}

# apply_pac_proxy sets the PAC only on services whose previous settings are in
# the backup, using the same service list the backup was taken from.
apply_pac_proxy() {
  pac_effective_url="$pac_url"
  if [ -n "$pac_script_file" ]; then
    if ! pac_start_server; then
      pac_log "server_failed"
      pac_stop_server
      return 0
    fi
  fi
  [ -n "$pac_effective_url" ] || return 0
  if ! pac_backup; then
    pac_log "backup_failed; system proxy left unchanged"
    rm -f "$pac_services_file"
    pac_stop_server
    return 0
  fi
  while IFS= read -r pac_svc; do
    [ -n "$pac_svc" ] || continue
    if ! pac_in_backup "$pac_svc" "$pac_backup_file"; then
      pac_log "set_skip_unsaved $pac_svc"
      continue
    fi
    if "$pac_networksetup" -setautoproxyurl "$pac_svc" "$pac_effective_url" < /dev/null >> "$log_file" 2>&1; then
      pac_log "set $pac_svc $pac_effective_url"
    else
      pac_log "set_failed $pac_svc"
    fi
  done < "$pac_services_file"
  rm -f "$pac_services_file"
}

# restore_pac_proxy puts back the saved settings. When the services cannot be
# listed it changes nothing and keeps the backup for the next disconnect. A
# service that is gone is dropped; a service that fails to restore stays in
# the backup on its own, so later disconnects never re-apply entries that
# were already restored.
restore_pac_proxy() {
  pac_stop_server
  [ -s "$pac_backup_file" ] || return 0
  if ! pac_all_services > "$pac_services_file.all" || [ ! -s "$pac_services_file.all" ]; then
    rm -f "$pac_services_file.all"
    pac_log "restore_deferred: network services could not be listed; backup kept at $pac_backup_file"
    return 0
  fi
  pac_keep="$pac_backup_file.keep.$$"
  rm -f "$pac_keep"
  pac_failed=0
  pac_keep_ok=1
  while IFS="$pac_tab" read -r pac_svc pac_prev_enabled pac_prev_url; do
    [ -n "$pac_svc" ] || continue
    if ! pac_in_list "$pac_svc" "$pac_services_file.all"; then
      pac_log "restore_skip_missing $pac_svc"
      continue
    fi
    pac_ok=1
    if [ -n "$pac_prev_url" ] && [ "$pac_prev_url" != "(null)" ]; then
      "$pac_networksetup" -setautoproxyurl "$pac_svc" "$pac_prev_url" < /dev/null >> "$log_file" 2>&1 || pac_ok=0
    fi
    case "$pac_prev_enabled" in
      Yes) pac_state=on ;;
      *) pac_state=off ;;
    esac
    "$pac_networksetup" -setautoproxystate "$pac_svc" "$pac_state" < /dev/null >> "$log_file" 2>&1 || pac_ok=0
    if [ "$pac_ok" = 1 ]; then
      pac_log "restore $pac_svc $pac_state"
    else
      pac_failed=1
      printf '%s\t%s\t%s\n' "$pac_svc" "$pac_prev_enabled" "$pac_prev_url" >> "$pac_keep" || pac_keep_ok=0
      pac_log "restore_failed $pac_svc"
    fi
  done < "$pac_backup_file"
  rm -f "$pac_services_file.all"
  if [ "$pac_failed" = 0 ]; then
    rm -f "$pac_backup_file" "$pac_keep"
    pac_log "restored"
  elif [ "$pac_keep_ok" = 1 ] && [ -s "$pac_keep" ] && mv -f "$pac_keep" "$pac_backup_file"; then
    pac_log "restore_incomplete; failed services kept at $pac_backup_file"
  else
    rm -f "$pac_keep"
    pac_log "restore_incomplete; backup kept at $pac_backup_file"
  fi
}
`
}

// PACServeOptions configures the loopback PAC server.
type PACServeOptions struct {
	cacheNow     func() time.Time
	File         string
	UpstreamURL  string
	RewritesFile string
	PortFile     string
	WatchPID     int
	Listen       string
}

// ParsePACServeArgs parses the arguments of the hidden PAC serve subcommand.
func ParsePACServeArgs(args []string) (PACServeOptions, error) {
	options := PACServeOptions{Listen: "127.0.0.1:0"}
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			return options, fmt.Errorf("missing value for %s", args[i])
		}
		value := args[i+1]
		switch args[i] {
		case "--file":
			options.File = value
		case "--upstream-url":
			options.UpstreamURL = value
		case "--rewrites-file":
			options.RewritesFile = value
		case "--port-file":
			options.PortFile = value
		case "--watch-pid":
			pid, err := strconv.Atoi(value)
			if err != nil || pid <= 0 {
				return options, fmt.Errorf("invalid --watch-pid %q", value)
			}
			options.WatchPID = pid
		default:
			return options, fmt.Errorf("unknown argument %s", args[i])
		}
		i++
	}
	if (options.File == "" && options.UpstreamURL == "" && options.RewritesFile == "") || options.PortFile == "" || options.WatchPID == 0 {
		return options, errors.New("a PAC source, --port-file and --watch-pid are required")
	}
	if err := (openconnectcfg.PACConfig{URL: options.UpstreamURL, File: options.File}).Validate(); err != nil {
		return options, err
	}
	return options, nil
}

var (
	pacWatchInterval = time.Second
	pacEffectiveUID  = os.Geteuid
	pacProcessAlive  = func(pid int) bool {
		err := syscall.Kill(pid, 0)
		return err == nil || errors.Is(err, syscall.EPERM)
	}
	pacDropPrivileges = dropPrivilegesToNobody
)

// ServePAC reads the PAC file, listens on loopback, publishes the port and
// serves the file until ctx ends or the watched process exits. When started as
// root it drops to the nobody account after binding.
func ServePAC(ctx context.Context, options PACServeOptions, logw io.Writer) error {
	handler, err := newPACServeHandler(options)
	if err != nil {
		return err
	}
	listen := options.Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("pac serve: invalid listen address %q: %w", listen, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("pac serve: listen address %q is not loopback", listen)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("pac serve: listen: %w", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	// Open the port file before dropping privileges (its directory may not be
	// writable by nobody) but publish the port only after the drop succeeded, so
	// the wrapper never points the system at a server that is about to exit.
	_ = os.Remove(options.PortFile)
	portFile, err := os.OpenFile(options.PortFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("pac serve: open port file: %w", err)
	}
	if pacEffectiveUID() == 0 {
		if err := pacDropPrivileges(); err != nil {
			_ = portFile.Close()
			_ = os.Remove(options.PortFile)
			return fmt.Errorf("pac serve: drop privileges: %w", err)
		}
	}
	_, writeErr := portFile.WriteString(strconv.Itoa(port) + "\n")
	closeErr := portFile.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(options.PortFile)
		return fmt.Errorf("pac serve: publish port: %v", errors.Join(writeErr, closeErr))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if options.WatchPID > 0 {
		go func() {
			ticker := time.NewTicker(pacWatchInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if !pacProcessAlive(options.WatchPID) {
						fmt.Fprintf(logw, "vpnc_wrapper_pac: server_exit watched pid %d gone\n", options.WatchPID)
						cancel()
						return
					}
				}
			}
		}()
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Fprintf(logw, "vpnc_wrapper_pac: server_listening 127.0.0.1:%d\n", port)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("pac serve: %w", err)
	}
	return nil
}

// readPACScript runs before the privilege drop, so it opens only a regular
// file and never follows a symlink at the last path component.
func readPACScript(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("pac serve: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("pac serve: stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("pac serve: %s is not a regular file", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, pacMaxScriptBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pac serve: read %s: %w", path, err)
	}
	if len(body) > pacMaxScriptBytes {
		return nil, fmt.Errorf("pac serve: %s exceeds %d bytes", path, pacMaxScriptBytes)
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil, fmt.Errorf("pac serve: %s is empty", path)
	}
	return body, nil
}

func pacHandler(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", pacContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})
}

// RewritePACScript captures the upstream function in a private scope. This
// renames its binding without rewriting strings, comments or recursive calls
// inside arbitrary JavaScript. Rewrites are validated before serialization.
func RewritePACScript(upstreamScript string, rewrites []openconnectcfg.PACRewriteRule) (string, error) {
	if err := (openconnectcfg.PACConfig{Rewrites: rewrites}).Validate(); err != nil {
		return "", err
	}
	if len(upstreamScript) > pacMaxScriptBytes {
		return "", errors.New("pac: upstream script exceeds 1 MiB")
	}
	var out strings.Builder
	out.WriteString("var __tun_wave_upstream_FindProxyForURL = (function() {\n")
	out.WriteString(upstreamScript)
	out.WriteString("\nreturn typeof FindProxyForURL === \"function\" ? FindProxyForURL : function(url, host) { return \"DIRECT\"; };\n})();\nfunction FindProxyForURL(url, host) {\n")
	for _, rule := range rewrites {
		value, _ := json.Marshal(rule.Return)
		if rule.Host != "" {
			host, _ := json.Marshal(strings.ToLower(rule.Host))
			fmt.Fprintf(&out, "  if (host.toLowerCase() === %s) return %s;\n", host, value)
		} else {
			suffix := strings.ToLower(strings.TrimPrefix(rule.DomainSuffix, "."))
			name, _ := json.Marshal(suffix)
			dotted, _ := json.Marshal("." + suffix)
			fmt.Fprintf(&out, "  if (dnsDomainIs(host.toLowerCase(), %s) || host.toLowerCase() === %s) return %s;\n", dotted, name, value)
		}
	}
	out.WriteString("  return __tun_wave_upstream_FindProxyForURL(url, host);\n}\n")
	return out.String(), nil
}

func newPACServeHandler(options PACServeOptions) (http.Handler, error) {
	if err := (openconnectcfg.PACConfig{URL: options.UpstreamURL, File: options.File}).Validate(); err != nil {
		return nil, err
	}
	var rewrites []openconnectcfg.PACRewriteRule
	if options.RewritesFile != "" {
		body, err := readPACScript(options.RewritesFile)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&rewrites); err != nil {
			return nil, errors.New("pac: invalid rewrites file")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return nil, errors.New("pac: trailing rewrites data")
		}
	}
	if err := (openconnectcfg.PACConfig{Rewrites: rewrites}).Validate(); err != nil {
		return nil, err
	}
	var local []byte
	if options.File != "" {
		var err error
		local, err = readPACScript(options.File)
		if err != nil {
			return nil, err
		}
	}
	if options.UpstreamURL == "" {
		if len(rewrites) > 0 || len(local) == 0 {
			script, err := RewritePACScript(string(local), rewrites)
			if err != nil {
				return nil, err
			}
			local = []byte(script)
		}
		return pacHandler(local), nil
	}
	// A dedicated standard transport retains certificate verification even if
	// another package customizes http.DefaultTransport. Redirects cannot escape
	// HTTP(S), and the client timeout also bounds body reads.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
			return errors.New("pac: invalid upstream redirect")
		}
		return nil
	}}
	fallback, err := RewritePACScript("", rewrites)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	cached := []byte(fallback)
	var nextFetch time.Time
	now := options.cacheNow
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy.pac" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			pacHandler(nil).ServeHTTP(w, r)
			return
		}
		mu.Lock()
		if now().After(nextFetch) {
			fetchCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			req, reqErr := http.NewRequestWithContext(fetchCtx, http.MethodGet, options.UpstreamURL, nil)
			fetchedOK := false
			if reqErr == nil {
				resp, fetchErr := client.Do(req)
				if fetchErr == nil {
					body, readErr := io.ReadAll(io.LimitReader(resp.Body, pacMaxScriptBytes+1))
					_ = resp.Body.Close()
					if readErr == nil && resp.StatusCode == http.StatusOK && len(body) <= pacMaxScriptBytes && strings.TrimSpace(string(body)) != "" {
						if script, rewriteErr := RewritePACScript(string(body), rewrites); rewriteErr == nil {
							cached = []byte(script)
							fetchedOK = true
						}
					}
				}
			}
			cancel()
			if fetchedOK {
				nextFetch = now().Add(60 * time.Second)
			} else {
				nextFetch = now().Add(5 * time.Second)
			}
		}
		body := cached
		mu.Unlock()
		pacHandler(body).ServeHTTP(w, r)
	}), nil
}

func dropPrivilegesToNobody() error {
	account, err := user.Lookup("nobody")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("still root after setuid")
	}
	return nil
}

func pacDescription(spec *pacProxySpec) string {
	switch {
	case spec == nil:
		return ""
	case spec.URL != "":
		return spec.URL
	case spec.UpstreamURL != "":
		return spec.UpstreamURL + " (rewritten on loopback)"
	default:
		return "local script served on loopback"
	}
}
