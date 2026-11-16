package openconnect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testPACURL = "http://pac.corp.example/proxy.pac"

// Claim: pacSpecForConnect maps the connect options to at most one PAC source
// and rejects ambiguous, oversized or control-character input before any side effect.
func TestPACSpecForConnect(t *testing.T) {
	if spec, err := pacSpecForConnect(ConnectOptions{}); err != nil || spec != nil {
		t.Fatalf("no PAC: spec=%+v err=%v, want nil, nil", spec, err)
	}
	spec, err := pacSpecForConnect(ConnectOptions{PACURL: "  " + testPACURL + " "})
	if err != nil || spec == nil || spec.URL != testPACURL {
		t.Fatalf("url: spec=%+v err=%v", spec, err)
	}
	spec, err = pacSpecForConnect(ConnectOptions{PACScript: "function FindProxyForURL(u, h) { return \"DIRECT\"; }"})
	if err != nil || spec == nil || spec.URL != "" {
		t.Fatalf("script: spec=%+v err=%v", spec, err)
	}

	rejected := []ConnectOptions{
		{PACURL: testPACURL, PACScript: "function FindProxyForURL() {}"},
		{PACURL: testPACURL + "\nreason=disconnect"},
		{PACScript: strings.Repeat("x", pacMaxScriptBytes+1)},
	}
	for _, options := range rejected {
		if spec, err := pacSpecForConnect(options); err == nil {
			t.Fatalf("pacSpecForConnect(url=%q, script=%d bytes) = %+v, want error", options.PACURL, len(options.PACScript), spec)
		}
	}
}

// Claim: a local PAC body is written next to the wrapper (readable by the
// root-run server) and the spec records an existing server binary.
func TestMaterializePACScript(t *testing.T) {
	dir := t.TempDir()
	spec := &pacProxySpec{}
	body := "function FindProxyForURL(u, h) { return \"DIRECT\"; }"
	if err := materializePACScript(spec, dir, body); err != nil {
		t.Fatalf("materializePACScript: %v", err)
	}
	if spec.ScriptPath != filepath.Join(dir, pacScriptFileName) {
		t.Fatalf("ScriptPath = %q", spec.ScriptPath)
	}
	raw, err := os.ReadFile(spec.ScriptPath)
	if err != nil || string(raw) != body {
		t.Fatalf("written body = %q err=%v", raw, err)
	}
	info, err := os.Stat(spec.ScriptPath)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("script mode = %v err=%v, want 0644", info.Mode().Perm(), err)
	}
	if _, err := os.Stat(spec.ServerBinary); err != nil {
		t.Fatalf("ServerBinary %q does not exist: %v", spec.ServerBinary, err)
	}

	urlSpec := &pacProxySpec{URL: testPACURL}
	urlDir := t.TempDir()
	if err := materializePACScript(urlSpec, urlDir, body); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(urlDir, pacScriptFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("URL mode must not write a local PAC file, stat err=%v", err)
	}
}

// Claim: the generated wrapper is valid sh, restores the proxy first on
// disconnect, applies the PAC only on the initial connect, and carries the
// configured URL quoted.
func TestScriptWrapperCarriesPACHooks(t *testing.T) {
	script := scriptDiagnosticsWrapperScript("/tmp/openconnect.log", "/opt/homebrew/etc/vpnc/vpnc-script", nil, "", nil, &pacProxySpec{URL: testPACURL})
	for _, want := range []string{
		"pac_url='" + testPACURL + "'",
		"pac_backup_file='" + pacBackupPath + "'",
		"  disconnect)\n    restore_pac_proxy\n    remove_vpn_gateway_route",
		`[ "${reason:-}" = "connect" ] && apply_pac_proxy`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("wrapper is missing %q", want)
		}
	}
	checkShellSyntax(t, script)

	// Without a PAC the wrapper still restores a leftover backup but has nothing to apply.
	plain := scriptDiagnosticsWrapperScript("/tmp/openconnect.log", "/opt/homebrew/etc/vpnc/vpnc-script", nil, "", nil, nil)
	if !strings.Contains(plain, "pac_url=''") || !strings.Contains(plain, "pac_script_file=''") {
		t.Fatal("wrapper without PAC must carry empty pac_url and pac_script_file")
	}
	if !strings.Contains(plain, "restore_pac_proxy") {
		t.Fatal("wrapper without PAC must still restore a leftover backup")
	}
	checkShellSyntax(t, plain)
}

func checkShellSyntax(t *testing.T, script string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wrapper.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("sh -n failed: %v\n%s", err, out)
	}
}

// Claim (review N3): a local PAC that cannot be written stops the connect
// with an error; a URL or no PAC needs no helper directory.
func TestPreparePACScriptFailsClosed(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	helperDir := filepath.Join(blocker, "helpers")
	if err := preparePACScript(&pacProxySpec{}, helperDir, "function FindProxyForURL() {}"); err == nil {
		t.Fatal("preparePACScript = nil, want an error when the helper dir cannot be created")
	}
	for _, spec := range []*pacProxySpec{nil, {URL: testPACURL}} {
		if err := preparePACScript(spec, helperDir, ""); err != nil {
			t.Fatalf("preparePACScript(%+v) = %v, want nil", spec, err)
		}
	}
	ok := t.TempDir()
	spec := &pacProxySpec{}
	if err := preparePACScript(spec, filepath.Join(ok, "helpers"), "function FindProxyForURL() {}"); err != nil || spec.ScriptPath == "" {
		t.Fatalf("preparePACScript positive = %v, spec %+v", err, spec)
	}
}

// fakeProxyHost is a fake networksetup with three services: two enabled
// ("Wi-Fi" with a PAC already on, "USB 10/100/1000 LAN" with none) and a
// disabled "*Bluetooth PAN" that must never be touched.
type fakeProxyHost struct {
	t            *testing.T
	dir          string
	networksetup string
	backup       string
	helperDir    string
}

const fakeNetworksetup = `#!/bin/sh
state="$FAKE_NETWORKSETUP_STATE"
printf '%s\n' "$*" >> "$state/calls.log"
key() { printf '%s' "$1" | cksum | cut -d' ' -f1; }
case "$1" in
  -listallnetworkservices)
    [ -f "$state/fail-list" ] && exit 1
    if [ -f "$state/fail-list-once" ]; then rm -f "$state/fail-list-once"; exit 1; fi
    if [ -f "$state/fail-list-partial" ]; then
      echo "An asterisk (*) denotes that a network service is disabled."
      head -n 1 "$state/services"
      exit 1
    fi
    echo "An asterisk (*) denotes that a network service is disabled."
    cat "$state/services"
    ;;
  -getautoproxyurl)
    [ -f "$state/fail-get" ] && exit 1
    k=$(key "$2")
    [ -f "$state/$k.url" ] || exit 4
    printf 'URL: %s\nEnabled: %s\n' "$(cat "$state/$k.url")" "$(cat "$state/$k.enabled")"
    ;;
  -setautoproxyurl)
    k=$(key "$2")
    [ -f "$state/$k.url" ] || exit 4
    [ -f "$state/fail-set-$k" ] && exit 1
    printf '%s' "$3" > "$state/$k.url"
    printf 'Yes' > "$state/$k.enabled"
    ;;
  -setautoproxystate)
    k=$(key "$2")
    [ -f "$state/$k.url" ] || exit 4
    [ -f "$state/fail-set-$k" ] && exit 1
    case "$3" in on) printf 'Yes' ;; *) printf 'No' ;; esac > "$state/$k.enabled"
    ;;
  *) exit 64 ;;
esac
`

func newFakeProxyHost(t *testing.T) *fakeProxyHost {
	t.Helper()
	dir := t.TempDir()
	host := &fakeProxyHost{
		t:            t,
		dir:          dir,
		networksetup: filepath.Join(dir, "networksetup"),
		backup:       filepath.Join(dir, "root", "pac-proxy-backup.tsv"),
		helperDir:    filepath.Join(dir, "helpers"),
	}
	if err := os.WriteFile(host.networksetup, []byte(fakeNetworksetup), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(host.helperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	host.setServices("Wi-Fi", "USB 10/100/1000 LAN", "*Bluetooth PAN")
	host.seed("Wi-Fi", "http://wpad/wpad.dat", "Yes")
	host.seed("USB 10/100/1000 LAN", "(null)", "No")
	host.seed("*Bluetooth PAN", "(null)", "No")
	host.seed("Bluetooth PAN", "http://untouched.example/x.pac", "No")
	return host
}

func (h *fakeProxyHost) setServices(services ...string) {
	if err := os.WriteFile(filepath.Join(h.dir, "services"), []byte(strings.Join(services, "\n")+"\n"), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeProxyHost) seed(service, url, enabled string) {
	h.t.Helper()
	key := h.key(service)
	if err := os.WriteFile(filepath.Join(h.dir, key+".url"), []byte(url), 0o644); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, key+".enabled"), []byte(enabled), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeProxyHost) env() []string {
	return append(os.Environ(), "FAKE_NETWORKSETUP_STATE="+h.dir)
}

func (h *fakeProxyHost) key(service string) string {
	out, err := exec.Command("/bin/sh", "-c", `printf '%s' "$1" | cksum | cut -d' ' -f1`, "sh", service).Output()
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// state returns "<url>|<enabled>" for a service.
func (h *fakeProxyHost) state(service string) string {
	key := h.key(service)
	url, _ := os.ReadFile(filepath.Join(h.dir, key+".url"))
	enabled, _ := os.ReadFile(filepath.Join(h.dir, key+".enabled"))
	return string(url) + "|" + string(enabled)
}

// flag creates or removes a fault flag file in the fake's state directory.
func (h *fakeProxyHost) flag(name string, on bool) {
	h.t.Helper()
	path := filepath.Join(h.dir, name)
	if !on {
		_ = os.Remove(path)
		return
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeProxyHost) backupText() string {
	raw, err := os.ReadFile(h.backup)
	if err != nil {
		return ""
	}
	return string(raw)
}

func (h *fakeProxyHost) calls() string {
	raw, _ := os.ReadFile(filepath.Join(h.dir, "calls.log"))
	return string(raw)
}

func (h *fakeProxyHost) resetCalls() {
	_ = os.Remove(filepath.Join(h.dir, "calls.log"))
}

func (h *fakeProxyHost) log() string {
	raw, _ := os.ReadFile(filepath.Join(h.dir, "wrapper.log"))
	return string(raw)
}

// wrapper runs one PAC wrapper function with the given spec, as the connect
// wrapper would for one openconnect script event.
func (h *fakeProxyHost) wrapper(spec *pacProxySpec, function string, extraEnv ...string) {
	h.t.Helper()
	script := "helper_dir=" + shellQuote(h.helperDir) + "\nlog_file=" + shellQuote(filepath.Join(h.dir, "wrapper.log")) + "\n" +
		pacProxyShellBlock(spec, h.backup, h.networksetup) + "\n" + function + "\n"
	path := filepath.Join(h.dir, "driver.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		h.t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", path)
	cmd.Env = append(h.env(), extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("%s: %v\n%s", function, err, out)
	}
}

const (
	wifi = "Wi-Fi"
	usb  = "USB 10/100/1000 LAN"
)

func (h *fakeProxyHost) assertOriginals() {
	h.t.Helper()
	if got := h.state(wifi); got != "http://wpad/wpad.dat|Yes" {
		h.t.Fatalf("Wi-Fi = %q, want the original PAC enabled", got)
	}
	if got := h.state(usb); !strings.HasSuffix(got, "|No") {
		h.t.Fatalf("USB = %q, want auto proxy disabled as before", got)
	}
	if got := h.state("Bluetooth PAN"); got != "http://untouched.example/x.pac|No" {
		h.t.Fatalf("disabled service changed: %q", got)
	}
}

// Claim: connect sets the PAC URL on every enabled service and never on a
// disabled one; disconnect puts back each service's on/off state, puts back
// the previous URL where the service had one, and removes the backup. A
// service that had no URL is only switched off, so its turned-off URL field
// keeps the PAC URL (documented behaviour).
func TestPACShellApplyAndRestoreURL(t *testing.T) {
	h := newFakeProxyHost(t)
	spec := &pacProxySpec{URL: testPACURL}

	h.wrapper(spec, "apply_pac_proxy")
	if got := h.state(wifi); got != testPACURL+"|Yes" {
		t.Fatalf("Wi-Fi after apply = %q", got)
	}
	if got := h.state(usb); got != testPACURL+"|Yes" {
		t.Fatalf("USB after apply = %q", got)
	}
	if strings.Contains(h.calls(), "Bluetooth") {
		t.Fatalf("disabled service was touched:\n%s", h.calls())
	}
	backup, err := os.ReadFile(h.backup)
	if err != nil {
		t.Fatalf("backup missing after apply: %v", err)
	}
	if want := "Wi-Fi\tYes\thttp://wpad/wpad.dat\nUSB 10/100/1000 LAN\tNo\t(null)\n"; string(backup) != want {
		t.Fatalf("backup = %q, want %q", backup, want)
	}

	h.wrapper(spec, "restore_pac_proxy")
	h.assertOriginals()
	if got := h.state(usb); got != testPACURL+"|No" {
		t.Fatalf("USB after restore = %q, want the PAC URL left in the turned-off field", got)
	}
	if _, err := os.Stat(h.backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup must be removed after a full restore, stat err=%v", err)
	}
}

// Claim (regression, review B1): when the services cannot be listed at
// disconnect (networksetup fails with no output, or fails after printing part
// of the list), restore changes nothing, keeps the backup byte for byte and
// does not report "restored"; the next disconnect with a working listing
// restores the originals.
func TestPACShellRestoreKeepsBackupWhenListingFails(t *testing.T) {
	for _, fault := range []string{"fail-list", "fail-list-partial"} {
		h := newFakeProxyHost(t)
		h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
		saved := h.backupText()
		if saved == "" {
			t.Fatalf("%s: no backup after apply", fault)
		}

		h.resetCalls()
		h.flag(fault, true)
		h.wrapper(nil, "restore_pac_proxy")
		if strings.Contains(h.calls(), "-set") {
			t.Fatalf("%s: restore changed settings without a full service listing:\n%s", fault, h.calls())
		}
		if got := h.backupText(); got != saved {
			t.Fatalf("%s: backup changed after a failed listing: %q, want %q", fault, got, saved)
		}
		if strings.Contains(h.log(), "restored") || !strings.Contains(h.log(), "restore_deferred") {
			t.Fatalf("%s: log must record restore_deferred and no restored:\n%s", fault, h.log())
		}
		if got := h.state(usb); got != testPACURL+"|Yes" {
			t.Fatalf("%s: USB after deferred restore = %q, want the PAC still set", fault, got)
		}

		// Positive control: the listing works again.
		h.flag(fault, false)
		h.wrapper(nil, "restore_pac_proxy")
		h.assertOriginals()
		if h.backupText() != "" {
			t.Fatalf("%s: backup must be removed after the later full restore", fault)
		}
	}
}

// Claim (regression, review B2): when the service listing fails once while
// the backup is taken, or lists no enabled service, connect sets nothing and
// writes no backup, even if a later listing would succeed.
func TestPACShellListingFailureDuringBackupChangesNothing(t *testing.T) {
	for _, fault := range []string{"fail-list-once", "no-enabled"} {
		h := newFakeProxyHost(t)
		if fault == "no-enabled" {
			h.setServices("*Bluetooth PAN")
		} else {
			h.flag(fault, true)
		}
		h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
		if strings.Contains(h.calls(), "-setautoproxy") {
			t.Fatalf("%s: proxy changed without a usable backup:\n%s", fault, h.calls())
		}
		if !strings.Contains(h.log(), "backup_failed") {
			t.Fatalf("%s: log must record backup_failed:\n%s", fault, h.log())
		}
		if _, err := os.Stat(h.backup); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: a failed backup must not leave a backup file", fault)
		}
		h.assertOriginals()
	}
}

// Claim (regression, review B2): after a crashed PAC session, a service that
// appeared since is added to the kept backup with its own settings before the
// PAC is set on it, so disconnect restores it too; the older entries keep the
// true originals.
func TestPACShellNewServiceAfterCrashIsSavedAndRestored(t *testing.T) {
	const phone = "iPhone USB"
	h := newFakeProxyHost(t)
	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy") // session 1 crashes
	h.setServices(wifi, usb, phone, "*Bluetooth PAN")
	h.seed(phone, "http://phone.example/own.pac", "Yes")

	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
	want := "Wi-Fi\tYes\thttp://wpad/wpad.dat\nUSB 10/100/1000 LAN\tNo\t(null)\n" + phone + "\tYes\thttp://phone.example/own.pac\n"
	if got := h.backupText(); got != want {
		t.Fatalf("backup = %q, want %q", got, want)
	}
	if got := h.state(phone); got != testPACURL+"|Yes" {
		t.Fatalf("new service after apply = %q", got)
	}

	h.wrapper(nil, "restore_pac_proxy")
	h.assertOriginals()
	if got := h.state(phone); got != "http://phone.example/own.pac|Yes" {
		t.Fatalf("new service after restore = %q, want its own PAC back", got)
	}
}

// Claim (review N1): when one service fails to restore, only that service
// stays in the backup; the next disconnect retries it and does not overwrite
// a setting the user changed on a service that was already restored.
func TestPACShellPartialRestoreKeepsOnlyFailedService(t *testing.T) {
	h := newFakeProxyHost(t)
	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
	h.flag("fail-set-"+h.key(usb), true)
	h.wrapper(nil, "restore_pac_proxy")
	if got := h.state(wifi); got != "http://wpad/wpad.dat|Yes" {
		t.Fatalf("Wi-Fi after partial restore = %q", got)
	}
	if got, want := h.backupText(), "USB 10/100/1000 LAN\tNo\t(null)\n"; got != want {
		t.Fatalf("backup after partial restore = %q, want only the failed service %q", got, want)
	}
	if !strings.Contains(h.log(), "restore_failed "+usb) {
		t.Fatalf("log must record the failed service:\n%s", h.log())
	}

	h.seed(wifi, "http://user.example/new.pac", "Yes") // the user changes Wi-Fi by hand
	h.flag("fail-set-"+h.key(usb), false)
	h.wrapper(nil, "restore_pac_proxy")
	if got := h.state(wifi); got != "http://user.example/new.pac|Yes" {
		t.Fatalf("Wi-Fi = %q, a later disconnect overwrote the user's setting", got)
	}
	if got := h.state(usb); !strings.HasSuffix(got, "|No") {
		t.Fatalf("USB after retry = %q, want turned off", got)
	}
	if h.backupText() != "" {
		t.Fatal("backup must be removed once the retry succeeds")
	}
}

// Claim: a service that was disabled while connected is still present, so
// restore puts back its settings instead of dropping it as removed.
func TestPACShellRestoresServiceDisabledWhileConnected(t *testing.T) {
	h := newFakeProxyHost(t)
	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
	h.setServices("*Wi-Fi", usb, "*Bluetooth PAN")
	h.wrapper(nil, "restore_pac_proxy")
	if got := h.state(wifi); got != "http://wpad/wpad.dat|Yes" {
		t.Fatalf("disabled Wi-Fi after restore = %q, want the original", got)
	}
	if strings.Contains(h.log(), "restore_skip_missing") {
		t.Fatalf("a disabled service was treated as removed:\n%s", h.log())
	}
}

// Claim (crash recovery): when a session died without restoring, the next
// session keeps the first backup instead of saving the PAC as "original",
// and its disconnect restores the true originals.
func TestPACShellKeepsBackupAcrossCrashedSession(t *testing.T) {
	h := newFakeProxyHost(t)
	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
	// Session 1 crashed: no restore. Session 2 applies another URL.
	second := "http://pac.corp.example/second.pac"
	h.wrapper(&pacProxySpec{URL: second}, "apply_pac_proxy")
	if got := h.state(wifi); got != second+"|Yes" {
		t.Fatalf("Wi-Fi after second apply = %q", got)
	}
	if !strings.Contains(h.log(), "backup_kept") {
		t.Fatalf("second apply must keep the earlier backup, log:\n%s", h.log())
	}
	h.wrapper(&pacProxySpec{URL: second}, "restore_pac_proxy")
	h.assertOriginals()
}

// Claim: a session without PAC never changes the proxy on connect, but its
// disconnect restores a backup left by an earlier crashed PAC session.
func TestPACShellNoPACSessionOnlyRestoresLeftover(t *testing.T) {
	h := newFakeProxyHost(t)
	h.wrapper(nil, "apply_pac_proxy")
	if strings.Contains(h.calls(), "-set") {
		t.Fatalf("connect without PAC changed the proxy:\n%s", h.calls())
	}
	if _, err := os.Stat(h.backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("connect without PAC must not write a backup")
	}

	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy") // crashed PAC session
	h.wrapper(nil, "restore_pac_proxy")
	h.assertOriginals()
}

// Claim (fail closed): when the current settings cannot be read, nothing is
// changed, so a failed backup can never lose the user's proxy settings.
func TestPACShellBackupFailureChangesNothing(t *testing.T) {
	h := newFakeProxyHost(t)
	if err := os.WriteFile(filepath.Join(h.dir, "fail-get"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
	if strings.Contains(h.calls(), "-setautoproxyurl") {
		t.Fatalf("proxy was changed without a backup:\n%s", h.calls())
	}
	if !strings.Contains(h.log(), "backup_failed") {
		t.Fatalf("log must record backup_failed:\n%s", h.log())
	}
	if _, err := os.Stat(h.backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed backup must not leave a backup file")
	}
	h.assertOriginals()
}

// Claim: a service removed while connected is skipped on restore and does not
// keep the backup alive; the remaining services are restored.
func TestPACShellRestoreSkipsRemovedService(t *testing.T) {
	h := newFakeProxyHost(t)
	h.wrapper(&pacProxySpec{URL: testPACURL}, "apply_pac_proxy")
	h.setServices("Wi-Fi", "*Bluetooth PAN")
	h.wrapper(nil, "restore_pac_proxy")
	if got := h.state(wifi); got != "http://wpad/wpad.dat|Yes" {
		t.Fatalf("Wi-Fi after restore = %q", got)
	}
	if !strings.Contains(h.log(), "restore_skip_missing "+usb) {
		t.Fatalf("log must record the skipped service:\n%s", h.log())
	}
	if _, err := os.Stat(h.backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("backup must be removed once the present services are restored")
	}
}

const fakePACServer = `#!/bin/sh
# Fake openconnect-tun: "__pac-serve --file F --port-file P --watch-pid N".
[ "$1" = "__pac-serve" ] || exit 64
port_file=$5
[ -n "$FAKE_PAC_FAIL" ] && exit 1
printf '%s\n' "$FAKE_PAC_PORT" > "$port_file"
while :; do sleep 1; done
`

// Claim: a local script starts the loopback server, the services point at its
// port, and disconnect stops exactly that server and restores the originals.
// When the server cannot publish a port, nothing is changed.
func TestPACShellLocalScriptServer(t *testing.T) {
	h := newFakeProxyHost(t)
	server := filepath.Join(h.dir, "openconnect-tun")
	if err := os.WriteFile(server, []byte(fakePACServer), 0o755); err != nil {
		t.Fatal(err)
	}
	pacFile := filepath.Join(h.helperDir, pacScriptFileName)
	if err := os.WriteFile(pacFile, []byte("function FindProxyForURL(u, h) { return \"DIRECT\"; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := &pacProxySpec{ScriptPath: pacFile, ServerBinary: server}

	h.wrapper(spec, "apply_pac_proxy", "FAKE_PAC_PORT=45123", "VPNPID=1")
	want := "http://127.0.0.1:45123/" + pacScriptFileName
	if got := h.state(wifi); got != want+"|Yes" {
		t.Fatalf("Wi-Fi after apply = %q, want %q", got, want)
	}
	rawPID, err := os.ReadFile(filepath.Join(h.helperDir, "pac-server.pid"))
	if err != nil {
		t.Fatalf("server pid file: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("kill", strconv.Itoa(pid)).Run() })
	if !processRunning(pid) {
		t.Fatalf("server pid %d is not running after apply", pid)
	}

	h.wrapper(spec, "restore_pac_proxy")
	h.assertOriginals()
	deadline := time.Now().Add(3 * time.Second)
	for processRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if processRunning(pid) {
		t.Fatalf("server pid %d still running after restore", pid)
	}

	// Negative: the server never publishes a port, or openconnect gave no
	// VPNPID to watch (review N4).
	for _, env := range [][]string{{"FAKE_PAC_FAIL=1", "VPNPID=1"}, {"FAKE_PAC_PORT=45123", "VPNPID="}} {
		h.resetCalls()
		_ = os.Remove(filepath.Join(h.dir, "wrapper.log"))
		h.wrapper(spec, "apply_pac_proxy", env...)
		if strings.Contains(h.calls(), "-setautoproxyurl") {
			t.Fatalf("%v: proxy changed although the server did not start:\n%s", env, h.calls())
		}
		if !strings.Contains(h.log(), "server_failed") {
			t.Fatalf("%v: log must record server_failed:\n%s", env, h.log())
		}
		h.assertOriginals()
	}
	if _, err := os.Stat(filepath.Join(h.helperDir, "pac-server.pid")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no server pid file may remain after a failed start")
	}
}

func processRunning(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "stat=").Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state != "" && !strings.HasPrefix(state, "Z")
}

func writePAC(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.pac")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func startPACServer(t *testing.T, options PACServeOptions) (context.CancelFunc, <-chan error, int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServePAC(ctx, options, io.Discard) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(options.PortFile)
		if err == nil && strings.HasSuffix(string(raw), "\n") {
			port, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err == nil {
				return cancel, done, port
			}
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("ServePAC exited early: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	t.Fatal("port file never appeared")
	return nil, nil, 0
}

// Claim: the server serves the PAC body to GET and HEAD on loopback with the
// PAC content type, refuses other methods, and stops on cancellation.
func TestServePACServesScript(t *testing.T) {
	body := "function FindProxyForURL(url, host) { return \"PROXY proxy.corp.example:8080\"; }"
	options := PACServeOptions{File: writePAC(t, body), PortFile: filepath.Join(t.TempDir(), "port")}
	cancel, done, port := startPACServer(t, options)
	defer cancel()
	base := fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", port)

	resp, err := http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(got) != body || resp.Header.Get("Content-Type") != pacContentType {
		t.Fatalf("GET = %d %q type=%q", resp.StatusCode, got, resp.Header.Get("Content-Type"))
	}
	head, err := http.Head(base)
	if err != nil || head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD = %v %v", head, err)
	}
	head.Body.Close()
	post, err := http.Post(base, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", post.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServePAC after cancel = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServePAC did not stop after cancel")
	}
}

// Claim: the server exits by itself when the watched VPN process is gone, so
// a crashed tunnel never leaves a PAC server behind.
func TestServePACExitsWhenWatchedProcessEnds(t *testing.T) {
	previous := pacWatchInterval
	pacWatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { pacWatchInterval = previous })

	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	options := PACServeOptions{File: writePAC(t, "function FindProxyForURL() { return \"DIRECT\"; }"), PortFile: filepath.Join(t.TempDir(), "port"), WatchPID: child.Process.Pid}
	cancel, done, _ := startPACServer(t, options)
	defer cancel()

	select {
	case err := <-done:
		t.Fatalf("ServePAC exited while the watched process was alive: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServePAC = %v, want nil after watched exit", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServePAC kept running after the watched process ended")
	}
}

// Claim: bad input (missing, empty or oversized file; a symlink or a
// directory instead of a regular file; non-loopback address) fails before any
// port is published, so the wrapper never sets a dead URL and the root server
// never reads through a link.
func TestServePACRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link.pac")
	if err := os.Symlink(writePAC(t, "function FindProxyForURL() {}"), link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]PACServeOptions{
		"symlink":      {File: link},
		"directory":    {File: dir},
		"missing":      {File: filepath.Join(dir, "absent.pac")},
		"empty":        {File: writePAC(t, " \n")},
		"oversized":    {File: writePAC(t, strings.Repeat("x", pacMaxScriptBytes+1))},
		"non-loopback": {File: writePAC(t, "function FindProxyForURL() {}"), Listen: "0.0.0.0:0"},
	}
	for name, options := range cases {
		options.PortFile = filepath.Join(dir, name+".port")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := ServePAC(ctx, options, io.Discard)
		cancel()
		if err == nil {
			t.Fatalf("%s: ServePAC = nil, want error", name)
		}
		if _, statErr := os.Stat(options.PortFile); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s: port file published despite error", name)
		}
	}
}

// Claim: started as root, the server publishes no port and stops when it
// cannot drop privileges; it never serves as root.
func TestServePACFailsClosedWhenPrivilegeDropFails(t *testing.T) {
	previousUID, previousDrop := pacEffectiveUID, pacDropPrivileges
	t.Cleanup(func() { pacEffectiveUID, pacDropPrivileges = previousUID, previousDrop })
	pacEffectiveUID = func() int { return 0 }
	dropped := false
	pacDropPrivileges = func() error { dropped = true; return errors.New("setuid refused") }

	options := PACServeOptions{File: writePAC(t, "function FindProxyForURL() {}"), PortFile: filepath.Join(t.TempDir(), "port")}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := ServePAC(ctx, options, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "drop privileges") {
		t.Fatalf("ServePAC = %v, want drop privileges error", err)
	}
	if !dropped {
		t.Fatal("privilege drop was not attempted for a root server")
	}
	if _, statErr := os.Stat(options.PortFile); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("port file published although privileges were not dropped")
	}
}

// Claim: the serve subcommand needs --file, --port-file and a positive
// --watch-pid, and rejects unknown or malformed arguments.
func TestParsePACServeArgs(t *testing.T) {
	options, err := ParsePACServeArgs([]string{"--file", "/x/proxy.pac", "--port-file", "/x/port", "--watch-pid", "42"})
	if err != nil || options.File != "/x/proxy.pac" || options.PortFile != "/x/port" || options.WatchPID != 42 || options.Listen != "127.0.0.1:0" {
		t.Fatalf("parse = %+v, %v", options, err)
	}
	for _, args := range [][]string{
		{"--file", "/x/proxy.pac"},
		{"--port-file", "/x/port"},
		{"--file", "/x/proxy.pac", "--port-file", "/x/port"},
		{"--file", "/x/proxy.pac", "--port-file", "/x/port", "--watch-pid", "0"},
		{"--file", "/x/proxy.pac", "--port-file", "/x/port", "--watch-pid", "-1"},
		{"--file", "/x/proxy.pac", "--port-file", "/x/port", "--listen", "0.0.0.0:80"},
		{"--file"},
	} {
		if _, err := ParsePACServeArgs(args); err == nil {
			t.Fatalf("ParsePACServeArgs(%v) = nil error", args)
		}
	}
}
