package openconnect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
)

func installPreStopSnapshotTestSeams(t *testing.T) CurrentSession {
	t.Helper()
	previousState := detectStateOpenConnect
	previousInfo := getConnectionInfoOpenConnect
	previousRuntime := currentRuntimeOpenConnect
	previousRoutes := currentRoutesOpenConnect
	previousCommand := newPreStopCommandOpenConnect
	t.Cleanup(func() {
		detectStateOpenConnect = previousState
		getConnectionInfoOpenConnect = previousInfo
		currentRuntimeOpenConnect = previousRuntime
		currentRoutesOpenConnect = previousRoutes
		newPreStopCommandOpenConnect = previousCommand
	})
	currentRuntimeOpenConnect = func() (*RuntimeStatus, error) {
		return &RuntimeStatus{PID: 4242, Interface: "utun8", Uptime: "00:57"}, nil
	}
	currentRoutesOpenConnect = func() ([]string, error) {
		return []string{"192.0.2.53/32", "198.51.100.53/32"}, nil
	}
	newPreStopCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
		switch {
		case name == "scutil" && strings.Join(args, " ") == "--dns":
			return exec.Command("/bin/sh", "-c", `printf 'DNS configuration\nresolver #1\n'`)
		case name == "netstat" && strings.Join(args, " ") == "-rn -f inet":
			return exec.Command("/bin/sh", "-c", `printf 'Routing tables\nInternet:\n'`)
		default:
			t.Fatalf("unexpected snapshot command: %s %q", name, args)
			return nil
		}
	}
	return CurrentSession{
		ID: "fixture", Mode: ConnectModeSplitInclude, Server: "vpn.example.test/outside", Interface: "utun8",
		LogPath: filepath.Join(t.TempDir(), "session.log"),
	}
}

func appendPreStopSnapshotForTest(t *testing.T, current CurrentSession) string {
	t.Helper()
	if err := appendPreStopSnapshot("", current); err != nil {
		t.Fatalf("appendPreStopSnapshot() error = %v, want best-effort success", err)
	}
	raw, err := os.ReadFile(current.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertPreStopSnapshotBytes(t *testing.T, got, ciscoLines string) {
	t.Helper()
	lines := strings.Split(got, "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "captured_at: ") {
		t.Fatalf("snapshot missing capture time: %q", got)
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimPrefix(lines[1], "captured_at: ")); err != nil {
		t.Fatalf("invalid capture time: %v", err)
	}
	// The capture time varies; every other byte is pinned to the pre-fix output format.
	want := "=== pre-stop snapshot ===\n" + lines[1] + "\n" +
		"pre_stop_session_id: fixture\n" +
		"pre_stop_session_mode: split-include\n" +
		"pre_stop_session_server: vpn.example.test/outside\n" +
		"pre_stop_session_interface: utun8\n" + ciscoLines +
		"pre_stop_openconnect_pid: 4242\n" +
		"pre_stop_openconnect_interface: utun8\n" +
		"pre_stop_openconnect_uptime: 00:57\n" +
		"pre_stop_live_routes: 192.0.2.53/32, 198.51.100.53/32\n" +
		"pre_stop_scutil_dns_begin\nDNS configuration\nresolver #1\npre_stop_scutil_dns_end\n" +
		"pre_stop_route_table_begin\nRouting tables\nInternet:\npre_stop_route_table_end\n" +
		"=== end pre-stop snapshot ===\n"
	if got != want {
		t.Fatalf("snapshot bytes differ:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestPreStopSnapshotCiscoErrorSkipsStats(t *testing.T) {
	// Proves timeout and exec errors skip stats, log one error line, preserve runtime/routes/DNS, and do not fail snapshot append.
	for _, tc := range []struct {
		name   string
		reason string
	}{
		{"timeout", "vpn state timed out after 5s"},
		{"exec_error", "running vpn state: executable failed"},
		{"multiline_exec_error", "running vpn state: executable failed\r\nagent unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := installPreStopSnapshotTestSeams(t)
			stateCalls, infoCalls := 0, 0
			detectStateOpenConnect = func() (State, string, error) {
				stateCalls++
				return StateUnknown, "/fake/cisco/vpn", errors.New(tc.reason)
			}
			getConnectionInfoOpenConnect = func() (*ConnectionInfo, string, error) {
				infoCalls++
				return nil, "", nil
			}
			got := appendPreStopSnapshotForTest(t, current)
			if stateCalls != 1 || infoCalls != 0 {
				t.Fatalf("Cisco calls: state=%d stats=%d, want state=1 stats=0", stateCalls, infoCalls)
			}
			reason := strings.NewReplacer("\r", " ", "\n", " ").Replace(tc.reason)
			assertPreStopSnapshotBytes(t, got, "pre_stop_cisco_error: "+reason+"\n")
		})
	}
}

func TestPreStopSnapshotCancelsHangingCiscoProbe(t *testing.T) {
	// Proves a state command blocked on context cancellation costs one 25ms timeout (plus 200ms margin), with no stats and a successful complete snapshot.
	current := installPreStopSnapshotTestSeams(t)
	detectStateOpenConnect = DetectState
	getConnectionInfoOpenConnect = GetConnectionInfo
	const timeout = 25 * time.Millisecond
	commandCalls := 0
	t.Cleanup(InstallCiscoTestSeams(CiscoTestSeams{
		CommandTimeout: timeout, VPNBinaryCandidates: []string{"/fake/cisco/vpn"},
		PathStat: func(string) (os.FileInfo, error) { return nil, nil },
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commandCalls++
			if name != "/fake/cisco/vpn" || len(args) != 1 || args[0] != "state" {
				t.Fatalf("unexpected Cisco command: %s %q", name, args)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}))
	startedAt := time.Now()
	got := appendPreStopSnapshotForTest(t, current)
	elapsed := time.Since(startedAt)
	if elapsed >= timeout+200*time.Millisecond {
		t.Fatalf("snapshot elapsed = %s, want < %s", elapsed, timeout+200*time.Millisecond)
	}
	if commandCalls != 1 {
		t.Fatalf("Cisco command calls = %d, want 1", commandCalls)
	}
	assertPreStopSnapshotBytes(t, got, "pre_stop_cisco_error: vpn state timed out after 25ms\n")
	t.Logf("snapshot returned in %s with exactly %d Cisco call", elapsed, commandCalls)
}

func TestPreStopSnapshotCiscoPositiveOutputUnchanged(t *testing.T) {
	// Proves healthy and not-installed snapshots retain every pre-fix output byte except the variable capture timestamp.
	for _, installed := range []bool{true, false} {
		t.Run(fmt.Sprintf("installed=%t", installed), func(t *testing.T) {
			current := installPreStopSnapshotTestSeams(t)
			detectStateOpenConnect = DetectState
			getConnectionInfoOpenConnect = GetConnectionInfo
			commandCalls := 0
			t.Cleanup(InstallCiscoTestSeams(CiscoTestSeams{
				CommandTimeout: time.Second, VPNBinaryCandidates: []string{"/fake/cisco/vpn"},
				PathStat: func(string) (os.FileInfo, error) {
					if !installed {
						return nil, os.ErrNotExist
					}
					return nil, nil
				},
				RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
					commandCalls++
					if name != "/fake/cisco/vpn" || len(args) != 1 {
						t.Fatalf("unexpected Cisco command: %s %q", name, args)
					}
					switch args[0] {
					case "state":
						return []byte(">> state: Connected"), nil
					case "stats":
						return []byte("Connection State: Connected\nServer Address: 198.51.100.1\nClient Address (IPv4): 192.0.2.42\nTunnel Mode (IPv4): Split Include\nDuration: 00:57\n"), nil
					default:
						t.Fatalf("unexpected Cisco probe: %q", args)
						return nil, nil
					}
				},
			}))
			got := appendPreStopSnapshotForTest(t, current)
			ciscoLines := "pre_stop_cisco_state: not_installed\n"
			wantCalls := 0
			if installed {
				ciscoLines = "pre_stop_vpn_binary: /fake/cisco/vpn\npre_stop_cisco_state: connected\n" +
					"pre_stop_state: connected\npre_stop_server_addr: 198.51.100.1\n" +
					"pre_stop_client_addr: 192.0.2.42\npre_stop_tunnel_mode: Split Include\npre_stop_duration: 00:57\n"
				wantCalls = 2
			}
			if commandCalls != wantCalls {
				t.Fatalf("Cisco calls = %d, want %d", commandCalls, wantCalls)
			}
			assertPreStopSnapshotBytes(t, got, ciscoLines)
		})
	}
}

func TestOrphanCleanupCiscoStateControls(t *testing.T) {
	// Proves timeout/exec errors allow marked-artifact cleanup with one state probe; connected Cisco prevents cleanup;
	// absent artifacts skip both cleanup and the Cisco probe. Unrelated files are preserved in every case.
	for _, tc := range []struct {
		name      string
		state     State
		err       error
		marker    string
		wantClean bool
		wantProbe int
	}{
		{"timeout", StateUnknown, errors.New("vpn state timed out after 5s"), "# Added by openconnect-tun DNS shim", true, 1},
		{"exec_error", StateUnknown, errors.New("running vpn state: executable failed"), "# Added by openconnect-tun public bypass", true, 1},
		{"connected", StateConnected, nil, "# Added by openconnect-tun DNS shim", false, 1},
		{"no_artifacts", StateUnknown, errors.New("vpn state timed out after 5s"), "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir, resolverDir := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(SessionsDir(cacheDir), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := SaveMetadata(CurrentSession{
				ID: "fixture", MetadataPath: filepath.Join(SessionsDir(cacheDir), metadataFilePrefix+"fixture.json"),
				Server: "vpn.example.test/outside", Mode: ConnectModeSplitInclude,
				VPNDomains: []string{"example.test"}, VPNNameservers: []string{"192.0.2.53"},
			}); err != nil {
				t.Fatal(err)
			}
			resolverPath := filepath.Join(resolverDir, "example.test")
			if tc.marker != "" {
				if err := os.WriteFile(resolverPath, []byte(tc.marker+"\nnameserver 192.0.2.53\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			unrelatedPath := filepath.Join(resolverDir, "unrelated.test")
			const unrelated = "# Managed elsewhere\nnameserver 198.51.100.53\n"
			if err := os.WriteFile(unrelatedPath, []byte(unrelated), 0o600); err != nil {
				t.Fatal(err)
			}
			previousState, previousInfo := detectStateOpenConnect, getConnectionInfoOpenConnect
			previousResolver, previousAvailable := resolverDirOpenConnect, vpnCoreAvailableOpenConnect
			previousCleanup, previousExec := vpnCoreCleanupResolversOpenConnect, execCommandOpenConnect
			t.Cleanup(func() {
				detectStateOpenConnect, getConnectionInfoOpenConnect = previousState, previousInfo
				resolverDirOpenConnect, vpnCoreAvailableOpenConnect = previousResolver, previousAvailable
				vpnCoreCleanupResolversOpenConnect, execCommandOpenConnect = previousCleanup, previousExec
			})
			stateCalls, cleanupCalls := 0, 0
			detectStateOpenConnect = func() (State, string, error) {
				stateCalls++
				return tc.state, "/fake/cisco/vpn", tc.err
			}
			getConnectionInfoOpenConnect = func() (*ConnectionInfo, string, error) {
				t.Fatal("orphan cleanup must not probe Cisco stats")
				return nil, "", nil
			}
			resolverDirOpenConnect = resolverDir
			vpnCoreAvailableOpenConnect = func(vpncore.ServiceConfig) bool { return true }
			vpnCoreCleanupResolversOpenConnect = func(vpncore.ServiceConfig) error {
				cleanupCalls++
				return os.Remove(resolverPath)
			}
			execCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
				t.Fatalf("unexpected cleanup command: %s %q", name, args)
				return nil
			}
			cleaned, err := cleanupOrphanedResolverState(cacheDir)
			wantCalls := 0
			if tc.wantClean {
				wantCalls = 1
			}
			if err != nil || cleaned != tc.wantClean || cleanupCalls != wantCalls || stateCalls != tc.wantProbe {
				t.Fatalf("cleaned=%t err=%v cleanup calls=%d state calls=%d; want cleaned=%t cleanup calls=%d state calls=%d", cleaned, err, cleanupCalls, stateCalls, tc.wantClean, wantCalls, tc.wantProbe)
			}
			_, statErr := os.Stat(resolverPath)
			wantPresent := tc.marker != "" && !tc.wantClean
			if (wantPresent && statErr != nil) || (!wantPresent && !errors.Is(statErr, os.ErrNotExist)) {
				t.Fatalf("resolver present=%t: stat error=%v", wantPresent, statErr)
			}
			raw, err := os.ReadFile(unrelatedPath)
			if err != nil || string(raw) != unrelated {
				t.Fatalf("unrelated resolver changed: %q, err=%v", raw, err)
			}
		})
	}
}
