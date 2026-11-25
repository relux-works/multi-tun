package openconnect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOpenConnectPIDProbeHelper(t *testing.T) {
	// This subprocess emits only fixture probe output, without invoking platform or credential tools.
	if os.Getenv("GO_WANT_OPENCONNECT_PROBE") != "1" {
		t.Skip("subprocess helper")
	}
	fmt.Print(os.Getenv("OPENCONNECT_PROBE_OUTPUT"))
	if os.Getenv("OPENCONNECT_PROBE_STDERR") == "1" {
		fmt.Fprint(os.Stderr, "PRIVATE_PID_PAYLOAD")
	}
	code, err := strconv.Atoi(os.Getenv("OPENCONNECT_PROBE_EXIT"))
	if err != nil {
		os.Exit(99)
	}
	os.Exit(code)
}

func installProcessProbeFixture(t *testing.T, output string, code int, missing bool) *[]string {
	t.Helper()
	fixture := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", fixture)
	previous := execCommandOpenConnect
	t.Cleanup(func() { execCommandOpenConnect = previous })
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	execCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, name)
		probeOutput, probeCode := "", 0
		switch name {
		case "pgrep":
			if strings.Join(args, " ") != "-x openconnect" {
				t.Fatalf("unexpected probe args %q", args)
			}
			if missing {
				return exec.Command(filepath.Join(fixture, "missing-probe"))
			}
			probeOutput, probeCode = output, code
		case "ifconfig", "ps":
			// Empty metadata is enough to prove runtime presence without consulting a live interface or process.
		default:
			t.Fatalf("forbidden fixture command %q", name)
		}
		cmd := exec.Command(executable, "-test.run=^TestOpenConnectPIDProbeHelper$")
		cmd.Env = []string{"HOME=" + fixture, "XDG_CACHE_HOME=" + fixture, "PATH=/usr/bin:/bin", "GORACE=atexit_sleep_ms=0", "GO_WANT_OPENCONNECT_PROBE=1", "OPENCONNECT_PROBE_OUTPUT=" + probeOutput, "OPENCONNECT_PROBE_EXIT=" + strconv.Itoa(probeCode), "OPENCONNECT_PROBE_STDERR=" + os.Getenv("OPENCONNECT_PROBE_STDERR")}
		return cmd
	}
	return &calls
}

func TestCurrentRuntimeProbeVerdicts(t *testing.T) {
	// Only a real no-match is absence. Probe failures/malformed output remain unknown; valid PIDs still report a runtime.
	for _, tc := range []struct {
		name, output string
		code, pid    int
		missing      bool
		stderr       bool
		wantError    bool
	}{
		{name: "absent", code: 1},
		{name: "single", output: "4242\n", pid: 4242},
		{name: "single-without-newline", output: "4242", pid: 4242},
		{name: "multiple", output: "4242\n4243\n", pid: 4243},
		{name: "multiple-without-final-newline", output: "4242\n4243", pid: 4243},
		{name: "blank-line", output: "4242\n\n", wantError: true},
		{name: "leading-blank-line", output: "\n4242\n", wantError: true},
		{name: "multiple-on-line", output: "4242 4243\n", wantError: true},
		{name: "tab-separated", output: "4242\t4243\n", wantError: true},
		{name: "signed-positive", output: "+4242\n", wantError: true},
		{name: "leading-space", output: " 4242\n", wantError: true},
		{name: "probe-error", code: 2, wantError: true},
		{name: "missing-executable", missing: true, wantError: true},
		{name: "empty-success", wantError: true},
		{name: "malformed", output: "PRIVATE_PID_PAYLOAD\n", wantError: true},
		{name: "malformed-before-valid", output: "PRIVATE_PID_PAYLOAD\n4242\n", wantError: true},
		{name: "zero", output: "0\n", wantError: true},
		{name: "negative", output: "-2\n", wantError: true},
		{name: "no-match-with-output", output: "PRIVATE_PID_PAYLOAD\n", code: 1, wantError: true},
		{name: "no-match-with-stderr", code: 1, stderr: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.stderr {
				t.Setenv("OPENCONNECT_PROBE_STDERR", "1")
			}
			calls := installProcessProbeFixture(t, tc.output, tc.code, tc.missing)
			runtime, err := CurrentRuntime()
			if tc.wantError {
				if err == nil || runtime != nil {
					t.Fatalf("unknown probe became absence/presence: runtime=%#v err=%v", runtime, err)
				}
				if !strings.Contains(err.Error(), "openconnect") || strings.Contains(err.Error(), "PRIVATE_PID_PAYLOAD") {
					t.Fatalf("wrong or unredacted error: %v", err)
				}
				if tc.missing && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("probe error lost its cause: %v", err)
				}
				if tc.code == 2 {
					var exitError *exec.ExitError
					if !errors.As(err, &exitError) || exitError.ExitCode() != 2 {
						t.Fatalf("probe exit cause lost: %v", err)
					}
				}
			} else if err != nil || (tc.pid == 0 && runtime != nil) || (tc.pid > 0 && (runtime == nil || runtime.PID != tc.pid)) {
				t.Fatalf("runtime=%#v err=%v want pid=%d", runtime, err, tc.pid)
			}
			if (tc.wantError || tc.pid == 0) && strings.Join(*calls, ",") != "pgrep" {
				t.Fatalf("metadata work after absent/unknown probe: %v", *calls)
			}
		})
	}
}

func TestStopProbeFailureDoesNotCleanOrWriteCache(t *testing.T) {
	// Unknown or malformed process state refuses before liveness checks, resolver cleanup or cache writes; true absence retains cleanup. All liveness is mocked.
	for _, tc := range []struct {
		name, output string
		code         int
		wantError    bool
	}{
		{name: "unknown", code: 2, wantError: true},
		{name: "absent", code: 1},
		{name: "blank-line", output: "4242\n\n", wantError: true},
		{name: "multiple-on-line", output: "4242 4243\n", wantError: true},
		{name: "signed-positive", output: "+4242\n", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := installProcessProbeFixture(t, tc.output, tc.code, false)
			cache := t.TempDir()
			previous := cleanupOrphanedResolverStateOpenConnect
			previousAlive := processAliveOpenConnect
			aliveChecks := 0
			processAliveOpenConnect = func(int) (bool, error) { aliveChecks++; return false, nil }
			cleanups := 0
			cleanupOrphanedResolverStateOpenConnect = func(string) (bool, error) { cleanups++; return false, nil }
			t.Cleanup(func() {
				cleanupOrphanedResolverStateOpenConnect = previous
				processAliveOpenConnect = previousAlive
			})
			_, state, err := Stop(cache, time.Millisecond)
			if tc.wantError {
				if err == nil || state != "" || cleanups != 0 || aliveChecks != 0 || strings.Join(*calls, ",") != "pgrep" {
					t.Errorf("unknown probe proceeded: state=%q err=%v cleanups=%d liveness=%d calls=%v", state, err, cleanups, aliveChecks, *calls)
				}
				entries, readErr := os.ReadDir(cache)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("unknown probe wrote cache: entries=%v err=%v", entries, readErr)
				}
			} else if err != nil || state != "none" || cleanups != 1 {
				t.Fatalf("no-match control failed: state=%q err=%v cleanups=%d", state, err, cleanups)
			}
		})
	}
}
