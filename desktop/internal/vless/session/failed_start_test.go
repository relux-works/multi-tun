package session

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
)

func helperStartOptions(sidecars ...SidecarOptions) StartOptions {
	return StartOptions{Mode: config.RenderModeTun, PrivilegedLaunch: config.PrivilegedLaunchConfig{Mode: config.LaunchModeHelper}, Sidecars: sidecars}
}

func writeStartConfig(t *testing.T) (string, string) {
	t.Helper()
	cache := t.TempDir()
	path := filepath.Join(cache, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return cache, path
}

// Claim: a helper start error carries ErrNothingStarted only when the helper itself answered with
// a refusal; a lost or broken reply (the helper may have started sing-box and still hold it) and a
// timeout return no session and no marker, so a caller cannot read them as "nothing runs".
// Limit: the helper RPC is a fake returning each error shape.
func TestStartMarksOnlyHelperRefusalAsNothingStarted(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{"helper refusal", &vpncore.RefusedError{Message: "sing-box key $.x is not allowed"}, true},
		{"lost reply", io.ErrUnexpectedEOF, false},
		{"timeout", &vpncore.RPCTimeoutError{Action: "singbox.start"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			previous := vpnCoreStartSingBoxSession
			vpnCoreStartSingBoxSession = func([]byte, string, int, bool) (int, string, error) { return 0, "", tt.err }
			t.Cleanup(func() { vpnCoreStartSingBoxSession = previous })
			cache, path := writeStartConfig(t)
			got, err := Start(cache, path, model.Profile{}, helperStartOptions())
			if err == nil || got.ID != "" || got.PID != 0 {
				t.Fatalf("session %+v err %v, want an error and no session", got, err)
			}
			if errors.Is(err, ErrNothingStarted) != tt.want {
				t.Fatalf("ErrNothingStarted = %v, want %v (err %v)", !tt.want, tt.want, err)
			}
		})
	}
}

// Claim: when a sidecar start fails, the start carries ErrNothingStarted only if the cleanup after
// it succeeded; if that cleanup fails, a started sidecar may survive, so the error has no marker.
// The main sing-box is never started in either case. Limit: the sidecar fails before exec (its
// executable is not found) and the cleanup's process listing is a fake.
func TestStartSidecarFailureMarkedOnlyAfterCleanup(t *testing.T) {
	for _, tt := range []struct {
		name       string
		cleanupErr error
		want       bool
	}{{"cleanup succeeds", nil, true}, {"cleanup fails", errors.New("ps failed"), false}} {
		t.Run(tt.name, func(t *testing.T) {
			prevLook, prevList, prevStart := execLookPath, sidecarProcessListSession, vpnCoreStartSingBoxSession
			execLookPath = func(file string) (string, error) { return "", errors.New("not found: " + file) }
			lists := 0
			sidecarProcessListSession = func() ([]byte, error) {
				lists++
				if lists == 2 {
					return nil, tt.cleanupErr
				}
				return nil, nil
			}
			vpnCoreStartSingBoxSession = func([]byte, string, int, bool) (int, string, error) {
				t.Fatal("main sing-box started after a sidecar failure")
				return 0, "", nil
			}
			t.Cleanup(func() {
				execLookPath, sidecarProcessListSession, vpnCoreStartSingBoxSession = prevLook, prevList, prevStart
			})
			cache, path := writeStartConfig(t)
			_, err := Start(cache, path, model.Profile{}, helperStartOptions(SidecarOptions{Name: "xray", Executable: "xray-lab", Args: []string{"run", "-c", filepath.Join(cache, "xray.json")}}))
			if err == nil || lists != 2 {
				t.Fatalf("err %v, process listings %d (want the pre-start and the post-failure cleanup)", err, lists)
			}
			if errors.Is(err, ErrNothingStarted) != tt.want {
				t.Fatalf("ErrNothingStarted = %v, want %v (err %v)", !tt.want, tt.want, err)
			}
		})
	}
}

// Claim: SessionStopped is true only when the main process and every sidecar are gone; a dead main
// with a live sidecar is not stopped, and a sidecar liveness error is returned, never read as gone.
// Limit: process liveness and identity are fakes.
func TestSessionStoppedChecksSidecars(t *testing.T) {
	started := time.Now()
	current := CurrentSession{PID: 4242, ProcessComm: "sing-box", ProcessStart: started,
		Sidecars: []SidecarSession{{Name: "xray", PID: 5151, ProcessComm: "xray", ProcessStart: started, Command: []string{"/opt/xray"}}}}
	for _, tt := range []struct {
		name        string
		sidecarLive bool
		sidecarErr  error
		want        bool
		wantErr     bool
	}{
		{"main and sidecar gone", false, nil, true, false},
		{"main gone, sidecar alive", true, nil, false, false},
		{"sidecar liveness unknown", false, errors.New("lookup denied"), false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			prevMain, prevSide := processAliveSession, sidecarProcessAliveSession
			processAliveSession = func(int) (bool, error) { return false, nil }
			sidecarProcessAliveSession = func(int) (bool, error) { return tt.sidecarLive, tt.sidecarErr }
			t.Cleanup(func() { processAliveSession, sidecarProcessAliveSession = prevMain, prevSide })
			withProcessIdentity(t, "xray", started, nil)
			got, err := SessionStopped(current)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("SessionStopped = %v, %v; want %v, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// Claim: SaveCurrentIfAbsent never overwrites a current record: with another session's record
// present it fails with fs.ErrExist and the record bytes stay the same; with no record it writes
// the session (positive control).
func TestSaveCurrentIfAbsentNeverOverwrites(t *testing.T) {
	cache := t.TempDir()
	if err := SaveCurrent(cache, CurrentSession{ID: "other", PID: 7777}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(CurrentPath(cache))
	if err := SaveCurrentIfAbsent(cache, CurrentSession{ID: "replacement", PID: 9999}); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("save over another record: %v, want fs.ErrExist", err)
	}
	if after, _ := os.ReadFile(CurrentPath(cache)); !bytes.Equal(before, after) {
		t.Fatalf("another session's record changed:\n%s", after)
	}
	fresh := t.TempDir()
	if err := SaveCurrentIfAbsent(fresh, CurrentSession{ID: "replacement", PID: 9999}); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadCurrent(fresh); err != nil || got.ID != "replacement" {
		t.Fatalf("written record %+v err %v", got, err)
	}
}

// Claim: StopIfCurrent leaves a record of another session alone: it returns an error, sends no
// signal, makes no liveness probe and leaves the record bytes unchanged. Positive control: a record
// of the expected session goes on to the normal stop. Limit: signals and liveness are fakes.
func TestStopIfCurrentLeavesAnotherSessionAlone(t *testing.T) {
	prevSignal, prevAlive := vpnCoreSignalSession, processAliveSession
	signals, probes := 0, 0
	vpnCoreSignalSession = func(string, string) error { signals++; return nil }
	processAliveSession = func(int) (bool, error) { probes++; return false, nil }
	t.Cleanup(func() { vpnCoreSignalSession, processAliveSession = prevSignal, prevAlive })
	launch := config.PrivilegedLaunchConfig{Mode: config.LaunchModeHelper}

	cache := t.TempDir()
	if err := SaveCurrent(cache, CurrentSession{ID: "other", PID: 7777, Handle: "other-handle", LaunchMode: config.LaunchModeHelper}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(CurrentPath(cache))
	if _, _, err := StopIfCurrent(cache, "replacement", launch, true, time.Second); err == nil || !strings.Contains(err.Error(), "left alone") {
		t.Fatalf("stop of another record: %v", err)
	}
	if after, _ := os.ReadFile(CurrentPath(cache)); !bytes.Equal(before, after) || signals != 0 || probes != 0 {
		t.Fatalf("record changed=%v signals=%d probes=%d", !bytes.Equal(before, after), signals, probes)
	}

	own := t.TempDir()
	if err := SaveCurrent(own, CurrentSession{ID: "replacement", PID: 9999, Handle: "own-handle", LaunchMode: config.LaunchModeHelper}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StopIfCurrent(own, "replacement", launch, true, time.Second); err != nil && strings.Contains(err.Error(), "left alone") {
		t.Fatalf("own record refused: %v", err)
	}
	if probes == 0 {
		t.Fatal("own record did not reach the normal stop")
	}
}

// Claim: StopReturned stops a helper session only through its own opaque handle and refuses one
// without a handle (no PID fallback); a direct-mode session whose main process is already gone gets
// no signal. Limit: the helper signal and liveness are fakes; a live direct-mode process is not
// exercised here because that path sends a real signal.
func TestStopReturnedUsesOwnHandleOnly(t *testing.T) {
	prevSignal, prevAlive := vpnCoreSignalSession, processAliveSession
	var handles []string
	vpnCoreSignalSession = func(handle, signal string) error { handles = append(handles, handle+" "+signal); return nil }
	processAliveSession = func(int) (bool, error) { return false, nil }
	t.Cleanup(func() { vpnCoreSignalSession, processAliveSession = prevSignal, prevAlive })

	if err := StopReturned(CurrentSession{ID: "r", PID: 9999, Handle: "own-handle", LaunchMode: config.LaunchModeHelper}); err != nil || strings.Join(handles, ",") != "own-handle -KILL" {
		t.Fatalf("helper stop err %v signals %v", err, handles)
	}
	handles = nil
	if err := StopReturned(CurrentSession{ID: "r", PID: 9999, LaunchMode: config.LaunchModeHelper}); err == nil || len(handles) != 0 {
		t.Fatalf("helper stop without handle err %v signals %v", err, handles)
	}
	if err := StopReturned(CurrentSession{ID: "r", PID: 9999, LaunchMode: config.LaunchModeDirect}); err != nil || len(handles) != 0 {
		t.Fatalf("direct stop of a gone process err %v signals %v", err, handles)
	}
}
