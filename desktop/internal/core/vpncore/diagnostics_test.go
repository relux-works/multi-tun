package vpncore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServiceSnapshotTracksQueuedActiveAndCompletedRequestsWithoutSecrets(t *testing.T) {
	cfg := startDiagnosticsTestDaemon(t, "activity")

	queuedConn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		t.Fatalf("Dial(queued connection) error = %v", err)
	}
	defer queuedConn.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "credential-secret.log")
	secretEndpoint := "https://vpn-secret.example.invalid/private"
	secretCookie := "COOKIE_SUPER_SECRET"
	secretCommandFragment := "sleep 0.25"
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- Run(cfg, []string{"/bin/sh", "-c", secretCommandFragment, secretEndpoint}, secretCookie, logPath)
	}()

	var activeStatus ServiceStatus
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, inspectErr := InspectService(cfg)
		if inspectErr == nil && status.HelperSnapshot != nil && len(status.HelperSnapshot.ActiveRequests) == 1 && len(status.HelperSnapshot.QueuedRequests) == 1 {
			activeStatus = status
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if activeStatus.HelperSnapshot == nil {
		t.Fatal("InspectService() did not report an active and queued request")
	}
	if got := activeStatus.HelperSnapshot.ActiveRequests[0].Action; got != "run" {
		t.Fatalf("active action = %q, want run", got)
	}
	if got := activeStatus.HelperSnapshot.QueuedRequests[0].Action; got != "pending" {
		t.Fatalf("queued action = %q, want pending", got)
	}

	rawSnapshot, err := json.Marshal(activeStatus.HelperSnapshot)
	if err != nil {
		t.Fatalf("json.Marshal(snapshot) error = %v", err)
	}
	for _, secret := range []string{secretEndpoint, secretCookie, secretCommandFragment, logPath, "credential-secret"} {
		if strings.Contains(string(rawSnapshot), secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, rawSnapshot)
		}
	}

	if err := queuedConn.Close(); err != nil {
		t.Fatalf("Close(queued connection) error = %v", err)
	}
	if err := <-runErrCh; err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	status, err := InspectService(cfg)
	if err != nil {
		t.Fatalf("InspectService() after completion error = %v", err)
	}
	if status.HelperSnapshot == nil || status.HelperSnapshot.LastCompletedRequest == nil {
		t.Fatalf("completed status = %#v, want last completed request", status)
	}
	last := status.HelperSnapshot.LastCompletedRequest
	if last.Action != "run" || last.Outcome != "ok" {
		t.Fatalf("last completed request = %#v, want successful run", last)
	}
	if len(status.HelperSnapshot.ActiveRequests) != 0 || len(status.HelperSnapshot.QueuedRequests) != 0 {
		t.Fatalf("completed snapshot = %#v, want no active or queued requests", status.HelperSnapshot)
	}
}

func TestRunTimeoutIncludesRedactedHelperSnapshotAndPreservesTimeoutCause(t *testing.T) {
	cfg := startDiagnosticsTestDaemon(t, "timeout")

	previousTimeout := rpcResponseTimeoutVPNCore
	rpcResponseTimeoutVPNCore = 40 * time.Millisecond
	t.Cleanup(func() {
		rpcResponseTimeoutVPNCore = previousTimeout
	})

	dir := t.TempDir()
	logPath := filepath.Join(dir, "credential-timeout.log")
	secretEndpoint := "https://vpn-timeout.example.invalid/private"
	secretCookie := "COOKIE_TIMEOUT_SECRET"
	secretCommandFragment := "sleep 0.2"
	err := Run(cfg, []string{"/bin/sh", "-c", secretCommandFragment, secretEndpoint}, secretCookie, logPath)
	if err == nil {
		t.Fatal("Run() error = nil, want RPC timeout")
	}

	var rpcTimeout *RPCTimeoutError
	if !errors.As(err, &rpcTimeout) {
		t.Fatalf("Run() error type = %T, want *RPCTimeoutError: %v", err, err)
	}
	var netTimeout net.Error
	if !errors.As(err, &netTimeout) || !netTimeout.Timeout() {
		t.Fatalf("Run() error does not preserve net timeout cause: %v", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Run() error does not unwrap to os.ErrDeadlineExceeded: %v", err)
	}
	if rpcTimeout.Status == nil || !rpcTimeout.Status.Reachable || rpcTimeout.Status.HelperSnapshot == nil {
		t.Fatalf("timeout snapshot status = %#v, want reachable helper snapshot", rpcTimeout.Status)
	}
	if got := err.Error(); !strings.Contains(got, "vpn core rpc run timed out after 40ms") || !strings.Contains(got, "helper snapshot: state=reachable") || !strings.Contains(got, "active_requests=run(") {
		t.Fatalf("Run() timeout error missing snapshot: %q", got)
	}
	for _, secret := range []string{secretEndpoint, secretCookie, secretCommandFragment, logPath, "credential-timeout"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("timeout diagnostic leaked %q: %v", secret, err)
		}
	}

	time.Sleep(250 * time.Millisecond)
}

func TestHelperSnapshotWireExtensionIsBackwardCompatible(t *testing.T) {
	newResponse, err := json.Marshal(Response{
		OK:        true,
		DaemonPID: 42,
		HelperSnapshot: &HelperSnapshot{
			ActiveRequests: []RequestSnapshot{{Action: "run", AgeMillis: 5000}},
			QueuedRequests: []RequestSnapshot{},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal(new response) error = %v", err)
	}
	var legacyResponse struct {
		OK        bool `json:"ok"`
		DaemonPID int  `json:"daemon_pid"`
	}
	if err := json.Unmarshal(newResponse, &legacyResponse); err != nil {
		t.Fatalf("legacy json.Unmarshal(new response) error = %v", err)
	}
	if !legacyResponse.OK || legacyResponse.DaemonPID != 42 {
		t.Fatalf("legacy response = %#v, want existing fields", legacyResponse)
	}

	var currentResponse Response
	if err := json.Unmarshal([]byte(`{"ok":true,"daemon_pid":43}`), &currentResponse); err != nil {
		t.Fatalf("current json.Unmarshal(legacy response) error = %v", err)
	}
	if !currentResponse.OK || currentResponse.DaemonPID != 43 || currentResponse.HelperSnapshot != nil {
		t.Fatalf("current response = %#v, want legacy fields with nil snapshot", currentResponse)
	}
}

func TestHelperSnapshotFormattingSanitizesUntrustedMetadata(t *testing.T) {
	snapshot := &HelperSnapshot{
		ActiveRequests: []RequestSnapshot{{Action: "https://secret.example.invalid", AgeMillis: -1}},
		QueuedRequests: []RequestSnapshot{{Action: "pending", AgeMillis: 2}},
		LastCompletedRequest: &CompletedRequestSnapshot{
			Action:         "COOKIE_ACTION_SECRET",
			Outcome:        "credential-secret",
			DurationMillis: -3,
			AgeMillis:      -4,
		},
	}
	got := FormatHelperSnapshot(snapshot)
	want := "active_requests=other(age=0ms) queued_requests=pending(age=2ms) last_completed_request=other(outcome=unknown,duration=0ms,age=0ms)"
	if got != want {
		t.Fatalf("FormatHelperSnapshot() = %q, want %q", got, want)
	}
	for _, secret := range []string{"secret.example.invalid", "COOKIE_ACTION_SECRET", "credential-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("FormatHelperSnapshot() leaked %q: %q", secret, got)
		}
	}
	if got := FormatHelperSnapshot(nil); got != "unavailable" {
		t.Fatalf("FormatHelperSnapshot(nil) = %q, want unavailable", got)
	}
	if got := FormatCompletedRequestSnapshot(nil); got != "none" {
		t.Fatalf("FormatCompletedRequestSnapshot(nil) = %q, want none", got)
	}
	if got := formatTimeoutServiceStatus(nil); got != "state=unavailable" {
		t.Fatalf("formatTimeoutServiceStatus(nil) = %q, want state=unavailable", got)
	}
	if got := formatTimeoutServiceStatus(&ServiceStatus{}); got != "state=missing" {
		t.Fatalf("formatTimeoutServiceStatus(missing) = %q, want state=missing", got)
	}

	timeoutErr := &RPCTimeoutError{
		Action:          "secret-action",
		ResponseTimeout: time.Second,
		cause:           os.ErrDeadlineExceeded,
	}
	var netErr net.Error
	if !errors.As(timeoutErr, &netErr) || !netErr.Timeout() || !netErr.Temporary() {
		t.Fatalf("RPCTimeoutError does not preserve net.Error semantics: %#v", timeoutErr)
	}
	if strings.Contains(timeoutErr.Error(), "secret-action") {
		t.Fatalf("RPCTimeoutError leaked unsafe action: %v", timeoutErr)
	}
}

func startDiagnosticsTestDaemon(t *testing.T, name string) ServiceConfig {
	t.Helper()

	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("vpn-core-diagnostics-%s-%d.sock", name, time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	t.Cleanup(func() {
		_ = os.Remove(socketPath)
	})

	cfg := ServiceConfig{
		Label:      "test-diagnostics-" + name,
		PlistPath:  "test-diagnostics-" + name,
		SocketPath: socketPath,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)
	return cfg
}
