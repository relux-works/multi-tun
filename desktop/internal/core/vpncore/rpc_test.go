package vpncore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type observedRPCRequest struct {
	payloadBytes int
	rightsBytes  int
	err          error
}

func TestRPCClientRejectsUnexpectedServerUIDBeforeSendingRequestOrFD(t *testing.T) {
	// This proves a mismatched server uid is refused before any request byte or SCM_RIGHTS descriptor reaches the listener.
	cfg, listener := newRPCClientTestListener(t)
	observed := make(chan observedRPCRequest, 1)
	go observeRPCClientRequest(listener, observed, false)

	withRPCServerIdentity(t, 0, func(*net.UnixConn) (uint32, error) { return 501, nil })
	logFile, err := os.OpenFile(filepath.Join(t.TempDir(), "client.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	_, err = callWithTimeoutAndLog(cfg, Request{Action: "ping"}, time.Second, logFile)
	result := <-observed
	if result.payloadBytes != 0 || result.rightsBytes != 0 {
		t.Fatalf("listener received payload=%d rights=%d, want no request data", result.payloadBytes, result.rightsBytes)
	}
	if result.err != nil && !errors.Is(result.err, io.EOF) {
		t.Fatalf("listener read error = %v, want EOF after empty connection", result.err)
	}
	if err == nil || !strings.Contains(err.Error(), "vpn core socket peer uid 501 is not root; refusing to send the request") {
		t.Fatalf("callWithTimeoutAndLog() error = %v, want peer uid refusal", err)
	}
}

func TestRPCClientAcceptsExpectedServerUID(t *testing.T) {
	// This proves a matching server uid passes authentication and permits a request-response exchange.
	cfg, listener := newRPCClientTestListener(t)
	observed := make(chan observedRPCRequest, 1)
	go observeRPCClientRequest(listener, observed, true)

	withRPCServerIdentity(t, 4242, func(*net.UnixConn) (uint32, error) { return 4242, nil })
	response, err := callWithTimeoutAndLog(cfg, Request{Action: "ping"}, time.Second, nil)
	if err != nil {
		t.Fatalf("callWithTimeoutAndLog() error = %v", err)
	}
	if !response.OK {
		t.Fatalf("callWithTimeoutAndLog() response = %#v, want OK", response)
	}
	result := <-observed
	if result.err != nil {
		t.Fatalf("listener read error = %v", result.err)
	}
	if result.payloadBytes == 0 {
		t.Fatal("listener received no request payload")
	}
}

func withRPCServerIdentity(t *testing.T, expected uint32, lookup peerUIDLookup) {
	t.Helper()
	previousExpected := expectedRPCServerUIDVPNCore
	previousLookup := rpcPeerUIDVPNCore
	expectedRPCServerUIDVPNCore = expected
	rpcPeerUIDVPNCore = lookup
	t.Cleanup(func() {
		expectedRPCServerUIDVPNCore = previousExpected
		rpcPeerUIDVPNCore = previousLookup
	})
}

func newRPCClientTestListener(t *testing.T) (ServiceConfig, *net.UnixListener) {
	t.Helper()
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("vpn-core-rpc-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})
	return ServiceConfig{SocketPath: socketPath}, listener
}

func observeRPCClientRequest(listener *net.UnixListener, observed chan<- observedRPCRequest, respond bool) {
	conn, err := listener.AcceptUnix()
	if err != nil {
		observed <- observedRPCRequest{err: err}
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	payload := make([]byte, maxRequestBytesVPNCore)
	rights := make([]byte, 128)
	payloadBytes, rightsBytes, _, _, err := conn.ReadMsgUnix(payload, rights)
	result := observedRPCRequest{payloadBytes: payloadBytes, rightsBytes: rightsBytes, err: err}
	if err == nil && respond {
		result.err = json.NewEncoder(conn).Encode(Response{OK: true})
	}
	observed <- result
}
