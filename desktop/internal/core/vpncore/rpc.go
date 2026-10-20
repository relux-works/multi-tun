package vpncore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	rpcDialTimeoutVPNCore            = 2 * time.Second
	rpcTimeoutSnapshotTimeoutVPNCore = 750 * time.Millisecond
	maxRequestBytesVPNCore           = 1 << 20
)

var (
	rpcResponseTimeoutVPNCore          = 5 * time.Second
	expectedRPCServerUIDVPNCore uint32 = 0
	rpcPeerUIDVPNCore                  = localPeerUID
)

type Request struct {
	Action      string   `json:"action"`
	ConfigJSON  []byte   `json:"config_json,omitempty"`
	Stdin       string   `json:"stdin,omitempty"`
	LogMaxLines int      `json:"log_max_lines,omitempty"`
	Handle      string   `json:"handle,omitempty"`
	Signal      string   `json:"signal,omitempty"`
	SetPGID     bool     `json:"setpgid,omitempty"`
	Service     string   `json:"service,omitempty"`
	Servers     []string `json:"servers,omitempty"`
	Interface   string   `json:"interface,omitempty"`
	Filter      []string `json:"filter,omitempty"`
	ApplePCAPNG bool     `json:"apple_pcapng,omitempty"`
	RunAsUser   bool     `json:"run_as_user,omitempty"`
}

type Response struct {
	OK             bool            `json:"ok"`
	Error          string          `json:"error,omitempty"`
	DaemonPID      int             `json:"daemon_pid,omitempty"`
	PID            int             `json:"pid,omitempty"`
	Handle         string          `json:"handle,omitempty"`
	Path           string          `json:"path,omitempty"`
	HelperSnapshot *HelperSnapshot `json:"helper_snapshot,omitempty"`
}

func call(cfg ServiceConfig, request Request) (Response, error) {
	return callWithTimeoutAndLog(cfg, request, rpcResponseTimeoutVPNCore, nil)
}

func callWithTimeout(cfg ServiceConfig, request Request, timeout time.Duration) (Response, error) {
	return callWithTimeoutAndLog(cfg, request, timeout, nil)
}

func callWithTimeoutAndLog(cfg ServiceConfig, request Request, timeout time.Duration, logFile *os.File) (Response, error) {
	if timeout <= 0 {
		timeout = rpcResponseTimeoutVPNCore
	}
	dialTimeout := minDuration(rpcDialTimeoutVPNCore, timeout)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", cfg.SocketPath)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return Response{}, errors.New("vpn core socket is not a unix connection")
	}
	peerUID, err := rpcPeerUIDVPNCore(unixConn)
	if err != nil {
		return Response{}, fmt.Errorf("read vpn core socket peer uid: %w", err)
	}
	if peerUID != expectedRPCServerUIDVPNCore {
		return Response{}, fmt.Errorf("vpn core socket peer uid %d is not root; refusing to send the request", peerUID)
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Response{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return Response{}, err
	}
	payload = append(payload, '\n')
	if len(payload) > maxRequestBytesVPNCore {
		return Response{}, fmt.Errorf("vpn core request exceeds %d bytes", maxRequestBytesVPNCore)
	}
	var rights []byte
	if logFile != nil {
		rights = unix.UnixRights(int(logFile.Fd()))
	}
	written, _, err := unixConn.WriteMsgUnix(payload, rights, nil)
	if err != nil {
		return Response{}, err
	}
	for written < len(payload) {
		n, err := unixConn.Write(payload[written:])
		if err != nil {
			return Response{}, err
		}
		written += n
	}

	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return Response{}, err
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}

// RPCTimeoutError preserves the network timeout while attaching a redacted
// helper status sampled through the existing ping request.
type RPCTimeoutError struct {
	Action          string
	ResponseTimeout time.Duration
	Status          *ServiceStatus
	cause           error
}

func (e *RPCTimeoutError) Error() string {
	return fmt.Sprintf(
		"vpn core rpc %s timed out after %s; helper snapshot: %s",
		safeRequestAction(e.Action),
		e.ResponseTimeout,
		formatTimeoutServiceStatus(e.Status),
	)
}

func (e *RPCTimeoutError) Unwrap() error {
	return e.cause
}

func (e *RPCTimeoutError) Timeout() bool {
	return true
}

func (e *RPCTimeoutError) Temporary() bool {
	return true
}

func isRPCTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func isUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "connect: no such file") ||
		strings.Contains(message, "connect: connection refused")
}
