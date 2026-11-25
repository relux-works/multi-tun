package vpncore

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestInspectServiceProjectsMaintenanceFromPingOnly(t *testing.T) {
	// Authenticated status preserves the optional capability, including active state; legacy omission stays nil and sends only ping.
	for _, state := range []*MaintenanceDrainState{nil, {}, {Active: true, ExpiresAt: "2026-11-26T15:00:00Z"}} {
		cfg, listener := newRPCClientTestListener(t)
		withRPCServerIdentity(t, 4242, func(*net.UnixConn) (uint32, error) { return 4242, nil })
		observed := make(chan Request, 1)
		serverErr := make(chan error, 1)
		go func() {
			conn, err := listener.AcceptUnix()
			if err != nil {
				serverErr <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var request Request
			if err := json.NewDecoder(conn).Decode(&request); err != nil {
				serverErr <- err
				return
			}
			observed <- request
			serverErr <- json.NewEncoder(conn).Encode(Response{OK: true, DaemonPID: 42, MaintenanceDrain: state})
		}()
		status, err := InspectService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
		request := <-observed
		if request.Action != "ping" || request.Token != "" {
			t.Fatalf("unexpected request: %#v", request)
		}
		if !status.Reachable || status.DaemonPID != 42 || (status.MaintenanceDrain == nil) != (state == nil) {
			t.Fatalf("status lost ping state: %#v", status)
		}
		if state != nil && *status.MaintenanceDrain != *state {
			t.Fatalf("drain=%#v want=%#v", status.MaintenanceDrain, state)
		}
	}
}
