package openconnectcli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"multi-tun/desktop/internal/anyconnect/openconnect"
)

// Persistent lookup failures expose the saved recovery context as unknown and fail status without altering the record; healthy status retains its exact output.
func TestRunStatusSessionIdentity(t *testing.T) {
	failure := errors.New("verify identity of openconnect pid 4242: identity denied")
	for _, lookupErr := range []error{failure, nil} {
		name := "healthy"
		if lookupErr != nil {
			name = "persistent identity error"
		}
		t.Run(name, func(t *testing.T) {
			configPath, cacheDir, args := statusTestPaths(t)
			current := openconnect.CurrentSession{
				ID: "recovery", PID: 4242, Mode: openconnect.ConnectModeSplitInclude,
				PrivilegedMode: openconnect.PrivilegedModeHelper, HelperSocketPath: "/fixture/helper.sock",
				Server: "vpn.example.test/outside", Interface: "utun8",
				StartedAt: time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC),
			}
			if err := openconnect.SaveCurrent(cacheDir, current); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(openconnect.CurrentPath(cacheDir))
			if err != nil {
				t.Fatal(err)
			}
			previousAlive := sessionAliveOpenConnectCLI
			t.Cleanup(func() { sessionAliveOpenConnectCLI = previousAlive })
			lookups := 0
			sessionAliveOpenConnectCLI = func(saved openconnect.CurrentSession) (bool, int, error) {
				lookups++
				if !reflect.DeepEqual(saved, current) {
					t.Fatalf("liveness received %+v, want saved %+v", saved, current)
				}
				return lookupErr == nil, current.PID, lookupErr
			}
			dependencies := StatusDependencies{
				DetectState:    func() (openconnect.State, string, error) { return openconnect.StateDisconnected, "", nil },
				ConnectionInfo: func() (*openconnect.ConnectionInfo, string, error) { return nil, "", nil },
				CurrentRuntime: func() (*openconnect.RuntimeStatus, error) {
					return &openconnect.RuntimeStatus{PID: 4242, Interface: "utun8", Uptime: "00:36"}, nil
				},
				ListProfiles:   func() ([]openconnect.CLIProfile, string, error) { return nil, "", nil },
				CurrentSession: currentSessionState,
			}
			var stdout, stderr bytes.Buffer
			app := NewWithStatusDependencies(&stdout, &stderr, dependencies)
			// Repeated status must keep the context visible for as long as the lookup error persists.
			for attempt := 0; attempt < 2; attempt++ {
				stdout.Reset()
				stderr.Reset()
				exitCode := app.Run(args)
				state := "active"
				wantCode, wantErr := 0, ""
				if lookupErr != nil {
					state = "unknown"
					wantCode, wantErr = 1, "status failed: "+failure.Error()+"\n"
				}
				want := fmt.Sprintf("config: %s\ncache_dir: %s\nsession: %s\nsession_id: recovery\nsession_mode: split-include\nsession_privileged_mode: helper\nsession_server: vpn.example.test/outside\nstarted_at: 2026-10-25T08:00:00Z\nsession_interface: utun8\nhelper_socket: /fixture/helper.sock\n", configPath, cacheDir, state)
				if lookupErr != nil {
					want += "openconnect_pid: 4242\nsession identity unknown: " + failure.Error() + "\n"
				} else {
					want += "vpn_binary: missing\nstate: connected\nstate_source: openconnect_runtime\ncisco_state: disconnected\nduration: 00:36\nopenconnect_pid: 4242\nopenconnect_interface: utun8\nopenconnect_uptime: 00:36\ncli_profiles: 0\n"
				}
				if exitCode != wantCode || stdout.String() != want || stderr.String() != wantErr {
					t.Fatalf("exit=%d want=%d\nstdout=%q\nwant=%q\nstderr=%q want=%q", exitCode, wantCode, stdout.String(), want, stderr.String(), wantErr)
				}
			}
			after, err := os.ReadFile(openconnect.CurrentPath(cacheDir))
			if err != nil || !bytes.Equal(before, after) || lookups != 2 {
				t.Fatalf("saved record err=%v changed=%v lookups=%d", err, !bytes.Equal(before, after), lookups)
			}
		})
	}
}
