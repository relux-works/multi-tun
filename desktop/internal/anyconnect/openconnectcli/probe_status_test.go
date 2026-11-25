package openconnectcli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"multi-tun/desktop/internal/anyconnect/openconnect"
)

func TestStatusRuntimeProbeErrorHasNoFalseStateVerdict(t *testing.T) {
	// Probe errors abort status before a state verdict; absence and an untracked runtime remain distinct valid controls despite Cisco unavailability.
	for _, name := range []string{"unknown", "absent", "present"} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			app := NewWithStatusDependencies(&stdout, &stderr, StatusDependencies{
				DetectState: func() (openconnect.State, string, error) {
					return openconnect.StateUnknown, "", errors.New("Cisco unavailable")
				},
				ConnectionInfo: func() (*openconnect.ConnectionInfo, string, error) {
					t.Fatal("unexpected Cisco query")
					return nil, "", nil
				},
				ListProfiles: func() ([]openconnect.CLIProfile, string, error) {
					t.Fatal("unexpected profile query")
					return nil, "", nil
				},
				CurrentRuntime: func() (*openconnect.RuntimeStatus, error) {
					if name == "unknown" {
						return nil, errors.New("inspect openconnect process: exit status 2")
					}
					if name == "present" {
						return &openconnect.RuntimeStatus{PID: 4242}, nil
					}
					return nil, nil
				},
				CurrentSession: func(string) (*openconnect.CurrentSession, string, bool, error) { return nil, "none", false, nil },
			})
			_, _, args := statusTestPaths(t)
			code := app.Run(args)
			if name == "unknown" {
				if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "status failed: inspect openconnect process") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
				return
			}
			want := "state: unknown\nstate_source: cisco_cli\n"
			if name == "present" {
				want = "state: connected\nstate_source: openconnect_runtime\n"
			}
			if code != 0 || !strings.Contains(stdout.String(), want) || !strings.Contains(stdout.String(), "session: none\n") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
