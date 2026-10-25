package vpncore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestServiceMaintenanceInstallRetryInheritedLease(t *testing.T) {
	// Two unavailable probes followed by real startup preserve an orphaned lease and report completed-with-warning; clean runtime succeeds and immediately admits start.
	for _, orphaned := range []bool{true, false} {
		t.Run(map[bool]string{true: "orphaned", false: "clean"}[orphaned], func(t *testing.T) {
			d1 := maintenanceDaemonGroupParent(t)
			cfg := testInstallConfig(t)
			cfg.RuntimeDir = d1.cfg.RuntimeDir
			_, run := maintenanceServiceFixture(t, "install", cfg)
			d1.cfg = cfg
			expiry := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
			var before []byte
			if orphaned {
				before = fixtureLeaseBytes(t, expiry)
				writeMaintenanceLeaseFixture(t, d1, before)
			}
			var replacement *serviceDaemon
			probes, pings := 0, 0
			withMaintenanceCall(t, func(got ServiceConfig, request Request) (Response, error) {
				if got != cfg {
					t.Fatal("wrong fixture config")
				}
				if replacement == nil {
					if request.Action != "maintenance.drain" {
						t.Fatal("unexpected pre-bootstrap RPC")
					}
					probes++
					return Response{}, os.ErrNotExist
				}
				if request.Action != "ping" || request.Token != "" {
					t.Fatal("retry attempted unowned lease mutation")
				}
				pings++
				return maintenanceRequest(t, replacement, request), nil
			})
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				if name == "launchctl" {
					switch args[0] {
					case "print":
						return nil, launchctlTestError(113, nil)
					case "bootstrap":
						if probes != 2 {
							t.Fatalf("pre-bootstrap probes=%d", probes)
						}
						replacement = newMaintenanceTestDaemon(t, cfg)
						replacement.leaseFiles = d1.leaseFiles
						startMaintenanceFixture(t, replacement)
						if (replacement.drainToken != "") != orphaned {
							t.Fatal("startup did not reflect retained lease")
						}
					}
				}
				return nil, performFakeInstall(name, args, nil)
			})
			err := run()
			var warning *InstallMaintenanceError
			if orphaned {
				if !errors.As(err, &warning) || !warning.Installed || !warning.DrainActive || !warning.ExpiresAt.Equal(expiry) {
					t.Fatalf("orphaned lease install reported clean success or wrong outcome: %v", err)
				}
				want := "warning: tunnel starts are blocked until " + expiry.Format(time.RFC3339) + " by a maintenance lease from an earlier operation"
				if err.Error() != want {
					t.Fatalf("warning=%q", err.Error())
				}
				if strings.Contains(err.Error(), strings.Repeat("a", 64)) {
					t.Fatal("warning leaked token")
				}
				after, readErr := os.ReadFile(maintenanceLeasePath(replacement))
				if readErr != nil || !bytes.Equal(before, after) {
					t.Fatal("retry changed prior owner's persisted lease")
				}
			} else if err != nil {
				t.Fatalf("clean install warning: %v", err)
			}
			if replacement == nil || probes != 2 || pings < 1 {
				t.Fatal("bootstrap/readiness not exercised")
			}
			starts := fixtureSingBoxStart(replacement)
			r := maintenanceRequest(t, replacement, Request{Action: "singbox.start"})
			if orphaned {
				if r.OK || r.Error != "vpn core is draining for maintenance" || *starts != 0 {
					t.Fatal("retry released unowned lease or admitted blocked start")
				}
			} else {
				if !r.OK || *starts != 1 {
					t.Fatal("clean retry refused immediate start")
				}
				assertMaintenanceLeaseAbsent(t, replacement)
			}
		})
	}
}

func withMaintenanceCall(t *testing.T, fn func(ServiceConfig, Request) (Response, error)) {
	t.Helper()
	previous, previousPing := maintenanceCallVPNCore, maintenancePingVPNCore
	maintenanceCallVPNCore = fn
	maintenancePingVPNCore = func(cfg ServiceConfig, _ time.Duration) (Response, error) { return fn(cfg, Request{Action: "ping"}) }
	t.Cleanup(func() { maintenanceCallVPNCore, maintenancePingVPNCore = previous, previousPing })
}

func maintenanceServiceFixture(t *testing.T, operation string, configs ...ServiceConfig) (ServiceConfig, func(...MaintenanceOptions) error) {
	t.Helper()
	cfg := testInstallConfig(t)
	if len(configs) != 0 {
		cfg = configs[0]
	}
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	if operation == "uninstall" {
		return cfg, func(options ...MaintenanceOptions) error { return UninstallService(cfg, options...) }
	}
	binary := writeInstallTestBinary(t)
	tool := filepath.Join(t.TempDir(), "fixture-sing-box")
	if err := os.WriteFile(tool, []byte("fixture tool, never executed"), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := lookPathInstallVPNCore
	lookPathInstallVPNCore = func(string) (string, error) { return tool, nil }
	t.Cleanup(func() { lookPathInstallVPNCore = previous })
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, func(options ...MaintenanceOptions) error {
		return InstallService(cfg, binary, 501, 20, digest, options...)
	}
}

func TestServiceMaintenanceRefusalsPrecedePrivilege(t *testing.T) {
	// Busy, old, untrusted, and unresponsive daemons abort install/uninstall before authentication or privileged changes.
	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"busy", errors.New("vpn core is busy: 1 sing-box, 1 tcpdump child active"), []string{"1 sing-box", "1 tcpdump", "stop the tunnels", "--allow-disruption"}},
		{"old", errors.New(`unsupported vpn core action "maintenance.drain"`), []string{"running daemon", "cannot confirm idleness", "stop the tunnels", "--allow-disruption"}},
		{"identity", errors.New("vpn core socket peer uid 501 is not root"), []string{"not root"}},
		{"timeout", os.ErrDeadlineExceeded, []string{"i/o timeout"}},
	}
	for _, operation := range []string{"install", "uninstall"} {
		for _, tc := range cases {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				cfg, run := maintenanceServiceFixture(t, operation)
				privileged, calls := 0, 0
				withInstallSeams(t, func() error { privileged++; return nil }, func(string, ...string) ([]byte, error) { privileged++; return nil, nil })
				withMaintenanceCall(t, func(got ServiceConfig, request Request) (Response, error) {
					calls++
					if got != cfg || request.Action != "maintenance.drain" {
						t.Fatalf("unexpected RPC: %+v %+v", got, request)
					}
					return Response{}, tc.err
				})
				err := run()
				for _, want := range tc.want {
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Errorf("error=%v, want %q", err, want)
					}
				}
				if privileged != 0 || calls != 1 {
					t.Fatalf("privileged=%d RPCs=%d", privileged, calls)
				}
				if _, err := os.Stat(cfg.HelperDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("installed path changed: %v", err)
				}
			})
		}
	}
}

func TestServiceMaintenanceIdleUnavailableAndOverrideProceed(t *testing.T) {
	// Idle/unavailable daemons permit fixture changes; override skips drain/renew but install still verifies replacement readiness and drain status.
	for _, operation := range []string{"install", "uninstall"} {
		for _, mode := range []string{"idle", "missing", "refused", "override"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				cfg, run := maintenanceServiceFixture(t, operation)
				var calls, commands []string
				withMaintenanceCall(t, func(_ ServiceConfig, request Request) (Response, error) {
					calls = append(calls, request.Action)
					if request.Action == "ping" {
						return Response{OK: true, MaintenanceDrain: &MaintenanceDrainState{}}, nil
					}
					switch mode {
					case "missing":
						return Response{}, &net.OpError{Op: "dial", Net: "unix", Err: syscall.ENOENT}
					case "refused":
						return Response{}, &net.OpError{Op: "dial", Net: "unix", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
					case "override":
						t.Fatal("override called daemon")
					}
					return Response{OK: true, Token: strings.Repeat("a", 64), MaintenanceDrain: &MaintenanceDrainState{}}, nil
				})
				withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
					commands = append(commands, strings.Join(append([]string{name}, args...), " "))
					if len(calls) == 0 && mode != "override" {
						t.Fatal("privilege before drain")
					}
					if name == "launchctl" && args[0] == "print" {
						return nil, launchctlTestError(113, nil)
					}
					return nil, performFakeInstall(name, args, nil)
				})
				if err := run(MaintenanceOptions{AllowDisruption: mode == "override"}); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(strings.Join(commands, "\n"), "launchctl bootout system/"+cfg.Label) {
					t.Fatal("did not reach fixture bootout")
				}
				if mode == "override" {
					want := []string(nil)
					if operation == "install" {
						want = []string{"ping", "ping"}
					}
					if !reflect.DeepEqual(calls, want) {
						t.Fatal(calls)
					}
				} else if mode == "idle" && !reflect.DeepEqual(calls, map[string][]string{
					"install":   {"maintenance.drain", "maintenance.renew", "ping", "maintenance.undrain", "ping"},
					"uninstall": {"maintenance.drain", "maintenance.renew"},
				}[operation]) {
					t.Fatal(calls)
				} else if mode != "idle" {
					want := []string{"maintenance.drain", "maintenance.drain"}
					if operation == "install" {
						want = append(want, "ping", "ping")
					}
					if !reflect.DeepEqual(calls, want) {
						t.Fatal(calls)
					}
				}
			})
		}
	}
}

func TestServiceMaintenanceFailureUndrains(t *testing.T) {
	// Authentication/pre-bootout copy failures release a successful drain; failure to undrain preserves the original error.
	for _, operation := range []string{"install", "uninstall"} {
		for _, mode := range []string{"auth", "command", "undrain-error"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				_, run := maintenanceServiceFixture(t, operation)
				var calls []string
				failure := errors.New("fixture pre-bootout failure")
				withMaintenanceCall(t, func(_ ServiceConfig, request Request) (Response, error) {
					calls = append(calls, request.Action)
					if mode == "undrain-error" && request.Action == "maintenance.undrain" {
						return Response{}, errors.New("fixture rollback error")
					}
					return Response{OK: true, Token: strings.Repeat("a", 64), MaintenanceDrain: &MaintenanceDrainState{}}, nil
				})
				withInstallSeams(t, func() error {
					if mode != "command" || operation == "uninstall" {
						return failure
					}
					return nil
				}, func(name string, args ...string) ([]byte, error) {
					if name == "launchctl" && args[0] == "bootout" {
						t.Fatal("failure should precede bootout")
					}
					return nil, failure
				})
				if err := run(); !errors.Is(err, failure) {
					t.Fatalf("error=%v", err)
				}
				if !reflect.DeepEqual(calls, []string{"maintenance.drain", "maintenance.undrain"}) {
					t.Fatal(calls)
				}
			})
		}
	}
}

func TestServiceMaintenanceCompatibilityRefusalUndrainsPrimary(t *testing.T) {
	// A busy compatibility daemon aborts the whole operation before privilege and releases the already drained primary.
	for _, operation := range []string{"install", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			cfg, run := maintenanceServiceFixture(t, operation)
			compat := testInstallConfig(t)
			compat.Label = "fixture-compatibility"
			previous := compatibilityServiceConfigsVPNCore
			compatibilityServiceConfigsVPNCore = func(ServiceConfig) []compatibilityConfig { return []compatibilityConfig{{ServiceConfig: compat}} }
			t.Cleanup(func() { compatibilityServiceConfigsVPNCore = previous })
			var calls []string
			withMaintenanceCall(t, func(got ServiceConfig, request Request) (Response, error) {
				calls = append(calls, got.Label+"/"+request.Action)
				if got == compat {
					return Response{}, errors.New("1 tcpdump child active")
				}
				return Response{OK: true, Token: strings.Repeat("a", 64), MaintenanceDrain: &MaintenanceDrainState{}}, nil
			})
			withInstallSeams(t, func() error { t.Fatal("unexpected auth"); return nil }, func(string, ...string) ([]byte, error) { t.Fatal("unexpected privileged change"); return nil, nil })
			if err := run(); err == nil || !strings.Contains(err.Error(), "1 tcpdump") {
				t.Fatal(err)
			}
			want := []string{cfg.Label + "/maintenance.drain", compat.Label + "/maintenance.drain", cfg.Label + "/maintenance.undrain"}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls=%v want=%v", calls, want)
			}
		})
	}
}

func TestServiceMaintenanceRenewRefusalPreventsBootout(t *testing.T) {
	// Final renew expiry/wrong-token/busy/protocol failures abort install/uninstall before bootout and attempt owned rollback.
	for _, operation := range []string{"install", "uninstall"} {
		for _, mode := range []string{"expired", "wrong-token", "busy", "unexpected", "false-ok", "missing-token"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				_, run := maintenanceServiceFixture(t, operation)
				var calls []string
				withMaintenanceCall(t, func(_ ServiceConfig, request Request) (Response, error) {
					calls = append(calls, request.Action)
					if request.Action != "maintenance.drain" && request.Token != strings.Repeat("a", 64) {
						t.Fatal("lost token")
					}
					if request.Action == "maintenance.renew" {
						switch mode {
						case "unexpected":
							return Response{OK: true, Token: strings.Repeat("b", 64)}, nil
						case "false-ok":
							return Response{}, nil
						case "missing-token":
							return Response{OK: true}, nil
						default:
							return Response{}, errors.New("fixture renew " + mode)
						}
					}
					if request.Action == "maintenance.undrain" {
						return Response{}, errors.New("stale release refused")
					}
					return Response{OK: true, Token: strings.Repeat("a", 64), MaintenanceDrain: &MaintenanceDrainState{}}, nil
				})
				withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
					if name == "launchctl" {
						t.Fatal("refused renew reached launchctl")
					}
					return nil, performFakeInstall(name, args, nil)
				})
				if err := run(); err == nil || !strings.Contains(err.Error(), "cannot renew") {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(calls, []string{"maintenance.drain", "maintenance.renew", "maintenance.undrain"}) {
					t.Fatal(calls)
				}
			})
		}
	}
}

func TestServiceMaintenanceAuthenticatesRPCPeer(t *testing.T) {
	// The maintenance guard sends its fieldless request only after the existing root-peer check accepts a temporary socket.
	for _, uid := range []uint32{0, 501} {
		t.Run(map[uint32]string{0: "root", 501: "non-root"}[uid], func(t *testing.T) {
			cfg := ServiceConfig{SocketPath: "fixture-socketpair"}
			server, client := unixSocketPair(t)
			previousDial := rpcDialVPNCore
			rpcDialVPNCore = func(context.Context, string, string) (net.Conn, error) { return client, nil }
			t.Cleanup(func() { rpcDialVPNCore = previousDial })
			withRPCServerIdentity(t, 0, func(*net.UnixConn) (uint32, error) { return uid, nil })
			observed := make(chan Request, 1)
			go func() {
				conn := server
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var request Request
				if json.NewDecoder(conn).Decode(&request) == nil {
					_ = json.NewEncoder(conn).Encode(Response{OK: true, Token: strings.Repeat("a", 64)})
				}
				observed <- request
			}()
			guard, err := drainServices([]ServiceConfig{cfg}, nil)
			request := <-observed
			if uid == 0 {
				if err != nil || request.Action != "maintenance.drain" {
					t.Fatalf("request=%+v error=%v", request, err)
				}
				guard.forgotten(cfg.Label)
			} else if err == nil || !strings.Contains(err.Error(), "not root") || request.Action != "" {
				t.Fatalf("request=%+v error=%v", request, err)
			}
		})
	}
}

func TestServiceMaintenanceUnavailableBecomesBusyBeforeBootout(t *testing.T) {
	// A daemon missing initially but busy after auth aborts all further privileged changes, releasing any other held lease.
	for _, operation := range []string{"install", "uninstall"} {
		for _, compatibility := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/primary", true: "/compatibility"}[compatibility], func(t *testing.T) {
				cfg, run := maintenanceServiceFixture(t, operation)
				target := cfg
				if compatibility {
					target = testInstallConfig(t)
					target.Label = "fixture-compatibility"
					previous := compatibilityServiceConfigsVPNCore
					compatibilityServiceConfigsVPNCore = func(ServiceConfig) []compatibilityConfig { return []compatibilityConfig{{ServiceConfig: target}} }
					t.Cleanup(func() { compatibilityServiceConfigsVPNCore = previous })
				}
				prepared, refused, released := false, false, false
				probes := 0
				withMaintenanceCall(t, func(got ServiceConfig, request Request) (Response, error) {
					if got.Label == target.Label {
						if request.Action != "maintenance.drain" {
							t.Fatalf("unexpected target RPC: %+v", request)
						}
						probes++
						if !prepared {
							return Response{}, os.ErrNotExist
						}
						refused = true
						return Response{}, errors.New("vpn core is busy: 1 sing-box child active")
					}
					if request.Action == "maintenance.undrain" {
						if !refused || request.Token != strings.Repeat("a", 64) {
							t.Fatal("bad rollback")
						}
						released = true
					}
					return Response{OK: true, Token: strings.Repeat("a", 64), MaintenanceDrain: &MaintenanceDrainState{}}, nil
				})
				withInstallSeams(t, func() error { prepared = true; return nil }, func(name string, args ...string) ([]byte, error) {
					if refused {
						t.Fatal("privileged change after final refusal")
					}
					if name == "launchctl" {
						t.Fatal("busy daemon reached launchctl")
					}
					return nil, performFakeInstall(name, args, nil)
				})
				if err := run(); err == nil || !strings.Contains(err.Error(), "1 sing-box") {
					t.Fatal(err)
				}
				if probes != 2 || !refused || released != compatibility {
					t.Fatalf("probes=%d refused=%v released=%v", probes, refused, released)
				}
			})
		}
	}
}

func TestServiceMaintenanceFinalAcquisitionRenewsBeforeBootout(t *testing.T) {
	// An initially absent daemon that becomes idle is drained and renewed immediately before fixture bootout.
	for _, operation := range []string{"install", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			_, run := maintenanceServiceFixture(t, operation)
			prepared, booted := false, false
			last := ""
			var calls []string
			withMaintenanceCall(t, func(_ ServiceConfig, request Request) (Response, error) {
				calls = append(calls, request.Action)
				last = request.Action
				if !prepared {
					return Response{}, os.ErrNotExist
				}
				if request.Action == "maintenance.renew" && request.Token != strings.Repeat("a", 64) {
					t.Fatal("lost acquired token")
				}
				return Response{OK: true, Token: strings.Repeat("a", 64), MaintenanceDrain: &MaintenanceDrainState{}}, nil
			})
			withInstallSeams(t, func() error { prepared = true; return nil }, func(name string, args ...string) ([]byte, error) {
				if name == "launchctl" && args[0] == "bootout" {
					if last != "maintenance.renew" {
						t.Fatal("bootout without immediately preceding renew")
					}
					booted = true
				}
				last = name
				if name == "launchctl" && args[0] == "print" {
					return nil, launchctlTestError(113, nil)
				}
				return nil, performFakeInstall(name, args, nil)
			})
			if err := run(); err != nil {
				t.Fatal(err)
			}
			want := []string{"maintenance.drain", "maintenance.drain", "maintenance.renew"}
			if operation == "install" {
				want = append(want, "ping", "maintenance.undrain", "ping")
			}
			if !booted || !reflect.DeepEqual(calls, want) {
				t.Fatal(calls)
			}
		})
	}
}

func TestServiceMaintenanceRejectsUnexpectedDrainResponse(t *testing.T) {
	// Missing, malformed, false-success and error-bearing drain replies fail closed before any privilege.
	for _, response := range []Response{{OK: true}, {OK: true, Token: "bad"}, {Token: strings.Repeat("a", 64)}, {OK: true, Token: strings.Repeat("a", 64), Error: "busy"}} {
		_, run := maintenanceServiceFixture(t, "uninstall")
		withMaintenanceCall(t, func(ServiceConfig, Request) (Response, error) { return response, nil })
		withInstallSeams(t, func() error { t.Fatal("unexpected auth"); return nil }, func(string, ...string) ([]byte, error) { t.Fatal("unexpected privilege"); return nil, nil })
		if err := run(); err == nil || !strings.Contains(err.Error(), "unexpected maintenance.drain response") {
			t.Fatal(err)
		}
	}
}

func TestServiceMaintenanceInstallReplacementAdmission(t *testing.T) {
	// Real installer orchestration retains ownership across fixture bootstrap;
	// replacement startup restores the lease, then owned undrain permits the very
	// next start after Install returns. No launchd, listener or child is started.
	d1 := maintenanceDaemonGroupParent(t)
	cfg := testInstallConfig(t)
	cfg.RuntimeDir = d1.cfg.RuntimeDir
	_, run := maintenanceServiceFixture(t, "install", cfg)
	d1.cfg = cfg
	var replacement *serviceDaemon
	booted, undrained := false, false
	withMaintenanceCall(t, func(_ ServiceConfig, request Request) (Response, error) {
		d := d1
		if booted {
			if replacement == nil {
				return Response{}, os.ErrNotExist
			}
			d = replacement
		}
		response := maintenanceRequest(t, d, request)
		if request.Action == "maintenance.undrain" && response.OK {
			undrained = true
		}
		if !response.OK {
			return response, errors.New(response.Error)
		}
		return response, nil
	})
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" {
			switch args[0] {
			case "bootout":
				booted = true
			case "print":
				return nil, launchctlTestError(113, nil)
			case "bootstrap":
				replacement = newMaintenanceTestDaemon(t, cfg)
				replacement.leaseFiles = d1.leaseFiles
				startMaintenanceFixture(t, replacement)
				if replacement.drainToken == "" {
					t.Fatal("bootstrap failed to inherit lease")
				}
				starts := fixtureSingBoxStart(replacement)
				if r := maintenanceRequest(t, replacement, Request{Action: "singbox.start"}); r.OK || *starts != 0 {
					t.Fatal("bootstrap admitted start before owned undrain")
				}
			}
		}
		return nil, performFakeInstall(name, args, nil)
	})
	if err := run(); err != nil {
		t.Error(err)
	}
	if replacement == nil {
		t.Fatal("no replacement fixture")
	}
	starts := fixtureSingBoxStart(replacement)
	if r := maintenanceRequest(t, replacement, Request{Action: "singbox.start"}); !r.OK || *starts != 1 {
		t.Fatal("immediate post-install start refused")
	}
	if !undrained {
		t.Fatal("installer omitted owned undrain")
	}
	assertMaintenanceLeaseAbsent(t, replacement)
}

func TestServiceMaintenanceInstallRetryReadinessAndStateRefusal(t *testing.T) {
	// A no-token retry cannot report clean success after readiness timeout or unavailable/malformed drain status, and never attempts unowned release.
	for _, mode := range []string{"readiness-timeout", "state-error", "missing-state", "invalid-expiry", "false-ok", "response-error"} {
		t.Run(mode, func(t *testing.T) {
			_, run := maintenanceServiceFixture(t, "install")
			bootstrapped := false
			probes, pings := 0, 0
			now := time.Now()
			base := now
			previousNow, previousSleep := installNowVPNCore, installSleepVPNCore
			installNowVPNCore = func() time.Time { return now }
			installSleepVPNCore = func(delay time.Duration) { now = now.Add(delay) }
			t.Cleanup(func() { installNowVPNCore, installSleepVPNCore = previousNow, previousSleep })
			withMaintenanceCall(t, func(_ ServiceConfig, request Request) (Response, error) {
				if !bootstrapped {
					if request.Action != "maintenance.drain" {
						t.Fatal("unexpected pre-bootstrap action")
					}
					probes++
					return Response{}, os.ErrNotExist
				}
				if request.Action != "ping" || request.Token != "" {
					t.Fatal("unowned retry sent a mutation")
				}
				pings++
				if mode == "readiness-timeout" {
					return Response{}, os.ErrNotExist
				}
				response := Response{OK: true, MaintenanceDrain: &MaintenanceDrainState{}}
				if pings > 1 {
					switch mode {
					case "state-error":
						return Response{}, errors.New("fixture drain-state unavailable")
					case "missing-state":
						response.MaintenanceDrain = nil
					case "invalid-expiry":
						response.MaintenanceDrain = &MaintenanceDrainState{Active: true, ExpiresAt: "invalid"}
					case "false-ok":
						response.OK = false
					case "response-error":
						response.Error = "fixture protocol error"
					}
				}
				return response, nil
			})
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				if name == "launchctl" {
					if args[0] == "print" {
						return nil, launchctlTestError(113, nil)
					}
					if args[0] == "bootstrap" {
						bootstrapped = true
					}
				}
				return nil, performFakeInstall(name, args, nil)
			})
			err := run()
			var warning *InstallMaintenanceError
			if !errors.As(err, &warning) || !warning.Installed || warning.DrainActive || !warning.ExpiresAt.IsZero() || !strings.Contains(err.Error(), "warning: could not verify whether tunnel starts are blocked") || strings.Contains(err.Error(), "0001-") {
				t.Fatalf("bad completed retry warning: %v", err)
			}
			if probes != 2 || pings < 2 {
				t.Fatalf("probes=%d pings=%d", probes, pings)
			}
			if mode == "readiness-timeout" && now.Sub(base) != maintenanceReadyTimeout {
				t.Fatal("unbounded readiness")
			}
		})
	}
}

func TestServiceMaintenanceInstallRecoveryWarnings(t *testing.T) {
	// A refused/malformed undrain or missing replacement reports installed with
	// a lease-deadline warning and an error; enable/bootstrap failure reports the
	// same inherited-drain risk without claiming installation completed.
	for _, mode := range []string{"undrain-refused", "undrain-malformed", "unreachable", "enable", "bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			_, run := maintenanceServiceFixture(t, "install")
			booted, bootstrapped := false, false
			undrains, pings := 0, 0
			base := time.Now()
			now := base
			previousNow, previousSleep := installNowVPNCore, installSleepVPNCore
			installNowVPNCore = func() time.Time { return now }
			installSleepVPNCore = func(delay time.Duration) { now = now.Add(delay) }
			t.Cleanup(func() { installNowVPNCore, installSleepVPNCore = previousNow, previousSleep })
			withMaintenanceCall(t, func(_ ServiceConfig, request Request) (Response, error) {
				switch request.Action {
				case "ping":
					pings++
					if !bootstrapped {
						t.Fatal("readiness preceded bootstrap")
					}
					if mode == "unreachable" {
						return Response{}, os.ErrNotExist
					}
				case "maintenance.undrain":
					undrains++
					if !bootstrapped || request.Token != strings.Repeat("a", 64) {
						t.Fatal("undrain lost replacement ownership")
					}
					if mode == "undrain-malformed" {
						return Response{}, nil
					}
					return Response{}, errors.New("fixture owned undrain refused")
				}
				return Response{OK: true, Token: strings.Repeat("a", 64), MaintenanceDrain: &MaintenanceDrainState{}}, nil
			})
			previousPing := maintenancePingVPNCore
			maintenancePingVPNCore = func(cfg ServiceConfig, timeout time.Duration) (Response, error) {
				if timeout <= 0 || timeout > maintenanceReadyTimeout/2 {
					t.Fatal("unbounded readiness RPC")
				}
				return previousPing(cfg, timeout)
			}
			t.Cleanup(func() { maintenancePingVPNCore = previousPing })
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				if name == "launchctl" {
					switch args[0] {
					case "bootout":
						booted = true
					case "print":
						return nil, launchctlTestError(113, nil)
					case "enable", "bootstrap":
						if args[0] == mode {
							return nil, errors.New("fixture " + mode + " failure")
						}
						if args[0] == "bootstrap" {
							bootstrapped = true
						}
					}
				}
				return nil, performFakeInstall(name, args, nil)
			})
			err := run()
			var warning *InstallMaintenanceError
			if !booted || !errors.As(err, &warning) || warning.Installed != bootstrapped || !warning.ExpiresAt.Equal(base.Add(maintenanceDrainTTL)) {
				t.Fatalf("bad install warning: %v", err)
			}
			for _, want := range []string{"warning:", "tunnel starts may remain blocked until", warning.ExpiresAt.UTC().Format(time.RFC3339Nano), "later bootstrap of retained runtime"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("missing %q: %v", want, err)
				}
			}
			if mode == "unreachable" {
				if pings < 2 || now.Sub(base) != maintenanceReadyTimeout || undrains != 0 {
					t.Fatal("readiness timeout/release violated")
				}
			} else if bootstrapped && (pings != 1 || undrains != 1) {
				t.Fatalf("ping=%d undrain=%d", pings, undrains)
			}
			if !bootstrapped && (pings != 0 || undrains != 0) {
				t.Fatal("failed bootstrap attempted replacement release")
			}
		})
	}
}

func TestServiceMaintenanceReadinessAuthenticatesRPCPeer(t *testing.T) {
	// The real readiness client sends ping only to a root peer. A non-root
	// replacement receives no bytes and no owned undrain, then times out.
	for _, uid := range []uint32{0, 501} {
		t.Run(map[uint32]string{0: "root", 501: "non-root"}[uid], func(t *testing.T) {
			cfg := ServiceConfig{Label: "fixture", SocketPath: "fixture-socketpair"}
			base := time.Now()
			now := base
			previousDial, previousNow, previousSleep := rpcDialVPNCore, installNowVPNCore, installSleepVPNCore
			installNowVPNCore = func() time.Time { return now }
			installSleepVPNCore = func(delay time.Duration) { now = now.Add(delay) }
			t.Cleanup(func() {
				rpcDialVPNCore, installNowVPNCore, installSleepVPNCore = previousDial, previousNow, previousSleep
			})
			withRPCServerIdentity(t, 0, func(*net.UnixConn) (uint32, error) { return uid, nil })
			observed := make(chan Request, 2)
			dials := 0
			rpcDialVPNCore = func(context.Context, string, string) (net.Conn, error) {
				dials++
				if dials > 2 || (uid != 0 && dials > 1) {
					now = base.Add(maintenanceReadyTimeout)
					return nil, os.ErrNotExist
				}
				server, client := unixSocketPair(t)
				go func() {
					defer server.Close()
					_ = server.SetDeadline(time.Now().Add(time.Second))
					var request Request
					if json.NewDecoder(server).Decode(&request) == nil {
						_ = json.NewEncoder(server).Encode(Response{OK: true, MaintenanceDrain: &MaintenanceDrainState{}})
					}
					observed <- request
				}()
				return client, nil
			}
			previousCall := maintenanceCallVPNCore
			undrains := 0
			maintenanceCallVPNCore = func(_ ServiceConfig, request Request) (Response, error) {
				undrains++
				if request.Action != "maintenance.undrain" || request.Token != strings.Repeat("a", 64) {
					t.Fatal("unexpected owned release")
				}
				return Response{OK: true}, nil
			}
			t.Cleanup(func() { maintenanceCallVPNCore = previousCall })
			guard := &maintenanceGuard{leases: map[string]maintenanceLease{cfg.Label: {cfg: cfg, token: strings.Repeat("a", 64)}}}
			err := guard.releaseReplacement(cfg)
			request := <-observed
			if uid == 0 {
				if err != nil || request.Action != "ping" || undrains != 1 || len(guard.leases) != 0 {
					t.Fatalf("request=%+v undrain=%d error=%v", request, undrains, err)
				}
			} else if err == nil || request.Action != "" || undrains != 0 || len(guard.leases) != 1 {
				t.Fatalf("untrusted readiness: request=%+v undrain=%d error=%v", request, undrains, err)
			}
		})
	}
}
