package vpncorecli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
)

func TestMaintenanceCLIForwardsOverrideAndWarns(t *testing.T) {
	// Install/uninstall forward the explicit override and print exactly one warning only when it is selected.
	for _, operation := range []string{"install", "uninstall"} {
		for _, allow := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/default", true: "/override"}[allow], func(t *testing.T) {
				previousPlan, previousInspect, previousUninstall := prepareInstallPlanVPNCoreCLI, inspectServiceVPNCoreCLI, uninstallServiceVPNCoreCLI
				t.Cleanup(func() {
					prepareInstallPlanVPNCoreCLI, inspectServiceVPNCoreCLI, uninstallServiceVPNCoreCLI = previousPlan, previousInspect, previousUninstall
				})
				plan := &fakeInstallPlan{}
				prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) { return plan, nil }
				inspectServiceVPNCoreCLI = func(vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
					return vpncore.ServiceStatus{Reachable: true}, nil
				}
				var uninstallOptions []vpncore.MaintenanceOptions
				uninstallServiceVPNCoreCLI = func(_ vpncore.ServiceConfig, options ...vpncore.MaintenanceOptions) error {
					uninstallOptions = options
					return nil
				}
				args := []string{operation}
				if operation == "install" {
					args = append(args, "--expect-sha256", strings.Repeat("a", 64))
				}
				if allow {
					args = append(args, "--allow-disruption")
				}
				var stdout, stderr bytes.Buffer
				if code := New(&stdout, &stderr).Run(args); code != 0 {
					t.Fatalf("code=%d stderr=%q", code, stderr.String())
				}
				options := uninstallOptions
				if operation == "install" {
					options = plan.options
				}
				if len(options) != 1 || options[0].AllowDisruption != allow {
					t.Fatalf("options=%+v", options)
				}
				warnings := strings.Count(stderr.String(), "warning: --allow-disruption skips the idle check;")
				if allow && warnings != 1 || !allow && warnings != 0 {
					t.Fatalf("warnings=%d stderr=%q", warnings, stderr.String())
				}
				if allow && strings.Count(strings.TrimSpace(stderr.String()), "\n") != 0 {
					t.Fatalf("warning not one line: %q", stderr.String())
				}
			})
		}
	}
}

func TestMaintenanceCLIReportsRefusalWithoutSuccess(t *testing.T) {
	// Install/uninstall propagate a busy-service refusal and never print success after the service layer rejects it.
	previousPlan, previousUninstall := prepareInstallPlanVPNCoreCLI, uninstallServiceVPNCoreCLI
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI, uninstallServiceVPNCoreCLI = previousPlan, previousUninstall })
	failure := errors.New("1 sing-box child active; stop the tunnels or rerun with --allow-disruption")
	prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) {
		return &fakeInstallPlan{install: func(vpncore.ServiceConfig, int, int, string) error { return failure }}, nil
	}
	uninstallServiceVPNCoreCLI = func(vpncore.ServiceConfig, ...vpncore.MaintenanceOptions) error { return failure }
	for _, args := range [][]string{{"install", "--expect-sha256", strings.Repeat("a", 64)}, {"uninstall"}} {
		var stdout, stderr bytes.Buffer
		if code := New(&stdout, &stderr).Run(args); code != 1 || !strings.Contains(stderr.String(), failure.Error()) || strings.Contains(stdout.String(), "installed vpn core") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

func TestMaintenanceCLIInstallRecoveryWarning(t *testing.T) {
	// Completed bootstrap plus undrain/readiness failure prints installation done,
	// an expiry warning and exit 1. Bootstrap failure warns without success output.
	previousPlan, previousInspect := prepareInstallPlanVPNCoreCLI, inspectServiceVPNCoreCLI
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI, inspectServiceVPNCoreCLI = previousPlan, previousInspect })
	inspectServiceVPNCoreCLI = func(vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
		t.Fatal("warning must bypass success reachability flow")
		return vpncore.ServiceStatus{}, nil
	}
	for _, cause := range []string{"undrain refused", "daemon not answering", "bootstrap failure"} {
		t.Run(cause, func(t *testing.T) {
			installed := cause != "bootstrap failure"
			expiry := time.Date(2026, 10, 25, 18, 0, 0, 0, time.UTC)
			prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) {
				return &fakeInstallPlan{install: func(vpncore.ServiceConfig, int, int, string) error {
					return &vpncore.InstallMaintenanceError{Installed: installed, ExpiresAt: expiry, Err: errors.New(cause)}
				}}, nil
			}
			var stdout, stderr bytes.Buffer
			if code := New(&stdout, &stderr).Run([]string{"install", "--expect-sha256", strings.Repeat("a", 64)}); code != 1 {
				t.Fatalf("exit=%d", code)
			}
			if strings.Contains(stdout.String(), "installed vpn core") != installed {
				t.Fatalf("stdout=%q", stdout.String())
			}
			for _, want := range []string{cause, "warning:", "tunnel starts may remain blocked until", expiry.Format(time.RFC3339Nano), "later bootstrap of retained runtime"} {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("stderr=%q missing %q", stderr.String(), want)
				}
			}
		})
	}
}

func TestMaintenanceCLIInstallRetryOutcome(t *testing.T) {
	// A completed retry carrying the service layer's inherited-lease verdict prints expiry and exit 1; its clean-runtime control prints success, no warning and exit 0.
	previousPlan, previousInspect := prepareInstallPlanVPNCoreCLI, inspectServiceVPNCoreCLI
	t.Cleanup(func() { prepareInstallPlanVPNCoreCLI, inspectServiceVPNCoreCLI = previousPlan, previousInspect })
	for _, orphaned := range []bool{true, false} {
		t.Run(map[bool]string{true: "orphaned", false: "clean"}[orphaned], func(t *testing.T) {
			expiry := time.Date(2026, 10, 25, 18, 30, 45, 0, time.UTC)
			plan := &fakeInstallPlan{install: func(vpncore.ServiceConfig, int, int, string) error {
				if orphaned {
					return &vpncore.InstallMaintenanceError{Installed: true, DrainActive: true, ExpiresAt: expiry}
				}
				return nil
			}}
			prepareInstallPlanVPNCoreCLI = func(string) (installPlanVPNCoreCLI, error) { return plan, nil }
			inspectServiceVPNCoreCLI = func(vpncore.ServiceConfig) (vpncore.ServiceStatus, error) {
				if orphaned {
					t.Fatal("inherited lease verdict was bypassed by reachability")
				}
				return vpncore.ServiceStatus{Reachable: true}, nil
			}
			var stdout, stderr bytes.Buffer
			code := New(&stdout, &stderr).Run([]string{"install", "--expect-sha256", strings.Repeat("a", 64)})
			wantCode := 0
			if orphaned {
				wantCode = 1
			}
			if code != wantCode || !strings.Contains(stdout.String(), "installed vpn core") || strings.Contains(stderr.String(), "install failed") || !plan.closeCall {
				t.Fatalf("exit=%d stdout=%q stderr=%q closed=%v", code, stdout.String(), stderr.String(), plan.closeCall)
			}
			if orphaned {
				want := "warning: tunnel starts are blocked until " + expiry.Format(time.RFC3339) + " by a maintenance lease from an earlier operation\n"
				if stderr.String() != want {
					t.Fatalf("stderr=%q", stderr.String())
				}
			} else if stderr.Len() != 0 {
				t.Fatalf("clean retry warned: %q", stderr.String())
			}
		})
	}
}
