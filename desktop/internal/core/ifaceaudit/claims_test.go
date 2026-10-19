package ifaceaudit

import (
	"errors"
	"os"
	"strings"
	"testing"

	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
)

func installClaimCollectionSeams(t *testing.T) {
	t.Helper()
	previousResolveVLESSConfigPath := resolveVLESSConfigPath
	previousLoadVLESSConfig := loadVLESSConfig
	previousResolveVLESSCurrent := resolveVLESSCurrent
	previousCheckVLESSSessionAlive := checkVLESSSessionAlive
	previousLoadOpenConnectConfig := loadOpenConnectConfig
	previousLoadOpenConnectCurrent := loadOpenConnectCurrent
	previousCheckOpenConnectAlive := checkOpenConnectAlive
	t.Cleanup(func() {
		resolveVLESSConfigPath = previousResolveVLESSConfigPath
		loadVLESSConfig = previousLoadVLESSConfig
		resolveVLESSCurrent = previousResolveVLESSCurrent
		checkVLESSSessionAlive = previousCheckVLESSSessionAlive
		loadOpenConnectConfig = previousLoadOpenConnectConfig
		loadOpenConnectCurrent = previousLoadOpenConnectCurrent
		checkOpenConnectAlive = previousCheckOpenConnectAlive
	})

	resolveVLESSConfigPath = func(string) (string, error) {
		return "/test/vless/config.json", nil
	}
	loadVLESSConfig = func(string) (config.ProjectConfig, error) {
		return config.ProjectConfig{CacheDir: "/test/vless-cache"}, nil
	}
	resolveVLESSCurrent = func(string, config.PrivilegedLaunchConfig) (session.CurrentSession, error) {
		return session.CurrentSession{}, os.ErrNotExist
	}
	checkVLESSSessionAlive = func(session.CurrentSession) (bool, int, error) {
		t.Fatal("unexpected VLESS liveness check")
		return false, 0, nil
	}
	loadOpenConnectConfig = func(string) (openconnectcfg.Config, string, error) {
		return openconnectcfg.Config{CacheDir: "/test/openconnect-cache"}, "/test/openconnect/config.json", nil
	}
	loadOpenConnectCurrent = func(string) (openconnect.CurrentSession, error) {
		return openconnect.CurrentSession{}, os.ErrNotExist
	}
	checkOpenConnectAlive = func(openconnect.CurrentSession) (bool, int, error) {
		t.Fatal("unexpected OpenConnect liveness check")
		return false, 0, nil
	}
}

// This proves a PID-less VLESS record reported not alive remains an unknown claim rather than a dead claim.
func TestCollectClaimsTreatsPIDLessVLESSRecordAsUnknown(t *testing.T) {
	installClaimCollectionSeams(t)
	resolveVLESSCurrent = func(string, config.PrivilegedLaunchConfig) (session.CurrentSession, error) {
		return session.CurrentSession{ID: "vless-starting", InterfaceName: "utun7"}, nil
	}
	checkVLESSSessionAlive = func(session.CurrentSession) (bool, int, error) {
		return false, 0, nil
	}

	got := CollectClaims()
	if len(got.Claims) != 1 || got.Claims[0].Engine != EngineVLESS || got.Claims[0].Liveness != LivenessUnknown || len(got.Issues) != 0 {
		t.Fatalf("collection = %#v, want one unknown PID-less VLESS claim without issues", got)
	}
}

// This proves a positive VLESS liveness result remains alive even when the resolved record itself has no PID.
func TestCollectClaimsPreservesAlivePIDLessVLESSResult(t *testing.T) {
	installClaimCollectionSeams(t)
	resolveVLESSCurrent = func(string, config.PrivilegedLaunchConfig) (session.CurrentSession, error) {
		return session.CurrentSession{ID: "vless-launchd", InterfaceName: "utun8"}, nil
	}
	checkVLESSSessionAlive = func(session.CurrentSession) (bool, int, error) {
		return true, 812, nil
	}

	got := CollectClaims()
	if len(got.Claims) != 1 || got.Claims[0].Liveness != LivenessAlive || len(got.Issues) != 0 {
		t.Fatalf("collection = %#v, want one alive VLESS claim without issues", got)
	}
}

// This proves a VLESS liveness error produces an unknown claim plus a status-directed issue.
func TestCollectClaimsReportsVLESSLivenessError(t *testing.T) {
	installClaimCollectionSeams(t)
	resolveVLESSCurrent = func(string, config.PrivilegedLaunchConfig) (session.CurrentSession, error) {
		return session.CurrentSession{ID: "vless-error", PID: 42, InterfaceName: "utun9"}, nil
	}
	checkVLESSSessionAlive = func(session.CurrentSession) (bool, int, error) {
		return false, 42, errors.New("inspection failed")
	}

	got := CollectClaims()
	if len(got.Claims) != 1 || got.Claims[0].Liveness != LivenessUnknown {
		t.Fatalf("claims = %#v, want one unknown VLESS claim", got.Claims)
	}
	if len(got.Issues) != 1 || !strings.Contains(got.Issues[0], "vless-tun session vless-error liveness") || !strings.Contains(got.Issues[0], "vless-tun status") {
		t.Fatalf("issues = %v, want VLESS liveness issue with status guidance", got.Issues)
	}
}

// This proves a legacy VLESS record without an interface name yields no claim and an issue naming the older vless-tun origin.
func TestCollectClaimsReportsMissingVLESSInterfaceName(t *testing.T) {
	installClaimCollectionSeams(t)
	resolveVLESSCurrent = func(string, config.PrivilegedLaunchConfig) (session.CurrentSession, error) {
		return session.CurrentSession{ID: "legacy-vless", PID: 43}, nil
	}

	got := CollectClaims()
	if len(got.Claims) != 0 || len(got.Issues) != 1 || !strings.Contains(got.Issues[0], "older vless-tun") {
		t.Fatalf("collection = %#v, want no claim and older-vless-tun issue", got)
	}
}

// This proves distinct VLESS cache directories each contribute their own claim with independently checked alive and dead liveness.
func TestCollectClaimsReadsMultipleVLESSCacheDirectories(t *testing.T) {
	installClaimCollectionSeams(t)
	loadVLESSConfig = func(string) (config.ProjectConfig, error) {
		return config.ProjectConfig{Servers: map[string]config.ServerConfig{
			"alive": {CacheDir: "/cache/alive"},
			"dead":  {CacheDir: "/cache/dead"},
		}}, nil
	}
	resolveVLESSCurrent = func(cacheDir string, _ config.PrivilegedLaunchConfig) (session.CurrentSession, error) {
		switch cacheDir {
		case "/cache/alive":
			return session.CurrentSession{ID: "alive", PID: 100, InterfaceName: "utun10"}, nil
		case "/cache/dead":
			return session.CurrentSession{ID: "dead", PID: 101, InterfaceName: "utun11"}, nil
		default:
			t.Fatalf("unexpected VLESS cache directory %q", cacheDir)
			return session.CurrentSession{}, os.ErrNotExist
		}
	}
	checkVLESSSessionAlive = func(current session.CurrentSession) (bool, int, error) {
		return current.ID == "alive", current.PID, nil
	}

	got := CollectClaims()
	if len(got.Claims) != 2 || got.Claims[0].Interface != "utun10" || got.Claims[0].Liveness != LivenessAlive || got.Claims[1].Interface != "utun11" || got.Claims[1].Liveness != LivenessDead || len(got.Issues) != 0 {
		t.Fatalf("collection = %#v, want alive and dead claims from both VLESS cache directories", got)
	}
}

// This proves a PID-less OpenConnect current record is collected with unknown liveness.
func TestCollectClaimsTreatsPIDLessOpenConnectRecordAsUnknown(t *testing.T) {
	installClaimCollectionSeams(t)
	loadOpenConnectCurrent = func(string) (openconnect.CurrentSession, error) {
		return openconnect.CurrentSession{ID: "openconnect-starting", Interface: "utun12"}, nil
	}
	checkOpenConnectAlive = func(openconnect.CurrentSession) (bool, int, error) {
		return false, 0, nil
	}

	got := CollectClaims()
	if len(got.Claims) != 1 || got.Claims[0].Engine != EngineOpenConnect || got.Claims[0].Liveness != LivenessUnknown || len(got.Issues) != 0 {
		t.Fatalf("collection = %#v, want one unknown PID-less OpenConnect claim without issues", got)
	}
}

// This proves missing VLESS and OpenConnect current-session files produce neither claims nor issues.
func TestCollectClaimsIgnoresMissingSessionRecords(t *testing.T) {
	installClaimCollectionSeams(t)
	vlessLoads := 0
	openConnectLoads := 0
	loadVLESSConfig = func(string) (config.ProjectConfig, error) {
		return config.ProjectConfig{}, os.ErrNotExist
	}
	resolveVLESSCurrent = func(string, config.PrivilegedLaunchConfig) (session.CurrentSession, error) {
		vlessLoads++
		return session.CurrentSession{}, os.ErrNotExist
	}
	loadOpenConnectCurrent = func(string) (openconnect.CurrentSession, error) {
		openConnectLoads++
		return openconnect.CurrentSession{}, os.ErrNotExist
	}

	got := CollectClaims()
	if len(got.Claims) != 0 || len(got.Issues) != 0 || vlessLoads != 1 || openConnectLoads != 1 {
		t.Fatalf("collection/calls = %#v/%d/%d, want empty collection after both missing records", got, vlessLoads, openConnectLoads)
	}
}

// This proves either engine's configuration load error yields an engine-specific issue and no claims.
func TestCollectClaimsReportsConfigurationLoadErrors(t *testing.T) {
	tests := []struct {
		name   string
		engine string
		fail   func()
	}{
		{name: "vless", engine: EngineVLESS, fail: func() {
			loadVLESSConfig = func(string) (config.ProjectConfig, error) {
				return config.ProjectConfig{}, errors.New("bad VLESS config")
			}
		}},
		{name: "openconnect", engine: EngineOpenConnect, fail: func() {
			loadOpenConnectConfig = func(string) (openconnectcfg.Config, string, error) {
				return openconnectcfg.Config{}, "", errors.New("bad OpenConnect config")
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installClaimCollectionSeams(t)
			tc.fail()

			got := CollectClaims()
			if len(got.Claims) != 0 || len(got.Issues) != 1 || !strings.Contains(got.Issues[0], tc.engine+" configuration") {
				t.Fatalf("collection = %#v, want one %s configuration issue and no claims", got, tc.engine)
			}
		})
	}
}
