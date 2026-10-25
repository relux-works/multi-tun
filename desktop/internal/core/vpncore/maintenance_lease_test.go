package vpncore

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newMaintenanceTestDaemon(t *testing.T, configs ...ServiceConfig) *serviceDaemon {
	t.Helper()
	var cfg ServiceConfig
	if len(configs) != 0 {
		cfg = configs[0]
	} else {
		root := resolvedTempDir(t)
		cfg = ServiceConfig{RuntimeDir: filepath.Join(root, "runtime"), HelperDir: filepath.Join(root, "helper"), SocketPath: filepath.Join(root, "public.sock")}
	}
	d := newServiceDaemon(cfg, 501, 20)
	// Ownership is simulated; file operations, modes, secure traversal, fsync and
	// atomic rename are real and restricted to the fixture's temporary directory.
	d.leaseFiles.verification.owner = func(string, *unix.Stat_t) (uint32, error) { return 0, nil }
	d.leaseFiles.verification.group = func(string, *unix.Stat_t) (uint32, error) { return 0, nil }
	d.leaseFiles.verification.checkACL = func(string, int) error { return nil }
	d.leaseFiles.chown = func(_ int, uid, gid int) error {
		if uid != 0 || gid != 0 {
			t.Fatalf("lease chown = %d:%d, want root:wheel", uid, gid)
		}
		return nil
	}
	return d
}

func startMaintenanceFixture(t *testing.T, d *serviceDaemon) {
	t.Helper()
	d.verify = func() error { return nil }
	d.peerUID = func(*net.UnixConn) (uint32, error) { return 501, nil }
	d.socketVerification = d.leaseFiles.verification
	stop := errors.New("fixture stops before listen")
	d.listenUnix = func(string, *net.UnixAddr) (*net.UnixListener, error) { return nil, stop }
	if err := d.serve(); !errors.Is(err, stop) {
		t.Fatalf("startup did not reach pre-listen fixture: %v", err)
	}
}

func maintenanceLeasePath(d *serviceDaemon) string {
	return filepath.Join(d.cfg.RuntimeDir, maintenanceLeaseFilename)
}

func writeMaintenanceLeaseFixture(t *testing.T, d *serviceDaemon, data []byte) {
	t.Helper()
	if err := os.MkdirAll(d.cfg.RuntimeDir, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenanceLeasePath(d), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixtureLeaseBytes(t *testing.T, expiry time.Time) []byte {
	t.Helper()
	data, err := json.Marshal(persistedMaintenanceLease{Token: strings.Repeat("a", 64), ExpiresAt: expiry})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixtureSingBoxStart(d *serviceDaemon) *int {
	starts := new(int)
	d.startSingBox = func(_ Request, log *os.File) (int, string, error) {
		defer log.Close()
		*starts++
		return 0, "fixture-child", nil
	}
	return starts
}

func assertMaintenanceLeaseAbsent(t *testing.T, d *serviceDaemon) {
	t.Helper()
	if _, err := os.Lstat(maintenanceLeasePath(d)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lease still present: %v", err)
	}
}

func TestMaintenanceLeaseSurvivesDaemonReplacement(t *testing.T) {
	// D2's real startup restores D1's drain/renew from the same runtime, rejects
	// starts and wrong owners, and allows the original owner to renew and release.
	// Ownership is simulated; no real listener, launchd job or child is started.
	for _, renew := range []bool{false, true} {
		t.Run(map[bool]string{false: "after-drain", true: "after-renew"}[renew], func(t *testing.T) {
			d1 := newMaintenanceTestDaemon(t)
			drain := maintenanceRequest(t, d1, Request{Action: "maintenance.drain"})
			if !drain.OK {
				t.Fatal(drain)
			}
			if renew {
				if r := maintenanceRequest(t, d1, Request{Action: "maintenance.renew", Token: drain.Token}); !r.OK {
					t.Fatal(r)
				}
			}
			data, err := os.ReadFile(maintenanceLeasePath(d1))
			if err != nil {
				t.Fatal(err)
			}
			var stored persistedMaintenanceLease
			if err := json.Unmarshal(data, &stored); err != nil || stored.Token != drain.Token || !stored.ExpiresAt.Equal(d1.drainUntil) || !bytes.Contains(data, []byte(`Z"`)) {
				t.Fatal("persisted lease does not match the owned UTC deadline")
			}
			info, err := os.Stat(maintenanceLeasePath(d1))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatal("lease is not a mode 0600 regular file")
			}
			d2 := newMaintenanceTestDaemon(t, d1.cfg)
			starts := fixtureSingBoxStart(d2)
			startMaintenanceFixture(t, d2)
			if d2.drainToken != drain.Token || !d2.drainUntil.Equal(stored.ExpiresAt) || d2.drainUntil == d2.drainUntil.Round(0) {
				t.Fatal("replacement lost lease or failed to create a monotonic deadline")
			}
			if r := maintenanceRequest(t, d2, Request{Action: "singbox.start"}); r.OK || r.Error != "vpn core is draining for maintenance" || *starts != 0 {
				t.Fatal("replacement accepted a start during the inherited lease")
			}
			wrong := strings.Repeat("b", 64)
			if wrong == drain.Token {
				wrong = strings.Repeat("c", 64)
			}
			for _, action := range []string{"maintenance.undrain", "maintenance.renew"} {
				if r := maintenanceRequest(t, d2, Request{Action: action, Token: wrong}); r.OK || !strings.Contains(r.Error, "token does not match") {
					t.Fatal("replacement accepted a different owner")
				}
			}
			unchanged, err := os.ReadFile(maintenanceLeasePath(d2))
			if err != nil || !bytes.Equal(data, unchanged) {
				t.Fatal("wrong owner changed the persisted lease")
			}
			if r := maintenanceRequest(t, d2, Request{Action: "maintenance.renew", Token: drain.Token}); !r.OK || !d2.drainUntil.After(stored.ExpiresAt) {
				t.Fatal(r)
			}
			if r := maintenanceRequest(t, d2, Request{Action: "maintenance.undrain", Token: drain.Token}); !r.OK || d2.drainToken != "" || !d2.drainUntil.IsZero() {
				t.Fatal(r)
			}
			assertMaintenanceLeaseAbsent(t, d2)
			if r := maintenanceRequest(t, d2, Request{Action: "singbox.start"}); !r.OK || *starts != 1 {
				t.Fatal("owned release did not restore start admission")
			}
		})
	}
}

func TestMaintenanceLeaseStartupDiscardsExpiredAndMalformed(t *testing.T) {
	// Expired or malformed secure files are deleted before listen and cannot
	// block a valid fixture start; invalid content never supplies ownership.
	for _, kind := range []string{"expired", "json", "token", "unknown-field", "trailing", "non-utc", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			d := newMaintenanceTestDaemon(t)
			data := fixtureLeaseBytes(t, time.Now().Add(time.Minute).UTC())
			switch kind {
			case "expired":
				data = fixtureLeaseBytes(t, time.Now().Add(-time.Second).UTC())
			case "json":
				data = []byte("{")
			case "token":
				data = bytes.Replace(data, []byte(strings.Repeat("a", 64)), []byte("bad"), 1)
			case "unknown-field":
				data = append([]byte(`{"extra":true,`), data[1:]...)
			case "trailing":
				data = append(data, []byte(` {}`)...)
			case "non-utc":
				data = fixtureLeaseBytes(t, time.Now().Add(time.Minute).In(time.FixedZone("offset", 3600)))
			case "oversized":
				data = append(data, bytes.Repeat([]byte(" "), 4097)...)
			}
			writeMaintenanceLeaseFixture(t, d, data)
			starts := fixtureSingBoxStart(d)
			startMaintenanceFixture(t, d)
			assertMaintenanceLeaseAbsent(t, d)
			if d.drainToken != "" || !d.drainUntil.IsZero() {
				t.Fatal("invalid file supplied ownership")
			}
			if r := maintenanceRequest(t, d, Request{Action: "singbox.start"}); !r.OK || *starts != 1 {
				t.Fatal("invalid lease blocked start")
			}
		})
	}
}

func TestMaintenanceLeaseStartupIgnoresUnsafePaths(t *testing.T) {
	// Unsafe runtime/lease types, ownership, modes, groups and ACLs are ignored
	// without deleting the entry or following a symlink. Foreign ownership uses
	// the production metadata-check seam; no privileged chown is performed.
	for _, kind := range []string{"symlink", "foreign-owner", "foreign-group", "mode", "directory", "fifo", "acl", "runtime-symlink", "runtime-owner", "runtime-mode", "ancestor-symlink"} {
		t.Run(kind, func(t *testing.T) {
			d := newMaintenanceTestDaemon(t)
			data := fixtureLeaseBytes(t, time.Now().Add(time.Minute).UTC())
			writeMaintenanceLeaseFixture(t, d, data)
			path := maintenanceLeasePath(d)
			switch kind {
			case "symlink":
				victim := filepath.Join(filepath.Dir(d.cfg.RuntimeDir), "victim")
				if err := os.Rename(path, victim); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner", "runtime-owner":
				d.leaseFiles.verification.owner = func(found string, _ *unix.Stat_t) (uint32, error) {
					if found == path && kind == "foreign-owner" || found == d.cfg.RuntimeDir && kind == "runtime-owner" {
						return 501, nil
					}
					return 0, nil
				}
			case "foreign-group":
				d.leaseFiles.verification.group = func(string, *unix.Stat_t) (uint32, error) { return 20, nil }
			case "mode", "runtime-mode":
				target := path
				if kind == "runtime-mode" {
					target = d.cfg.RuntimeDir
				}
				if err := os.Chmod(target, 0o755); err != nil {
					t.Fatal(err)
				}
			case "directory", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "directory" {
					err = os.Mkdir(path, 0o600)
				} else {
					err = unix.Mkfifo(path, 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "acl":
				d.leaseFiles.verification.checkACL = func(found string, _ int) error {
					if found == path {
						return errors.New("fixture unsafe ACL")
					}
					return nil
				}
			case "runtime-symlink", "ancestor-symlink":
				original := d.cfg.RuntimeDir
				if kind == "runtime-symlink" {
					parked := original + "-parked"
					if err := os.Rename(original, parked); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(parked, original); err != nil {
						t.Fatal(err)
					}
				} else {
					link := filepath.Join(filepath.Dir(original), "parent-link")
					if err := os.Symlink(filepath.Dir(original), link); err != nil {
						t.Fatal(err)
					}
					d.cfg.RuntimeDir = filepath.Join(link, filepath.Base(original))
				}
			}
			startMaintenanceFixture(t, d)
			if d.drainToken != "" || !d.drainUntil.IsZero() {
				t.Fatal("unsafe lease supplied ownership")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("unsafe entry was removed: %v", err)
			}
			if kind == "symlink" || kind == "runtime-symlink" || kind == "ancestor-symlink" {
				found, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(found, data) {
					t.Fatal("symlink target changed")
				}
			}
		})
	}
}

func TestMaintenanceLeasePersistFailurePreservesState(t *testing.T) {
	// Chown, fsync, unsafe-directory and rename failures refuse drain/renew;
	// prior memory and disk bytes survive and temporary entries are cleaned.
	for _, action := range []string{"maintenance.drain", "maintenance.renew"} {
		for _, failure := range []string{"chown", "sync", "directory-mode", "rename"} {
			t.Run(action+"/"+failure, func(t *testing.T) {
				d := newMaintenanceTestDaemon(t)
				if action == "maintenance.renew" {
					if r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"}); !r.OK {
						t.Fatal(r)
					}
				} else {
					writeMaintenanceLeaseFixture(t, d, []byte("old fixture bytes"))
				}
				path := maintenanceLeasePath(d)
				old, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				token, until := d.drainToken, d.drainUntil
				sentinel := errors.New("fixture persistence failure")
				switch failure {
				case "chown":
					d.leaseFiles.chown = func(int, int, int) error { return sentinel }
				case "sync":
					d.leaseFiles.sync = func(int) error { return sentinel }
				case "directory-mode":
					if err := os.Chmod(d.cfg.RuntimeDir, 0o755); err != nil {
						t.Fatal(err)
					}
				case "rename":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				r := maintenanceRequest(t, d, Request{Action: action, Token: token})
				if r.OK || !strings.Contains(r.Error, "persist maintenance") || r.Token != "" || d.drainToken != token || d.drainUntil != until {
					t.Fatal("persistence failure changed in-memory ownership or reported success")
				}
				if failure == "rename" {
					info, err := os.Stat(path)
					if err != nil || !info.IsDir() {
						t.Fatal("failed rename replaced destination")
					}
				} else {
					found, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(old, found) {
						t.Fatal("persistence failure changed old file")
					}
				}
				entries, err := os.ReadDir(d.cfg.RuntimeDir)
				if err != nil || len(entries) != 1 || entries[0].Name() != maintenanceLeaseFilename {
					t.Fatal("persistence failure leaked temporary file")
				}
			})
		}
	}
}

func TestMaintenanceExpiredDrainClearsOwnershipAndFile(t *testing.T) {
	// Each expiry observation path clears token, deadline and file. Expired
	// owner RPCs remain refused; ordinary start dispatch resumes exactly once.
	for _, action := range []string{"singbox.start", "maintenance.renew", "maintenance.undrain"} {
		t.Run(action, func(t *testing.T) {
			d := newMaintenanceTestDaemon(t)
			drain := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
			if !drain.OK {
				t.Fatal(drain)
			}
			d.drainUntil = time.Now().Add(-time.Second)
			starts := fixtureSingBoxStart(d)
			request := Request{Action: action}
			if action != "singbox.start" {
				request.Token = drain.Token
			}
			r := maintenanceRequest(t, d, request)
			if action == "singbox.start" {
				if !r.OK || *starts != 1 {
					t.Fatal("expired drain blocked start")
				}
			} else if r.OK || !strings.Contains(r.Error, "expired or inactive") || *starts != 0 {
				t.Fatal("expired owner retained authority")
			}
			if d.drainToken != "" || !d.drainUntil.IsZero() {
				t.Fatal("expired ownership state retained")
			}
			assertMaintenanceLeaseAbsent(t, d)
		})
	}
}

// Simulate root:daemon on a real 0775 fixture parent without host ownership changes.
func maintenanceDaemonGroupParent(t *testing.T) *serviceDaemon {
	t.Helper()
	d := newMaintenanceTestDaemon(t)
	parent := filepath.Join(filepath.Dir(d.cfg.RuntimeDir), "run")
	if err := os.Mkdir(parent, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o775); err != nil {
		t.Fatal(err)
	}
	d.cfg.RuntimeDir = filepath.Join(parent, "runtime")
	d.leaseFiles.verification.group = func(path string, _ *unix.Stat_t) (uint32, error) {
		if path == parent {
			return 1, nil
		}
		return 0, nil
	}
	return d
}

func TestMaintenanceLeaseDaemonGroupParent(t *testing.T) {
	// Drain persists beneath simulated root:daemon 0775; actual replacement
	// startup restores the lease and refuses a start before owned release.
	d1 := maintenanceDaemonGroupParent(t)
	drain := maintenanceRequest(t, d1, Request{Action: "maintenance.drain"})
	if !drain.OK {
		t.Fatalf("gid-1 parent refused drain: %s", drain.Error)
	}
	if _, err := os.Stat(maintenanceLeasePath(d1)); err != nil {
		t.Fatal(err)
	}
	d2 := newMaintenanceTestDaemon(t, d1.cfg)
	d2.leaseFiles = d1.leaseFiles
	starts := fixtureSingBoxStart(d2)
	startMaintenanceFixture(t, d2)
	if d2.drainToken != drain.Token {
		t.Fatal("gid-1 parent lost restored lease")
	}
	if r := maintenanceRequest(t, d2, Request{Action: "singbox.start"}); r.OK || r.Error != "vpn core is draining for maintenance" || *starts != 0 {
		t.Fatal("gid-1 parent admitted inherited-drain start")
	}
	if r := maintenanceRequest(t, d2, Request{Action: "maintenance.undrain", Token: drain.Token}); !r.OK {
		t.Fatal(r)
	}
	if r := maintenanceRequest(t, d2, Request{Action: "singbox.start"}); !r.OK || *starts != 1 {
		t.Fatal("gid-1 parent failed owned release")
	}
}

func TestMaintenanceLeaseParentPolicyRejectsUnsafePaths(t *testing.T) {
	// The parent exception never admits other writable groups, world write,
	// unsafe ownership/ACLs/links, writable ancestors, or unsafe RuntimeDirs.
	// Rejected drain cannot change the existing file; startup cannot trust it.
	for _, kind := range []string{"parent-group", "parent-world", "parent-owner", "parent-acl", "parent-symlink", "ancestor-group", "runtime-symlink", "runtime-owner", "runtime-group", "runtime-mode"} {
		t.Run(kind, func(t *testing.T) {
			d := maintenanceDaemonGroupParent(t)
			data := fixtureLeaseBytes(t, time.Now().Add(time.Minute).UTC())
			writeMaintenanceLeaseFixture(t, d, data)
			parent := filepath.Dir(d.cfg.RuntimeDir)
			originalLease := maintenanceLeasePath(d)
			switch kind {
			case "parent-group":
				d.leaseFiles.verification.group = func(string, *unix.Stat_t) (uint32, error) { return 20, nil }
			case "parent-world":
				if err := os.Chmod(parent, 0o777); err != nil {
					t.Fatal(err)
				}
			case "parent-owner", "runtime-owner":
				target := parent
				if kind == "runtime-owner" {
					target = d.cfg.RuntimeDir
				}
				d.leaseFiles.verification.owner = func(path string, _ *unix.Stat_t) (uint32, error) {
					if path == target {
						return 501, nil
					}
					return 0, nil
				}
			case "parent-acl":
				d.leaseFiles.verification.checkACL = func(path string, _ int) error {
					if path == parent {
						return errors.New("fixture write ACL")
					}
					return nil
				}
			case "parent-symlink", "runtime-symlink":
				target := parent
				if kind == "runtime-symlink" {
					target = d.cfg.RuntimeDir
				}
				if err := os.Rename(target, target+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+"-moved", target); err != nil {
					t.Fatal(err)
				}
				if kind == "runtime-symlink" {
					originalLease = filepath.Join(target+"-moved", maintenanceLeaseFilename)
				} else {
					originalLease = filepath.Join(target+"-moved", "runtime", maintenanceLeaseFilename)
				}
			case "ancestor-group":
				if err := os.Chmod(filepath.Dir(parent), 0o775); err != nil {
					t.Fatal(err)
				}
			case "runtime-group":
				if err := os.Chmod(d.cfg.RuntimeDir, 0o731); err != nil {
					t.Fatal(err)
				}
			case "runtime-mode":
				if err := os.Chmod(d.cfg.RuntimeDir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"}); r.OK || !strings.Contains(r.Error, "persist maintenance drain") || d.drainToken != "" || !d.drainUntil.IsZero() {
				t.Fatalf("unsafe path accepted drain: %+v", r)
			}
			d.restoreMaintenanceLease()
			if d.drainToken != "" || !d.drainUntil.IsZero() {
				t.Fatal("unsafe path restored lease")
			}
			found, err := os.ReadFile(originalLease)
			if err != nil || !bytes.Equal(found, data) {
				t.Fatal("unsafe path changed lease/target")
			}
		})
	}
}
