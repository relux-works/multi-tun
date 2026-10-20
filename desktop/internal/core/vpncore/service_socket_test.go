package vpncore

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPreparePublishedSocketUsesPrivateDirectoryAndExpectedPermissions(t *testing.T) {
	// This proves startup binds and permissions a client-owned 0600 socket in a newly created 0700 private directory before publishing it.
	root := resolvedTempDir(t)
	publicPath := filepath.Join(root, "public.sock")
	daemon, chownPath := newSocketLifecycleTestDaemon(t, root, publicPath)

	published, err := daemon.preparePublishedSocket()
	if err != nil {
		t.Fatalf("preparePublishedSocket() error = %v", err)
	}
	t.Cleanup(func() { _ = published.close() })

	privateDir := privateSocketDir(daemon.cfg)
	privatePath := filepath.Join(privateDir, privateSocketFilename)
	dirInfo, err := os.Lstat(privateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("private socket directory mode = %#o, want 0700", got)
	}
	if *chownPath != privatePath {
		t.Fatalf("chown path = %q, want private path %q", *chownPath, privatePath)
	}
	if _, err := os.Lstat(privatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private socket after publish exists or cannot be inspected: %v", err)
	}
	info, err := os.Lstat(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("public path mode = %v, want unix socket without symlink", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("public socket mode = %#o, want 0600", got)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if gotUID, gotGID := int(stat.Uid), int(stat.Gid); gotUID != daemon.clientUID || gotGID != daemon.clientGID {
		t.Fatalf("public socket owner = %d:%d, want %d:%d", gotUID, gotGID, daemon.clientUID, daemon.clientGID)
	}
}

func TestPreparePublishedSocketLeavesHelperTreeEntriesUnchanged(t *testing.T) {
	// This proves socket startup adds nothing inside the helper directory: the installed helper tree must keep exactly its packaged entries (mac-infra's helper checks that list exactly).
	root := resolvedTempDir(t)
	publicPath := filepath.Join(root, "public.sock")
	daemon, _ := newSocketLifecycleTestDaemon(t, root, publicPath)
	if err := os.MkdirAll(daemon.cfg.HelperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(daemon.cfg.HelperDir)
	if err != nil {
		t.Fatal(err)
	}

	published, err := daemon.preparePublishedSocket()
	if err != nil {
		t.Fatalf("preparePublishedSocket() error = %v", err)
	}
	t.Cleanup(func() { _ = published.close() })

	after, err := os.ReadDir(daemon.cfg.HelperDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("helper directory entries changed from %d to %d: %v", len(before), len(after), after)
	}
	if filepath.Dir(privateSocketDir(daemon.cfg)) != filepath.Dir(filepath.Clean(daemon.cfg.HelperDir)) {
		t.Fatalf("private socket dir %q is not a sibling of helper dir %q", privateSocketDir(daemon.cfg), daemon.cfg.HelperDir)
	}
}

func TestPreparePublishedSocketReplacesPreplantedPublicSymlinkWithoutTouchingVictim(t *testing.T) {
	// This proves a public symlink planted before startup is atomically replaced without changing its victim's mode, owner, or content.
	root := resolvedTempDir(t)
	publicPath := filepath.Join(root, "public.sock")
	victimPath := filepath.Join(root, "victim")
	writeVictimFile(t, victimPath)
	wantVictim := snapshotFile(t, victimPath)
	if err := os.Symlink(victimPath, publicPath); err != nil {
		t.Fatal(err)
	}
	daemon, _ := newSocketLifecycleTestDaemon(t, root, publicPath)

	published, err := daemon.preparePublishedSocket()
	if err != nil {
		t.Fatalf("preparePublishedSocket() error = %v", err)
	}
	t.Cleanup(func() { _ = published.close() })

	assertFileSnapshot(t, victimPath, wantVictim)
	info, err := os.Lstat(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("public path mode = %v, want published socket", info.Mode())
	}
}

func TestPreparePublishedSocketDefeatsPublicSymlinkPlantedImmediatelyBeforeRename(t *testing.T) {
	// This proves a public symlink swapped in after private bind/chmod/chown is replaced by rename without changing its victim.
	root := resolvedTempDir(t)
	publicPath := filepath.Join(root, "public.sock")
	victimPath := filepath.Join(root, "victim")
	writeVictimFile(t, victimPath)
	wantVictim := snapshotFile(t, victimPath)
	daemon, _ := newSocketLifecycleTestDaemon(t, root, publicPath)
	daemon.beforeSocketPublish = func(path string) error {
		return os.Symlink(victimPath, path)
	}

	published, err := daemon.preparePublishedSocket()
	if err != nil {
		t.Fatalf("preparePublishedSocket() error = %v", err)
	}
	t.Cleanup(func() { _ = published.close() })

	assertFileSnapshot(t, victimPath, wantVictim)
}

func TestPreparePublishedSocketRefusesUnsafePrivateDirectoryBeforeBind(t *testing.T) {
	// This proves group-write, symlink replacement, and non-root ownership each stop startup before any socket bind.
	tests := []struct {
		name      string
		prepare   func(*testing.T, *serviceDaemon, string)
		wantError string
	}{
		{
			name: "group-writable",
			prepare: func(t *testing.T, _ *serviceDaemon, privateDir string) {
				if err := os.Mkdir(privateDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(privateDir, 0o770); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "group/world-writable",
		},
		{
			name: "symlinked",
			prepare: func(t *testing.T, _ *serviceDaemon, privateDir string) {
				target := privateDir + "-target"
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, privateDir); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "without following symlinks",
		},
		{
			name: "not-root-owned",
			prepare: func(t *testing.T, daemon *serviceDaemon, privateDir string) {
				if err := os.Mkdir(privateDir, 0o700); err != nil {
					t.Fatal(err)
				}
				daemon.socketVerification.owner = func(path string, _ *unix.Stat_t) (uint32, error) {
					if path == privateDir {
						return 501, nil
					}
					return 0, nil
				}
			},
			wantError: "owned by uid 501",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := resolvedTempDir(t)
			daemon, _ := newSocketLifecycleTestDaemon(t, root, filepath.Join(root, "public.sock"))
			privateDir := privateSocketDir(daemon.cfg)
			test.prepare(t, daemon, privateDir)
			bindCalls := 0
			daemon.listenUnix = func(string, *net.UnixAddr) (*net.UnixListener, error) {
				bindCalls++
				return nil, errors.New("unexpected bind")
			}

			_, err := daemon.preparePublishedSocket()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("preparePublishedSocket() error = %v, want %q", err, test.wantError)
			}
			if bindCalls != 0 {
				t.Fatalf("listen calls = %d, want zero before private directory verification", bindCalls)
			}
		})
	}
}

func TestPreparePublishedSocketRenameFailureClosesListenerAndRemovesPrivateSocket(t *testing.T) {
	// This proves a destination-directory rename failure aborts startup, closes the listener, and removes the private socket.
	root := resolvedTempDir(t)
	publicPath := filepath.Join(root, "public.sock")
	if err := os.Mkdir(publicPath, 0o700); err != nil {
		t.Fatal(err)
	}
	daemon, _ := newSocketLifecycleTestDaemon(t, root, publicPath)
	var captured *net.UnixListener
	daemon.listenUnix = func(network string, addr *net.UnixAddr) (*net.UnixListener, error) {
		listener, err := net.ListenUnix(network, addr)
		captured = listener
		return listener, err
	}

	_, err := daemon.preparePublishedSocket()
	if err == nil || !strings.Contains(err.Error(), "atomically publish vpn core socket") {
		t.Fatalf("preparePublishedSocket() error = %v, want publish failure", err)
	}
	if captured == nil {
		t.Fatal("listener was not created before rename failure")
	}
	_ = captured.SetDeadline(time.Now())
	if _, acceptErr := captured.AcceptUnix(); !errors.Is(acceptErr, net.ErrClosed) {
		t.Fatalf("AcceptUnix() after startup failure error = %v, want closed listener", acceptErr)
	}
	privatePath := filepath.Join(privateSocketDir(daemon.cfg), privateSocketFilename)
	if _, statErr := os.Lstat(privatePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("private socket remains after rename failure: %v", statErr)
	}
}

func TestPublishedSocketCleanupPreservesReplacementAndRemovesOwnedSocket(t *testing.T) {
	// This proves shutdown removes the published socket only while its captured device/inode identity still matches.
	t.Run("foreign replacement", func(t *testing.T) {
		root := resolvedTempDir(t)
		publicPath := filepath.Join(root, "public.sock")
		daemon, _ := newSocketLifecycleTestDaemon(t, root, publicPath)
		published, err := daemon.preparePublishedSocket()
		if err != nil {
			t.Fatalf("preparePublishedSocket() error = %v", err)
		}
		if err := os.Remove(publicPath); err != nil {
			t.Fatal(err)
		}
		const foreign = "foreign file must survive cleanup"
		if err := os.WriteFile(publicPath, []byte(foreign), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := published.close(); err != nil {
			t.Fatalf("close() error = %v", err)
		}
		content, err := os.ReadFile(publicPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != foreign {
			t.Fatalf("foreign replacement content = %q, want %q", content, foreign)
		}
	})

	t.Run("owned socket", func(t *testing.T) {
		root := resolvedTempDir(t)
		publicPath := filepath.Join(root, "public.sock")
		daemon, _ := newSocketLifecycleTestDaemon(t, root, publicPath)
		published, err := daemon.preparePublishedSocket()
		if err != nil {
			t.Fatalf("preparePublishedSocket() error = %v", err)
		}
		if err := published.close(); err != nil {
			t.Fatalf("close() error = %v", err)
		}
		if _, err := os.Lstat(publicPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned socket remains after cleanup: %v", err)
		}
	})
}

func TestPreparePublishedSocketRefusesPublicPathSwappedRightAfterRename(t *testing.T) {
	// This proves startup refuses when the public entry is replaced by a different unix socket between the atomic rename and the identity check (only the dev/ino comparison can catch this), and leaves the foreign socket in place.
	root := resolvedTempDir(t)
	publicPath := filepath.Join(root, "public.sock")
	daemon, _ := newSocketLifecycleTestDaemon(t, root, publicPath)
	var foreign *net.UnixListener
	daemon.afterSocketPublish = func(path string) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return err
		}
		listener.SetUnlinkOnClose(false)
		foreign = listener
		return nil
	}
	t.Cleanup(func() {
		if foreign != nil {
			_ = foreign.Close()
		}
	})

	published, err := daemon.preparePublishedSocket()
	if err == nil {
		_ = published.close()
		t.Fatal("preparePublishedSocket() error = nil, want refusal after the public socket identity changed")
	}
	if !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("preparePublishedSocket() error = %v, want identity-changed refusal", err)
	}
	info, statErr := os.Lstat(publicPath)
	if statErr != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("foreign socket at public path missing after refusal: %v %v", info, statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(privateSocketDir(daemon.cfg), privateSocketFilename)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("private socket left behind: %v", statErr)
	}
}

func newSocketLifecycleTestDaemon(t *testing.T, root, publicPath string) (*serviceDaemon, *string) {
	t.Helper()
	helperDir := filepath.Join(root, "h")
	if err := os.Mkdir(helperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	daemon := newServiceDaemon(ServiceConfig{SocketPath: publicPath, HelperDir: helperDir}, os.Getuid(), os.Getgid())
	daemon.socketVerification.owner = func(string, *unix.Stat_t) (uint32, error) { return 0, nil }
	daemon.socketVerification.checkACL = func(string, int) error { return nil }
	daemon.effectiveUID = func() int { return 0 }
	chownPath := ""
	daemon.chownSocket = func(path string, uid, gid int) error {
		chownPath = path
		if uid != os.Getuid() || gid != os.Getgid() {
			t.Fatalf("chown owner = %d:%d, want test client %d:%d", uid, gid, os.Getuid(), os.Getgid())
		}
		return nil
	}
	return daemon, &chownPath
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "v-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	root, err := filepath.EvalSymlinks(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

type fileSnapshot struct {
	mode    os.FileMode
	uid     uint32
	gid     uint32
	content string
}

func writeVictimFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("victim content must not change"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
}

func snapshotFile(t *testing.T, path string) fileSnapshot {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	return fileSnapshot{mode: info.Mode(), uid: stat.Uid, gid: stat.Gid, content: string(content)}
}

func assertFileSnapshot(t *testing.T, path string, want fileSnapshot) {
	t.Helper()
	got := snapshotFile(t, path)
	if got != want {
		t.Fatalf("file snapshot = %#v, want unchanged %#v", got, want)
	}
}
