package vpncore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A link above the immediate parent refuses load, save, apply and clear before
// PF calls or creation beneath the link. A canonical sibling path remains valid.
func TestFailClosedRefusesDeepStateSymlink(t *testing.T) {
	for _, operation := range []string{"load", "save", "apply", "clear"} {
		t.Run(operation, func(t *testing.T) {
			root := resolvedTempDir(t)
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			valid := filepath.Join(target, "nested", "state", "failclosed.json")
			if err := checkStatePath(valid); err != nil {
				t.Fatalf("valid path refused: %v", err)
			}
			pf := &fakePF{}
			m := &failClosedManager{statePath: filepath.Join(link, "nested", "state", "failclosed.json"), pfctl: pf.run, now: time.Now}
			var err error
			switch operation {
			case "load":
				_, err = m.load()
			case "save":
				err = m.save(failClosedState{Enabled: true})
			case "apply":
				err = m.Apply(goodReq)
			case "clear":
				err = m.Clear()
			}
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("%s through link = %v", operation, err)
			}
			if len(pf.calls) != 0 {
				t.Fatalf("PF called: %v", pf.calls)
			}
			if _, err := os.Stat(filepath.Join(target, "nested")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refusal created directories: %v", err)
			}
		})
	}
}

type failClosedOwnershipInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info failClosedOwnershipInfo) Sys() any { return &info.stat }

// Synthetic stat ownership checks each depth without chown or root privileges.
// Current-user state and root-owned system ancestors are positive controls.
func TestFailClosedStatePathOwnershipAtEveryDepth(t *testing.T) {
	root := resolvedTempDir(t)
	path := filepath.Join(root, "ancestor", "parent", "state.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkStatePath(path); err != nil {
		t.Fatalf("owned path refused: %v", err)
	}
	ancestor := filepath.Join(root, "ancestor")
	for _, changed := range []string{path, filepath.Dir(path), ancestor} {
		t.Run(filepath.Base(changed), func(t *testing.T) {
			lstat := func(name string) (os.FileInfo, error) {
				info, err := os.Lstat(name)
				if err != nil || name != changed {
					return info, err
				}
				stat := *info.Sys().(*syscall.Stat_t)
				stat.Uid = uint32(os.Geteuid() + 10000)
				return failClosedOwnershipInfo{info, stat}, nil
			}
			if err := checkStatePathWithLstat(path, lstat); err == nil || !strings.Contains(err.Error(), "owned by uid") {
				t.Fatalf("foreign ownership at %s = %v", changed, err)
			}
		})
	}
	lstat := func(name string) (os.FileInfo, error) {
		info, err := os.Lstat(name)
		if err != nil || name != ancestor {
			return info, err
		}
		stat := *info.Sys().(*syscall.Stat_t)
		stat.Uid = 0
		return failClosedOwnershipInfo{info, stat}, nil
	}
	if err := checkStatePathWithLstat(path, lstat); err != nil {
		t.Fatalf("root-owned ancestor refused: %v", err)
	}
}

// Clear reports the previous table/interface counts, then reports an empty
// already-off policy on the next clear. All PF operations use the fake runner.
func TestFailClosedClearLogsPreviousCounts(t *testing.T) {
	pf := &fakePF{}
	m := newTestManager(t, pf)
	req := goodReq
	req.Interfaces = []string{"en0", "en1"}
	if err := m.Apply(req); err != nil {
		t.Fatal(err)
	}
	var logs []string
	m.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	for i := 0; i < 2; i++ {
		if err := m.Clear(); err != nil {
			t.Fatal(err)
		}
	}
	want := "vpn core: fail-closed cleared: entries=2 interfaces=2 token_released=true\n" +
		"vpn core: fail-closed cleared: entries=0 interfaces=0 token_released=false\n"
	if got := strings.Join(logs, ""); got != want {
		t.Fatalf("clear logs = %q, want %q", got, want)
	}
}
