package vpncore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"multi-tun/desktop/internal/core/failclosed"
)

// failClosedStatePathVPNCore persists the accepted fail-closed state across
// reboots (/var/run is cleared at boot). Root-owned; tests override it.
var failClosedStatePathVPNCore = "/Library/Application Support/works.relux.vpn-core/failclosed.json"

// pfctlVPNCore runs /sbin/pfctl; tests replace it with a fake.
var pfctlVPNCore = func(args []string, stdin string) ([]byte, error) {
	return runTypedCommand("/sbin/pfctl", args, stdin)
}

var pfTokenRE = regexp.MustCompile(`(?m)^Token\s*:\s*([0-9]{1,20})\s*$`)

// FailClosedRequest carries the policy the client wants enforced.
type FailClosedRequest struct {
	Interfaces []string `json:"interfaces,omitempty"`
	Table      []string `json:"table,omitempty"`
}

// FailClosedStatus is the public fail-closed state; the pf token stays private.
type FailClosedStatus struct {
	Enabled      bool      `json:"enabled"`
	Interfaces   []string  `json:"interfaces,omitempty"`
	TableEntries int       `json:"table_entries"`
	TokenHeld    bool      `json:"token_held"`
	AppliedAt    time.Time `json:"applied_at,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}

type failClosedState struct {
	Enabled    bool      `json:"enabled"`
	Interfaces []string  `json:"interfaces,omitempty"`
	Table      []string  `json:"table,omitempty"`
	Token      string    `json:"token,omitempty"`
	AppliedAt  time.Time `json:"applied_at,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

// failClosedManager owns the pf anchor and the pf enable token. It never
// edits /etc/pf.conf, never touches other anchors and never disables pf it
// did not enable. It does not start, stop or reconfigure any tunnel.
type failClosedManager struct {
	mu        sync.Mutex
	statePath string
	pfctl     func(args []string, stdin string) ([]byte, error)
	now       func() time.Time
}

func newFailClosedManager() *failClosedManager {
	return &failClosedManager{statePath: failClosedStatePathVPNCore, pfctl: pfctlVPNCore, now: time.Now}
}

func (m *failClosedManager) load() (failClosedState, error) {
	var st failClosedState
	data, err := os.ReadFile(m.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("fail-closed state %s is corrupt: %w", m.statePath, err)
	}
	return st, nil
}

func (m *failClosedManager) save(st failClosedState) error {
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath)
}

func (m *failClosedManager) run(args []string, stdin string) ([]byte, error) {
	out, err := m.pfctl(args, stdin)
	if err != nil {
		return out, fmt.Errorf("pfctl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (m *failClosedManager) acquireToken() (string, error) {
	out, err := m.run([]string{"-E"}, "")
	if err != nil {
		return "", err
	}
	match := pfTokenRE.FindSubmatch(out)
	if match == nil {
		return "", errors.New("pfctl -E did not report an enable token")
	}
	return string(match[1]), nil
}

// Apply validates the request, loads the anchor rules and replaces its table.
// Nothing reaches pfctl before validation passes. On a pf failure the rules
// already loaded stay in place and the error is recorded.
func (m *failClosedManager) Apply(req FailClosedRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	anchor, err := failclosed.RenderAnchor(req.Interfaces)
	if err != nil {
		return err
	}
	table, err := failclosed.ValidateTable(req.Table)
	if err != nil {
		return err
	}
	st, err := m.load()
	if err != nil {
		return err
	}
	return m.applyLocked(st, req.Interfaces, table, anchor)
}

func (m *failClosedManager) applyLocked(st failClosedState, interfaces, table []string, anchor string) error {
	if st.Token == "" {
		token, err := m.acquireToken()
		if err != nil {
			st.LastError = err.Error()
			_ = m.save(st)
			return err
		}
		st.Token = token
		// Record the token at once so it can always be released later.
		if err := m.save(st); err != nil {
			return err
		}
	}
	steps := [][2]any{
		{[]string{"-a", failclosed.AnchorName, "-f", "-"}, anchor},
		{[]string{"-a", failclosed.AnchorName, "-t", failclosed.TableName, "-T", "replace", "-f", "-"}, strings.Join(table, "\n") + "\n"},
	}
	for _, step := range steps {
		if _, err := m.run(step[0].([]string), step[1].(string)); err != nil {
			st.LastError = err.Error()
			_ = m.save(st)
			return err
		}
	}
	st.Enabled, st.Interfaces, st.Table, st.LastError = true, append([]string(nil), interfaces...), table, ""
	st.AppliedAt = m.now().UTC()
	return m.save(st)
}

// Clear flushes the anchor, releases the token and records enabled=false so
// the block stays off after reboot.
func (m *failClosedManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.load()
	if err != nil {
		// A corrupt state must not prevent the owner's rollback.
		st = failClosedState{}
	}
	if _, err := m.run([]string{"-a", failclosed.AnchorName, "-F", "all"}, ""); err != nil {
		st.LastError = err.Error()
		_ = m.save(st)
		return err
	}
	if st.Token != "" {
		if _, err := m.run([]string{"-X", st.Token}, ""); err != nil {
			st.LastError = err.Error()
			_ = m.save(st)
			return err
		}
	}
	return m.save(failClosedState{Enabled: false})
}

// ReapplyAtStart re-applies the last accepted policy when the daemon starts.
// A token from a previous daemon run is released first (it is invalid after a
// reboot; after a daemon restart it would otherwise leak a pf reference).
// Errors are returned for logging; rules already loaded are never cleared.
func (m *failClosedManager) ReapplyAtStart() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.load()
	if err != nil {
		return err
	}
	if !st.Enabled {
		return nil
	}
	if st.Token != "" {
		_, _ = m.pfctl([]string{"-X", st.Token}, "")
		st.Token = ""
	}
	anchor, err := failclosed.RenderAnchor(st.Interfaces)
	if err != nil {
		return fmt.Errorf("stored fail-closed state: %w", err)
	}
	table, err := failclosed.ValidateTable(st.Table)
	if err != nil {
		return fmt.Errorf("stored fail-closed state: %w", err)
	}
	return m.applyLocked(st, st.Interfaces, table, anchor)
}

// Status reports the stored state without touching pf.
func (m *failClosedManager) Status() (FailClosedStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.load()
	if err != nil {
		return FailClosedStatus{LastError: err.Error()}, err
	}
	return FailClosedStatus{
		Enabled: st.Enabled, Interfaces: st.Interfaces, TableEntries: len(st.Table),
		TokenHeld: st.Token != "", AppliedAt: st.AppliedAt, LastError: st.LastError,
	}, nil
}
