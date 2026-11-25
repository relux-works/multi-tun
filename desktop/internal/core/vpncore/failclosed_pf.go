package vpncore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
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

// physicalInterfacesVPNCore lists every existing physical interface the block
// must cover (en*, bridge*), up or not, so a later switch of uplink is covered.
var physicalInterfacesVPNCore = func() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range ifs {
		if physicalIfaceRE.MatchString(i.Name) {
			out = append(out, i.Name)
		}
	}
	return out, nil
}

var physicalIfaceRE = regexp.MustCompile(`^(en|bridge)[0-9]{1,3}$`)

// mergeInterfaces returns the sorted union of requested and discovered names.
func mergeInterfaces(a, b []string) []string {
	set := map[string]bool{}
	for _, n := range append(append([]string(nil), a...), b...) {
		set[n] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

var errEmptyFailClosedTable = errors.New("fail-closed table is empty; refusing to enforce nothing")

var rawTokenRE = regexp.MustCompile(`"token"\s*:\s*"([0-9]{1,20})"`)

// tokenFromRawState recovers the pf token from a state file that no longer
// parses as JSON, or returns "".
func tokenFromRawState(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := rawTokenRE.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

var pfTokenRE = regexp.MustCompile(`(?m)^Token\s*:\s*([0-9]{1,20})\s*$`)

// FailClosedRequest carries the policy the client wants enforced.
type FailClosedRequest struct {
	Interfaces []string `json:"interfaces,omitempty"`
	Table      []string `json:"table,omitempty"`
}

// failClosedWatchIntervalVPNCore bounds how long a lost anchor or a disabled pf
// goes unnoticed. pf offers no change notification, so the helper polls.
var failClosedWatchIntervalVPNCore = 5 * time.Second

// FailClosedStatus is the public fail-closed state; the pf token stays private.
type FailClosedStatus struct {
	Enabled bool `json:"enabled"`
	// Live facts read from pf at status time (only when enabled).
	LiveChecked      bool      `json:"live_checked"`
	PFEnabled        bool      `json:"pf_enabled"`
	AnchorLoaded     bool      `json:"anchor_loaded"`
	LiveTableEntries int       `json:"live_table_entries"`
	Enforcing        bool      `json:"enforcing"`
	LiveError        string    `json:"live_error,omitempty"`
	Backoff          string    `json:"backoff,omitempty"`
	LastRecovery     string    `json:"last_recovery,omitempty"`
	RecoveredAt      time.Time `json:"recovered_at,omitempty"`
	Interfaces       []string  `json:"interfaces,omitempty"`
	TableEntries     int       `json:"table_entries"`
	TokenHeld        bool      `json:"token_held"`
	AppliedAt        time.Time `json:"applied_at,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
}

type failClosedState struct {
	Enabled    bool      `json:"enabled"`
	Interfaces []string  `json:"interfaces,omitempty"`
	Table      []string  `json:"table,omitempty"`
	Token      string    `json:"token,omitempty"`
	AppliedAt  time.Time `json:"applied_at,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	// LastRecovery names what the watchdog found and repaired.
	LastRecovery string    `json:"last_recovery,omitempty"`
	RecoveredAt  time.Time `json:"recovered_at,omitempty"`
}

// failClosedManager owns the pf anchor and the pf enable token. It never
// edits /etc/pf.conf, never touches other anchors and never disables pf it
// did not enable. It does not start, stop or reconfigure any tunnel.
type failClosedManager struct {
	mu         sync.Mutex
	statePath  string
	pfctl      func(args []string, stdin string) ([]byte, error)
	now        func() time.Time
	interfaces func() ([]string, error)
	logf       func(string, ...any)
	// backoffNote describes the watchdog's current retry pace (guarded by mu).
	backoffNote string
}

func newFailClosedManager() *failClosedManager {
	return &failClosedManager{statePath: failClosedStatePathVPNCore, pfctl: pfctlVPNCore, now: time.Now, interfaces: physicalInterfacesVPNCore,
		logf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, format, args...) }}
}

// coveredInterfaces is the union of the requested and currently existing
// physical interfaces.
func (m *failClosedManager) coveredInterfaces(requested []string) []string {
	if m.interfaces == nil {
		return mergeInterfaces(requested, nil)
	}
	found, err := m.interfaces()
	if err != nil {
		return mergeInterfaces(requested, nil)
	}
	return mergeInterfaces(requested, found)
}

// checkStatePath refuses a state path (or its parent) that is a symlink or a
// file this process does not own, so the root helper never follows a link
// planted by someone else.
func checkStatePath(path string) error {
	for _, p := range []string{filepath.Dir(path), path} {
		info, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("fail-closed state path %s is a symlink", p)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
			return fmt.Errorf("fail-closed state path %s is owned by uid %d, not this process", p, st.Uid)
		}
	}
	return nil
}

func (m *failClosedManager) load() (failClosedState, error) {
	var st failClosedState
	if err := checkStatePath(m.statePath); err != nil {
		return st, err
	}
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
	if err := checkStatePath(m.statePath); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.statePath + ".tmp"
	if info, err := os.Lstat(tmp); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("fail-closed temp state %s is a symlink", tmp)
		}
		_ = os.Remove(tmp)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
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
	if _, err := failclosed.RenderAnchor(req.Interfaces); err != nil {
		return err
	}
	ifaces := m.coveredInterfaces(req.Interfaces)
	anchor, err := failclosed.RenderAnchor(ifaces)
	if err != nil {
		return err
	}
	table, err := failclosed.ValidateTable(req.Table)
	if err != nil {
		return err
	}
	if len(table) == 0 {
		return errEmptyFailClosedTable
	}
	st, err := m.load()
	if err != nil {
		return err
	}
	return m.applyLocked(st, ifaces, table, anchor)
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
		// Record the token at once so it can always be released later. If it
		// cannot be recorded, give it back now rather than orphan it.
		if err := m.save(st); err != nil {
			if _, relErr := m.run([]string{"-X", token}, ""); relErr != nil {
				return fmt.Errorf("record pf token: %w; releasing it also failed: %v", err, relErr)
			}
			return fmt.Errorf("record pf token (released): %w", err)
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
	if err := m.save(st); err != nil {
		return err
	}
	if m.logf != nil {
		m.logf("vpn core: fail-closed applied: interfaces=%d entries=%d\n", len(interfaces), len(table))
	}
	return nil
}

// Clear flushes the anchor, releases the token and records enabled=false so
// the block stays off after reboot.
func (m *failClosedManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, loadErr := m.load()
	if loadErr != nil {
		// A corrupt state must not prevent the owner's rollback, but its token
		// must not be forgotten silently.
		st = failClosedState{Token: tokenFromRawState(m.statePath)}
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
	if err := m.save(failClosedState{Enabled: false}); err != nil {
		return err
	}
	if m.logf != nil {
		m.logf("vpn core: fail-closed cleared: token_released=%t\n", st.Token != "")
	}
	if loadErr != nil && st.Token == "" {
		return fmt.Errorf("anchor cleared, but the pf token could not be recovered from the unreadable state (%v); check 'pfctl -s References' and release it with 'pfctl -X <token>'", loadErr)
	}
	return nil
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
	out := FailClosedStatus{
		Enabled: st.Enabled, Interfaces: st.Interfaces, TableEntries: len(st.Table),
		TokenHeld: st.Token != "", AppliedAt: st.AppliedAt, LastError: st.LastError,
		LastRecovery: st.LastRecovery, RecoveredAt: st.RecoveredAt,
		Backoff: m.backoffNote,
	}
	if !st.Enabled {
		return out, nil
	}
	f, err := m.readLiveLocked()
	if err != nil {
		out.LiveError = err.Error()
		return out, nil
	}
	out.LiveChecked, out.PFEnabled, out.LiveTableEntries = true, f.pfEnabled, f.tableEntries
	out.AnchorLoaded = len(f.rulesPerIface) > 0
	for _, i := range st.Interfaces {
		if !f.rulesPerIface[i] {
			out.AnchorLoaded = false
		}
	}
	out.Enforcing = out.PFEnabled && out.AnchorLoaded && out.LiveTableEntries == len(st.Table) && len(st.Table) > 0
	return out, nil
}

// liveFacts is what pf currently enforces for our anchor.
type liveFacts struct {
	pfEnabled     bool
	rulesPerIface map[string]bool
	tableEntries  int
}

// readLiveLocked queries pf for the enable status, our anchor's rules and
// table. Rules are matched per interface because pf expands { en0 en1 }.
func (m *failClosedManager) readLiveLocked() (liveFacts, error) {
	f := liveFacts{rulesPerIface: map[string]bool{}}
	info, err := m.run([]string{"-s", "info"}, "")
	if err != nil {
		return f, err
	}
	f.pfEnabled = pfStatusEnabledRE.Match(info)
	rules, err := m.run([]string{"-a", failclosed.AnchorName, "-s", "rules"}, "")
	if err != nil {
		return f, err
	}
	for _, line := range strings.Split(string(rules), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "block return out quick on ") || !strings.Contains(line, "<"+failclosed.TableName+">") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "block return out quick on "))
		if len(fields) > 0 {
			for _, n := range strings.FieldsFunc(strings.Trim(fields[0], "{}"), func(r rune) bool { return r == ',' || r == ' ' }) {
				f.rulesPerIface[n] = true
			}
		}
		// The unexpanded form "{ en0 en1 }" spans several fields.
		if strings.HasPrefix(fields[0], "{") {
			for _, n := range fields[1:] {
				if n == "}" {
					break
				}
				f.rulesPerIface[strings.Trim(n, "{},")] = true
			}
		}
	}
	entries, err := m.run([]string{"-a", failclosed.AnchorName, "-t", failclosed.TableName, "-T", "show"}, "")
	if err == nil {
		for _, l := range strings.Split(string(entries), "\n") {
			if strings.TrimSpace(l) != "" {
				f.tableEntries++
			}
		}
	}
	return f, nil
}

// inspectLocked compares pf's live state with the stored policy and names the
// first difference ("" when everything matches).
func (m *failClosedManager) inspectLocked(st failClosedState) (string, error) {
	f, err := m.readLiveLocked()
	if err != nil {
		return "", err
	}
	switch {
	case !f.pfEnabled:
		return "pf disabled by another party", nil
	case len(f.rulesPerIface) == 0:
		return "anchor rules missing", nil
	}
	for _, i := range st.Interfaces {
		if !f.rulesPerIface[i] {
			return "anchor rules missing", nil
		}
	}
	if f.tableEntries != len(st.Table) {
		return "anchor table missing", nil
	}
	return "", nil
}

var pfStatusEnabledRE = regexp.MustCompile(`(?m)^Status:\s*Enabled\b`)

// Check verifies that an enabled policy is still in force: pf enabled, our
// anchor rules loaded and our table populated. Another party may reload
// /etc/pf.conf, reload the com.apple anchor or run pfctl -d (the work VPN's
// vpn-slice does such things). On a finding it re-applies, re-enabling pf only
// through a fresh token of its own, and records what happened. It returns the
// finding ("" when everything was in force).
func (m *failClosedManager) Check() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.load()
	if err != nil || !st.Enabled {
		return "", err
	}
	finding, err := m.inspectLocked(st)
	if err != nil {
		return "", err
	}
	if finding == "" {
		if covered := m.coveredInterfaces(st.Interfaces); strings.Join(covered, ",") != strings.Join(st.Interfaces, ",") {
			finding = "physical interfaces changed"
			st.Interfaces = covered
		}
	}
	if finding == "" {
		return "", nil
	}
	if finding == "pf disabled by another party" {
		// pfctl -d drops every enable reference, ours included.
		st.Token = ""
	}
	anchor, err := failclosed.RenderAnchor(st.Interfaces)
	if err != nil {
		return finding, err
	}
	table, err := failclosed.ValidateTable(st.Table)
	if err != nil {
		return finding, err
	}
	if err := m.applyLocked(st, st.Interfaces, table, anchor); err != nil {
		return finding, err
	}
	st, err = m.load()
	if err != nil {
		return finding, err
	}
	st.LastRecovery, st.RecoveredAt = finding, m.now().UTC()
	return finding, m.save(st)
}

// failClosedWatchMaxIntervalVPNCore caps the watchdog's backoff when another
// party keeps undoing the block.
var failClosedWatchMaxIntervalVPNCore = 5 * time.Minute

// watch runs Check every interval until stop is closed. After consecutive
// recoveries the interval doubles up to the maximum (another tool fighting the
// anchor must not make the helper spin); a quiet tick resets it.
func (m *failClosedManager) watch(interval time.Duration, stop <-chan struct{}, logf func(string, ...any)) {
	current, streak := interval, 0
	timer := time.NewTimer(current)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
		}
		finding, err := m.Check()
		switch {
		case finding != "":
			streak++
			logf("vpn core: fail-closed watchdog: %s; re-applied (err=%v)\n", finding, err)
			if streak > 1 && current < failClosedWatchMaxIntervalVPNCore {
				current *= 2
				if current > failClosedWatchMaxIntervalVPNCore {
					current = failClosedWatchMaxIntervalVPNCore
				}
			}
		case err != nil:
			logf("vpn core: fail-closed watchdog: %v\n", err)
		default:
			streak, current = 0, interval
		}
		m.mu.Lock()
		if streak > 1 {
			m.backoffNote = fmt.Sprintf("%d recoveries in a row; checking every %s", streak, current)
		} else {
			m.backoffNote = ""
		}
		m.mu.Unlock()
		timer.Reset(current)
	}
}
