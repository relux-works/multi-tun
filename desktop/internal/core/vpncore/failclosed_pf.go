package vpncore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	TableMatches     bool      `json:"table_matches"`
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

// checkStatePath refuses symlinks and foreign ownership along the entire path.
// System ancestors may be root-owned; the state file and its parent belong to
// this process. Callers must keep their ancestors protected against replacement.
func checkStatePath(path string) error {
	return checkStatePathWithLstat(path, os.Lstat)
}

func checkStatePathWithLstat(path string, lstat func(string) (os.FileInfo, error)) error {
	// Cleaning a link/../ component before Lstat would check a different path
	// from the one ReadFile or MkdirAll traverses. Require one lexical spelling.
	if filepath.Clean(path) != path {
		return fmt.Errorf("fail-closed state path %s is not clean", path)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	for p := path; ; p = filepath.Dir(p) {
		info, err := lstat(p)
		if errors.Is(err, os.ErrNotExist) && p != filepath.Dir(p) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("fail-closed state path %s is a symlink", p)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("fail-closed state path %s has no ownership information", p)
		}
		owned := int(st.Uid) == os.Geteuid()
		if !owned && !(st.Uid == 0 && p != path && p != parent) {
			return fmt.Errorf("fail-closed state path %s is owned by uid %d, not this process", p, st.Uid)
		}
		if p == filepath.Dir(p) {
			break
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
	if err := checkStatePath(m.statePath); err != nil {
		return err
	}
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
	if err := checkStatePath(m.statePath); err != nil {
		return err
	}
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
		m.logf("vpn core: fail-closed cleared: entries=%d interfaces=%d token_released=%t\n", len(st.Table), len(st.Interfaces), st.Token != "")
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
	out.LiveChecked, out.PFEnabled, out.LiveTableEntries = true, f.pfEnabled, len(f.table)
	out.AnchorLoaded = f.anchorMatches(st.Interfaces)
	out.TableMatches = f.tableMatches(st.Table)
	out.Enforcing = out.PFEnabled && out.AnchorLoaded && out.TableMatches
	return out, nil
}

// liveFacts is what pf currently enforces for our anchor.
type liveFacts struct {
	pfEnabled     bool
	rulesPerIface map[string]bool
	// foreignRules counts anchor rule lines that are not exactly our block
	// rule (a permissive, narrowed or extra rule).
	foreignRules int
	table        []string // normalized prefixes, sorted
}

// ourRuleRE is pf's normalized form of the rendered block rule, one line per
// interface ("block return out quick on en0 from any to <failclosed>").
var ourRuleRE = regexp.MustCompile(`^block return out quick on ([a-z]+[0-9]+) (?:from any )?to <` + failclosed.TableName + `>$`)

// readLiveLocked queries pf for the enable status, our anchor's rules and
// the table entries.
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
		line = strings.Join(strings.Fields(line), " ")
		if line == "" {
			continue
		}
		if m := ourRuleRE.FindStringSubmatch(line); m != nil {
			f.rulesPerIface[m[1]] = true
			continue
		}
		f.foreignRules++
	}
	entries, err := m.run([]string{"-a", failclosed.AnchorName, "-t", failclosed.TableName, "-T", "show"}, "")
	if err == nil {
		f.table = normalizeShownTable(string(entries))
	}
	return f, nil
}

// normalizeShownTable turns pfctl -T show output (hosts without a prefix
// length) into sorted prefixes comparable with the stored table.
func normalizeShownTable(out string) []string {
	var table []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if p, err := netip.ParsePrefix(l); err == nil {
			table = append(table, p.Masked().String())
			continue
		}
		if a, err := netip.ParseAddr(l); err == nil {
			table = append(table, netip.PrefixFrom(a, a.BitLen()).String())
			continue
		}
		table = append(table, "invalid:"+l)
	}
	sort.Strings(table)
	return table
}

// anchorMatches reports whether every interface has exactly our rule and no
// other rule is present.
func (f liveFacts) anchorMatches(ifaces []string) bool {
	if f.foreignRules != 0 || len(ifaces) == 0 {
		return false
	}
	for _, i := range ifaces {
		if !f.rulesPerIface[i] {
			return false
		}
	}
	return true
}

func (f liveFacts) tableMatches(stored []string) bool {
	return len(stored) > 0 && strings.Join(f.table, ",") == strings.Join(stored, ",")
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
	case !f.anchorMatches(st.Interfaces):
		return "anchor rules missing or altered", nil
	case !f.tableMatches(st.Table):
		return "anchor table missing or altered", nil
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

// watch runs Check every interval until stop is closed. Detection stays at
// one interval even when another party keeps undoing the block (contract:
// 5 s); only the log is thinned after three recoveries in a row, and status
// reports the streak.
func (m *failClosedManager) watch(interval time.Duration, stop <-chan struct{}, logf func(string, ...any)) {
	streak := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		finding, err := m.Check()
		switch {
		case finding != "":
			streak++
			if streak <= 3 || streak%12 == 0 {
				logf("vpn core: fail-closed watchdog: %s; re-applied (err=%v, %d in a row)\n", finding, err, streak)
			}
		case err != nil:
			logf("vpn core: fail-closed watchdog: %v\n", err)
		default:
			streak = 0
		}
		m.mu.Lock()
		if streak > 1 {
			m.backoffNote = fmt.Sprintf("%d recoveries in a row; another party keeps undoing the block; checking every %s", streak, interval)
		} else {
			m.backoffNote = ""
		}
		m.mu.Unlock()
	}
}
