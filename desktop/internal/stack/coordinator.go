package stack

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

type State string

const (
	StateIdle                   State = "idle"
	StatePreparingProviders     State = "preparing_providers"
	StateApplyingCorePrimitives State = "applying_core_primitives"
	StateVerifyingReadiness     State = "verifying_readiness"
	StateActive                 State = "active"
	StateStopping               State = "stopping"
)

type Verdict string

const (
	VerdictAdmit  Verdict = "Admit"
	VerdictRefuse Verdict = "Refuse"
	VerdictClose  Verdict = "Close"
)

type RefusalCode string

const (
	StackEmpty            RefusalCode = "STACK_EMPTY"
	StackInvalidSelector  RefusalCode = "STACK_INVALID_SELECTOR"
	StackMemberUnknown    RefusalCode = "STACK_MEMBER_UNKNOWN"
	StackDuplicateServer  RefusalCode = "STACK_DUPLICATE_SERVER"
	StackTunConflict      RefusalCode = "STACK_TUN_CONFLICT"
	ProviderUnavailable   RefusalCode = "PROVIDER_UNAVAILABLE"
	ProviderPrepareFailed RefusalCode = "PROVIDER_PREPARE_FAILED"
	ProviderStartFailed   RefusalCode = "PROVIDER_START_FAILED"
	ReadinessFailed       RefusalCode = "READINESS_FAILED"
	RollbackFailed        RefusalCode = "ROLLBACK_FAILED"
)

type StackError struct {
	Code       RefusalCode
	Verdict    Verdict
	Phase      State
	Member     string
	Message    string
	Cause      error
	RolledBack []string
}

func (e *StackError) Error() string {
	return fmt.Sprintf("%s (%s, %s): %s", e.Code, e.Phase, e.Member, e.Message)
}
func (e *StackError) Unwrap() error { return e.Cause }
func refusal(code RefusalCode, phase State, member string, err error) *StackError {
	return &StackError{Code: code, Verdict: VerdictRefuse, Phase: phase, Member: member, Message: err.Error(), Cause: err}
}

type StartStackOptions struct {
	Refresh bool
	Timeout time.Duration
}
type UpOptions struct {
	Refresh bool
	Replace bool
	Timeout time.Duration
}
type DownOptions struct {
	Force   bool
	Timeout time.Duration
}
type StackReport struct {
	Verdict       Verdict       `json:"verdict"`
	State         State         `json:"state"`
	Members       []MemberState `json:"members"`
	AlreadyActive bool          `json:"already_active,omitempty"`
	RolledBack    []string      `json:"rolled_back,omitempty"`
	Transitions   []State       `json:"transitions,omitempty"`
}
type StackStatus struct {
	State   State
	Members []MemberState
}
type CoordinatorOptions struct {
	Providers  map[ProviderKind]TunnelProvider
	Resolve    ResolveMemberFunc
	Configured []MemberSpec
	StatePath  string
}
type Coordinator struct {
	mu         sync.Mutex
	providers  map[ProviderKind]TunnelProvider
	resolve    ResolveMemberFunc
	configured []MemberSpec
	statePath  string
	memory     ActiveStackState
}

func NewCoordinator(opts CoordinatorOptions) *Coordinator {
	providers := make(map[ProviderKind]TunnelProvider, len(opts.Providers))
	for k, p := range opts.Providers {
		providers[k] = p
	}
	return &Coordinator{providers: providers, resolve: opts.Resolve, configured: append([]MemberSpec(nil), opts.Configured...), statePath: opts.StatePath, memory: ActiveStackState{Version: 1}}
}
func ParseSelector(selector string) (MemberSpec, error) {
	parts := strings.Split(selector, "/")
	if selector == "" || len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") || strings.ContainsFunc(selector, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return MemberSpec{}, refusal(StackInvalidSelector, StateIdle, selector, errors.New("expected server or server/profile"))
	}
	spec := MemberSpec{Selector: selector, Server: parts[0]}
	if len(parts) == 2 {
		spec.Profile = parts[1]
	}
	return spec, nil
}
func (c *Coordinator) resolveSpec(ctx context.Context, selector string) (MemberSpec, error) {
	parsed, err := ParseSelector(selector)
	if err != nil {
		return MemberSpec{}, err
	}
	if c.resolve == nil {
		return MemberSpec{}, refusal(StackMemberUnknown, StateIdle, selector, errors.New("member resolver unavailable"))
	}
	spec, err := c.resolve(ctx, selector)
	if err != nil {
		return MemberSpec{}, refusal(StackMemberUnknown, StateIdle, selector, err)
	}
	spec.Selector, spec.Server = parsed.Selector, parsed.Server
	if spec.Profile == "" {
		spec.Profile = parsed.Profile
	}
	if spec.Kind == ProviderOpenConnect {
		spec.Role = "overlay"
	} else {
		spec.Role = "egress"
	}
	switch spec.Kind {
	case ProviderOpenConnect, ProviderAmneziaAWG, ProviderVLESS, ProviderVLESSReality, ProviderXray:
	default:
		return spec, refusal(ProviderUnavailable, StateIdle, selector, errors.New("unknown provider kind"))
	}
	if p := c.providers[spec.Kind]; p == nil || p.Kind() != spec.Kind {
		return spec, refusal(ProviderUnavailable, StateIdle, selector, errors.New("provider unavailable"))
	}
	return spec, nil
}
func validateMembers(specs []MemberSpec) error {
	seen := map[string]bool{}
	egress := 0
	for _, s := range specs {
		if seen[s.Server] {
			return refusal(StackDuplicateServer, StateIdle, s.Selector, errors.New("a server can appear only once"))
		}
		seen[s.Server] = true
		if s.Role == "egress" {
			egress++
			if egress > 1 {
				return refusal(StackTunConflict, StateIdle, s.Selector, errors.New("only one egress TUN may be active"))
			}
		}
	}
	return nil
}
func orderSpecs(specs []MemberSpec) {
	sort.SliceStable(specs, func(i, j int) bool {
		if specs[i].Role != specs[j].Role {
			return specs[i].Role == "overlay"
		}
		return specs[i].Selector < specs[j].Selector
	})
}
func (c *Coordinator) transaction(ctx context.Context, fn func() (StackReport, error)) (StackReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	unlock, err := lockState(ctx, c.statePath)
	if err != nil {
		return failedReport(refusal(ProviderUnavailable, StateIdle, "", err))
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return failedReport(refusal(ProviderUnavailable, StateIdle, "", err))
	}
	return fn()
}
func failedReport(err error) (StackReport, error) {
	report := StackReport{Verdict: VerdictRefuse, State: StateIdle}
	var se *StackError
	if errors.As(err, &se) {
		report.State = se.Phase
		report.RolledBack = se.RolledBack
	}
	return report, err
}
func (c *Coordinator) saved() (ActiveStackState, error) {
	if c.statePath == "" {
		return c.memory, nil
	}
	return readState(c.statePath)
}
func (c *Coordinator) save(members []MemberState) error {
	state := ActiveStackState{Version: 1, Members: append([]MemberState(nil), members...), UpdatedAt: time.Now().UTC()}
	if err := writeState(c.statePath, state); err != nil {
		return err
	}
	c.memory = state
	return nil
}
func (c *Coordinator) inspect(ctx context.Context) ([]MemberState, error) {
	state, err := c.saved()
	if err != nil {
		return nil, err
	}
	specs := make([]MemberSpec, 0, len(state.Members)+len(c.configured))
	seen := map[string]bool{}
	for _, m := range state.Members {
		specs = append(specs, m.Spec)
		seen[m.Spec.Server] = true
	}
	for _, s := range c.configured {
		if !seen[s.Server] {
			specs = append(specs, s)
			seen[s.Server] = true
		}
	}
	orderSpecs(specs)
	var out []MemberState
	for _, s := range specs {
		parsed, parseErr := ParseSelector(s.Selector)
		if parseErr != nil || parsed.Server != s.Server {
			return nil, errors.New("invalid tracked stack member")
		}
		if s.Kind == ProviderOpenConnect {
			s.Role = "overlay"
		} else {
			s.Role = "egress"
		}
		p := c.providers[s.Kind]
		if p == nil {
			return nil, fmt.Errorf("provider %s unavailable for tracked member %s", s.Kind, s.Selector)
		}
		m, err := p.Status(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", s.Selector, err)
		}
		if m.Spec.Server != s.Server || m.Spec.Selector == "" {
			m.Spec = s
		}
		out = append(out, m)
	}
	return out, nil
}

// inspectRequested also discovers requested legacy providers that have not yet
// acquired a stack record in the unified cache.
func (c *Coordinator) inspectRequested(ctx context.Context, specs []MemberSpec) ([]MemberState, error) {
	all, err := c.inspect(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, m := range all {
		seen[m.Spec.Server] = true
	}
	for _, spec := range specs {
		if !seen[spec.Server] {
			m, err := c.providers[spec.Kind].Status(ctx, spec)
			if err != nil {
				return nil, err
			}
			if m.Spec.Server != spec.Server || m.Spec.Selector == "" {
				m.Spec = spec
			}
			all = append(all, m)
			seen[spec.Server] = true
		}
	}
	return all, nil
}

func activeOnly(all []MemberState) []MemberState {
	var out []MemberState
	for _, m := range all {
		if m.Active {
			out = append(out, m)
		}
	}
	return out
}
func specsOf(members []MemberState) []MemberSpec {
	out := make([]MemberSpec, 0, len(members))
	for _, m := range members {
		out = append(out, m.Spec)
	}
	return out
}
func (c *Coordinator) fragments(ctx context.Context, members []MemberState) ([]PreparedMember, error) {
	var out []PreparedMember
	for _, m := range members {
		if m.Spec.Role != "overlay" {
			continue
		}
		p, ok := c.providers[m.Spec.Kind].(FragmentProvider)
		if !ok {
			return nil, fmt.Errorf("%s cannot emit live overlay fragments", m.Spec.Selector)
		}
		r, d, err := p.Fragments(ctx, m.Spec)
		if err != nil {
			return nil, err
		}
		out = append(out, PreparedMember{Spec: m.Spec, Interface: m.Interface, Routing: r, DNS: d})
	}
	return out, nil
}

// MergeFragments is stable, sorted and duplicate-free regardless of provider
// map order. It copies inputs, so a provider cannot mutate another's fragments.
func MergeFragments(members []PreparedMember) (RoutingFragment, DNSFragment) {
	var r RoutingFragment
	var d DNSFragment
	for _, m := range members {
		r.RouteExcludes = append(r.RouteExcludes, m.Routing.RouteExcludes...)
		r.IncludeRoutes = append(r.IncludeRoutes, m.Routing.IncludeRoutes...)
		r.BypassSuffixes = append(r.BypassSuffixes, m.Routing.BypassSuffixes...)
		r.DirectProcess = append(r.DirectProcess, m.Routing.DirectProcess...)
		d.Domains = append(d.Domains, m.DNS.Domains...)
		d.BypassDomains = append(d.BypassDomains, m.DNS.BypassDomains...)
		d.Nameservers = append(d.Nameservers, m.DNS.Nameservers...)
		d.SystemServers = append(d.SystemServers, m.DNS.SystemServers...)
	}
	r.RouteExcludes = unique(r.RouteExcludes)
	r.IncludeRoutes = unique(r.IncludeRoutes)
	r.BypassSuffixes = unique(r.BypassSuffixes)
	r.DirectProcess = unique(r.DirectProcess)
	d.Domains = unique(d.Domains)
	d.BypassDomains = unique(d.BypassDomains)
	d.Nameservers = unique(d.Nameservers)
	d.SystemServers = unique(d.SystemServers)
	return r, d
}
func unique(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, v := range values {
		if v != "" && (len(out) == 0 || out[len(out)-1] != v) {
			out = append(out, v)
		}
	}
	return out
}
func (c *Coordinator) rollback(ctx context.Context, started []MemberState, original *StackError, prior []MemberState) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	var failures []error
	remaining := append([]MemberState(nil), prior...)
	for i := len(started) - 1; i >= 0; i-- {
		m := started[i]
		stopped, err := c.providers[m.Spec.Kind].Stop(cleanup, m.Spec, true, 20*time.Second)
		if err != nil || stopped.Active {
			failures = append(failures, fmt.Errorf("rollback %s: %v", m.Spec.Selector, err))
			remaining = append(remaining, m)
		} else {
			original.RolledBack = append(original.RolledBack, m.Spec.Selector)
		}
	}
	if err := c.save(remaining); err != nil {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		original.Code = RollbackFailed
		original.Message = "rollback incomplete"
		original.Cause = errors.Join(append([]error{original.Cause}, failures...)...)
	}
	return original
}
func (c *Coordinator) activate(ctx context.Context, specs []MemberSpec, prior []MemberState, preparedFirst *PreparedMember) (StackReport, error) {
	report := StackReport{Verdict: VerdictAdmit, State: StatePreparingProviders, Members: append([]MemberState(nil), prior...), Transitions: []State{StatePreparingProviders}}
	peers, err := c.fragments(ctx, prior)
	if err != nil {
		return failedReport(refusal(ProviderPrepareFailed, StatePreparingProviders, "", err))
	}
	var started []MemberState
	fail := func(code RefusalCode, s MemberSpec, err error) (StackReport, error) {
		se := refusal(code, report.State, s.Selector, err)
		err = c.rollback(ctx, started, se, prior)
		report.Verdict = VerdictRefuse
		report.RolledBack = se.RolledBack
		report.Members = append([]MemberState(nil), prior...)
		for _, m := range started {
			rolledBack := false
			for _, selector := range se.RolledBack {
				if selector == m.Spec.Selector {
					rolledBack = true
				}
			}
			if !rolledBack {
				report.Members = append(report.Members, m)
			}
		}
		return report, err
	}
	orderSpecs(specs)
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return fail(ProviderPrepareFailed, spec, err)
		}
		report.State = StatePreparingProviders
		report.Transitions = append(report.Transitions, report.State)
		p := c.providers[spec.Kind]
		var prepared PreparedMember
		if preparedFirst != nil && preparedFirst.Spec.Selector == spec.Selector {
			prepared = *preparedFirst
		} else {
			prepared, err = p.Prepare(ctx, spec, peers)
		}
		if err != nil {
			return fail(ProviderPrepareFailed, spec, err)
		}
		prepared.Spec = spec
		r, d := MergeFragments(peers)
		report.State = StateApplyingCorePrimitives
		report.Transitions = append(report.Transitions, report.State)
		m, startErr := p.Start(ctx, prepared, r, d)
		m.Spec = spec
		// Providers must return their partial session on an ambiguous failed start.
		if startErr == nil || m.Active || m.SessionID != "" || m.PID > 0 {
			started = append(started, m)
		}
		if startErr != nil {
			return fail(ProviderStartFailed, spec, startErr)
		}
		report.Members = append(report.Members, m)
		if spec.Role == "overlay" {
			emitter, ok := p.(FragmentProvider)
			if !ok {
				return fail(ProviderPrepareFailed, spec, errors.New("overlay provider has no live fragments"))
			}
			prepared.Routing, prepared.DNS, err = emitter.Fragments(ctx, spec)
			if err != nil {
				return fail(ProviderPrepareFailed, spec, err)
			}
			prepared.Payload = nil
			peers = append(peers, prepared)
		}
	}
	report.State = StateVerifyingReadiness
	report.Transitions = append(report.Transitions, report.State)
	for i, m := range report.Members {
		live, err := c.providers[m.Spec.Kind].Status(ctx, m.Spec)
		if err != nil {
			return fail(ReadinessFailed, m.Spec, err)
		}
		if !healthy(live) {
			return fail(ReadinessFailed, m.Spec, errors.New("provider is not active"))
		}
		live.Spec = m.Spec
		report.Members[i] = live
	}
	if err := c.save(report.Members); err != nil {
		return fail(ProviderStartFailed, MemberSpec{}, fmt.Errorf("persist stack: %w", err))
	}
	report.State = StateActive
	report.Transitions = append(report.Transitions, report.State)
	return report, nil
}
func (c *Coordinator) StartStack(ctx context.Context, selectors []string, opts StartStackOptions) (StackReport, error) {
	return c.transaction(ctx, func() (StackReport, error) {
		if len(selectors) == 0 {
			return failedReport(refusal(StackEmpty, StateIdle, "", errors.New("stack is empty")))
		}
		var specs []MemberSpec
		for _, selector := range selectors {
			s, err := c.resolveSpec(ctx, selector)
			if err != nil {
				return failedReport(err)
			}
			specs = append(specs, s)
		}
		if err := validateMembers(specs); err != nil {
			return failedReport(err)
		}
		all, err := c.inspectRequested(ctx, specs)
		if err != nil {
			return failedReport(refusal(ProviderUnavailable, StateIdle, "", err))
		}
		prior := activeOnly(all)
		union := specsOf(prior)
		var pending []MemberSpec
		for _, s := range specs {
			exists := false
			for _, m := range prior {
				if m.Spec.Server == s.Server {
					if m.Spec.Profile != s.Profile {
						return failedReport(refusal(StackDuplicateServer, StateIdle, s.Selector, errors.New("server already active under another profile")))
					}
					exists = true
				}
			}
			if !exists {
				union = append(union, s)
				pending = append(pending, s)
			}
		}
		if err := validateMembers(union); err != nil {
			return failedReport(err)
		}
		if len(pending) == 0 {
			return StackReport{Verdict: VerdictAdmit, State: StateActive, Members: prior, AlreadyActive: true}, nil
		}
		// Adding overlays to a live egress requires the Order-B Up flow.
		for _, s := range pending {
			if s.Role == "overlay" {
				for _, m := range prior {
					if m.Spec.Role == "egress" {
						return failedReport(refusal(StackTunConflict, StateIdle, s.Selector, errors.New("use up to add an overlay to an active egress")))
					}
				}
			}
		}
		return c.activate(ctx, pending, prior, nil)
	})
}
func (c *Coordinator) reconcile(ctx context.Context, member MemberState, peers []PreparedMember) (MemberState, error) {
	p, ok := c.providers[member.Spec.Kind].(Reconciler)
	if !ok {
		return member, errors.New("egress provider does not support reconciliation")
	}
	r, d := MergeFragments(peers)
	m, err := p.Reconcile(ctx, member.Spec, r, d)
	m.Spec = member.Spec
	return m, err
}
func (c *Coordinator) Up(ctx context.Context, selector string, opts UpOptions) (StackReport, error) {
	return c.transaction(ctx, func() (StackReport, error) {
		spec, err := c.resolveSpec(ctx, selector)
		if err != nil {
			return failedReport(err)
		}
		all, err := c.inspectRequested(ctx, []MemberSpec{spec})
		if err != nil {
			return failedReport(refusal(ProviderUnavailable, StateIdle, selector, err))
		}
		prior := activeOnly(all)
		var old *MemberState
		for i, m := range prior {
			if m.Spec.Server == spec.Server && m.Spec.Profile == spec.Profile {
				if !healthy(m) {
					return failedReport(refusal(ReadinessFailed, StateVerifyingReadiness, selector, errors.New("existing member is not healthy")))
				}
				return StackReport{Verdict: VerdictAdmit, State: StateActive, Members: prior, AlreadyActive: true}, nil
			}
			if m.Spec.Server == spec.Server && !(opts.Replace && spec.Role == "egress") {
				return failedReport(refusal(StackDuplicateServer, StateIdle, selector, errors.New("server already active")))
			}
			if m.Spec.Role == "egress" {
				copy := prior[i]
				old = &copy
			}
		}
		if spec.Role == "egress" && old != nil && !opts.Replace {
			return failedReport(refusal(StackTunConflict, StateIdle, selector, errors.New("another egress is active")))
		}
		peers, err := c.fragments(ctx, prior)
		if err != nil {
			return failedReport(refusal(ProviderPrepareFailed, StatePreparingProviders, selector, err))
		}
		prepared, err := c.providers[spec.Kind].Prepare(ctx, spec, peers)
		if err != nil {
			return failedReport(refusal(ProviderPrepareFailed, StatePreparingProviders, selector, err))
		}
		prepared.Spec = spec
		replaced := false
		preexcluded := false
		if old != nil && spec.Role == "egress" {
			stopped, err := c.providers[old.Spec.Kind].Stop(ctx, old.Spec, false, defaultTimeout(opts.Timeout))
			if err != nil || stopped.Active {
				return failedReport(refusal(ProviderStartFailed, StateStopping, old.Spec.Selector, errors.Join(err, errors.New("previous egress could not be stopped"))))
			}
			prior = without(prior, old.Spec.Server)
			replaced = true
		} else if old != nil && spec.Role == "overlay" {
			// Before authentication, prepare emits resolved gateway routes only. DNS
			// remains from the live overlays until the new one has actually started.
			gateway := PreparedMember{Routing: RoutingFragment{RouteExcludes: prepared.Routing.RouteExcludes, DirectProcess: prepared.Routing.DirectProcess}}
			updated, err := c.reconcile(ctx, *old, append(peers, gateway))
			if err == nil && !healthy(updated) {
				err = errors.New("pre-excluded egress is not healthy")
			}
			if err != nil {
				return failedReport(refusal(ProviderStartFailed, StateApplyingCorePrimitives, selector, err))
			}
			for i := range prior {
				if prior[i].Spec.Server == old.Spec.Server {
					prior[i] = updated
				}
			}
			preexcluded = true
		}
		report, startErr := c.activate(ctx, []MemberSpec{spec}, prior, &prepared)
		if startErr == nil && preexcluded {
			livePeers, err := c.fragments(ctx, report.Members)
			var updated MemberState
			if err == nil {
				updated, err = c.reconcile(ctx, *old, livePeers)
			}
			if err == nil && !healthy(updated) {
				err = errors.New("reconciled egress is not active")
			}
			if err != nil {
				se := refusal(ReadinessFailed, StateVerifyingReadiness, old.Spec.Selector, err)
				for _, m := range report.Members {
					if m.Spec.Server == spec.Server {
						startErr = c.rollback(ctx, []MemberState{m}, se, prior)
					}
				}
				report.Verdict = VerdictRefuse
				report.RolledBack = se.RolledBack
			} else {
				for i := range report.Members {
					if report.Members[i].Spec.Server == old.Spec.Server {
						report.Members[i] = updated
					}
				}
				if err := c.save(report.Members); err != nil {
					return failedReport(refusal(ProviderStartFailed, StateActive, selector, err))
				}
			}
		}
		var activationFailure *StackError
		if errors.As(startErr, &activationFailure) && activationFailure.Code == RollbackFailed {
			return report, startErr
		}
		if startErr != nil && preexcluded {
			restored, err := c.reconcile(context.WithoutCancel(ctx), *old, peers)
			if err != nil || !restored.Active {
				return failedReport(refusal(RollbackFailed, StateApplyingCorePrimitives, old.Spec.Selector, errors.Join(startErr, err)))
			}
			for i := range prior {
				if prior[i].Spec.Server == old.Spec.Server {
					prior[i] = restored
				}
			}
			if err := c.save(prior); err != nil {
				return failedReport(refusal(RollbackFailed, StateIdle, selector, err))
			}
		}
		if startErr != nil && replaced {
			_, restoreErr := c.activate(context.WithoutCancel(ctx), []MemberSpec{old.Spec}, prior, nil)
			if restoreErr != nil {
				return failedReport(refusal(RollbackFailed, StateApplyingCorePrimitives, old.Spec.Selector, errors.Join(startErr, restoreErr)))
			}
		}
		return report, startErr
	})
}
func defaultTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 20 * time.Second
	}
	return timeout
}
func without(members []MemberState, server string) []MemberState {
	var out []MemberState
	for _, m := range members {
		if m.Spec.Server != server {
			out = append(out, m)
		}
	}
	return out
}
func (c *Coordinator) Down(ctx context.Context, selector string, opts DownOptions) (StackReport, error) {
	return c.transaction(ctx, func() (StackReport, error) {
		parsed, err := ParseSelector(selector)
		if err != nil {
			return failedReport(err)
		}
		selectedProfile := parsed.Profile
		var requested []MemberSpec
		if parsed.Profile != "" {
			resolved, err := c.resolveSpec(ctx, selector)
			if err != nil {
				return failedReport(err)
			}
			selectedProfile = resolved.Profile
			requested = append(requested, resolved)
		}
		if len(requested) == 0 {
			if resolved, err := c.resolveSpec(ctx, selector); err == nil {
				requested = append(requested, resolved)
			}
		}
		all, err := c.inspectRequested(ctx, requested)
		if err != nil {
			return failedReport(refusal(ProviderUnavailable, StateStopping, selector, err))
		}
		active := activeOnly(all)
		var target *MemberState
		for i, m := range active {
			if m.Spec.Server == parsed.Server && (parsed.Profile == "" || m.Spec.Profile == selectedProfile) {
				copy := active[i]
				target = &copy
				break
			}
		}
		if target == nil {
			if _, err := c.resolveSpec(ctx, selector); err != nil {
				return failedReport(err)
			}
			return StackReport{Verdict: VerdictClose, State: stateFor(active), Members: active}, nil
		}
		stopped, err := c.providers[target.Spec.Kind].Stop(ctx, target.Spec, opts.Force, defaultTimeout(opts.Timeout))
		if err != nil || stopped.Active {
			return failedReport(refusal(ProviderStartFailed, StateStopping, selector, errors.Join(err, errors.New("member did not stop"))))
		}
		remaining := without(active, target.Spec.Server)
		if err := c.save(remaining); err != nil {
			return failedReport(refusal(ProviderStartFailed, StateStopping, selector, err))
		}
		if target.Spec.Role == "overlay" {
			peers, err := c.fragments(ctx, remaining)
			if err != nil {
				return failedReport(refusal(ProviderPrepareFailed, StateStopping, selector, err))
			}
			for i, m := range remaining {
				if m.Spec.Role == "egress" {
					updated, err := c.reconcile(ctx, m, peers)
					if err != nil || !healthy(updated) {
						return failedReport(refusal(ReadinessFailed, StateStopping, m.Spec.Selector, errors.Join(err, errors.New("surviving egress not ready"))))
					}
					remaining[i] = updated
				}
			}
		}
		if err := c.save(remaining); err != nil {
			return failedReport(refusal(ProviderStartFailed, StateStopping, selector, err))
		}
		return StackReport{Verdict: VerdictClose, State: stateFor(remaining), Members: remaining, Transitions: []State{StateStopping, stateFor(remaining)}}, nil
	})
}
func healthy(m MemberState) bool {
	return m.Active && (m.Status == "active" || m.Status == "healthy" || m.Status == "connected" || m.Status == "")
}

func stateFor(active []MemberState) State {
	if len(active) == 0 {
		return StateIdle
	}
	return StateActive
}
func (c *Coordinator) StopStack(ctx context.Context, opts DownOptions) (StackReport, error) {
	return c.transaction(ctx, func() (StackReport, error) {
		all, err := c.inspect(ctx)
		if err != nil {
			return failedReport(refusal(ProviderUnavailable, StateStopping, "", err))
		}
		remaining := activeOnly(all)
		specs := specsOf(remaining)
		orderSpecs(specs)
		var failures []error
		for i := len(specs) - 1; i >= 0; i-- {
			s := specs[i]
			m, err := c.providers[s.Kind].Stop(ctx, s, opts.Force, defaultTimeout(opts.Timeout))
			if err != nil || m.Active {
				failures = append(failures, fmt.Errorf("stop %s: %v", s.Selector, err))
				continue
			}
			remaining = without(remaining, s.Server)
		}
		if err := c.save(remaining); err != nil {
			failures = append(failures, err)
		}
		if len(failures) > 0 {
			return failedReport(refusal(ProviderStartFailed, StateStopping, "", errors.Join(failures...)))
		}
		return StackReport{Verdict: VerdictClose, State: StateIdle, Members: remaining, Transitions: []State{StateStopping, StateIdle}}, nil
	})
}
func (c *Coordinator) Status(ctx context.Context) (StackStatus, error) {
	report, err := c.transaction(ctx, func() (StackReport, error) {
		all, err := c.inspect(ctx)
		return StackReport{State: stateFor(activeOnly(all)), Members: all}, err
	})
	return StackStatus{State: report.State, Members: report.Members}, err
}
