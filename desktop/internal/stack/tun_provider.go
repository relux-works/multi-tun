package stack

import (
	"context"
	"errors"
	"time"
)

// TunProvider adapts the application's existing renderer/session/fail-closed
// implementation. The adapter avoids an import cycle with CLI credential and
// profile selection; it never invents a second rendering implementation.
type TunProvider struct {
	ProviderKind  ProviderKind
	PrepareFunc   func(context.Context, MemberSpec, []PreparedMember) (PreparedMember, error)
	StartFunc     func(context.Context, PreparedMember, RoutingFragment, DNSFragment) (MemberState, error)
	StopFunc      func(context.Context, MemberSpec, bool, time.Duration) (MemberState, error)
	StatusFunc    func(context.Context, MemberSpec) (MemberState, error)
	ReconcileFunc func(context.Context, MemberSpec, RoutingFragment, DNSFragment) (MemberState, error)
}

func (p *TunProvider) Kind() ProviderKind { return p.ProviderKind }
func (p *TunProvider) Prepare(ctx context.Context, s MemberSpec, peers []PreparedMember) (PreparedMember, error) {
	if p.PrepareFunc == nil {
		return PreparedMember{}, errors.New("TUN preparation unavailable")
	}
	return p.PrepareFunc(ctx, s, peers)
}
func (p *TunProvider) Start(ctx context.Context, m PreparedMember, r RoutingFragment, d DNSFragment) (MemberState, error) {
	if p.StartFunc == nil {
		return MemberState{}, errors.New("TUN activation unavailable")
	}
	return p.StartFunc(ctx, m, r, d)
}
func (p *TunProvider) Stop(ctx context.Context, s MemberSpec, force bool, timeout time.Duration) (MemberState, error) {
	if p.StopFunc == nil {
		return MemberState{}, errors.New("TUN stop unavailable")
	}
	return p.StopFunc(ctx, s, force, timeout)
}
func (p *TunProvider) Status(ctx context.Context, s MemberSpec) (MemberState, error) {
	if p.StatusFunc == nil {
		return MemberState{}, errors.New("TUN status unavailable")
	}
	return p.StatusFunc(ctx, s)
}
func (p *TunProvider) Reconcile(ctx context.Context, s MemberSpec, r RoutingFragment, d DNSFragment) (MemberState, error) {
	if p.ReconcileFunc == nil {
		return MemberState{}, errors.New("TUN reconciliation unavailable")
	}
	return p.ReconcileFunc(ctx, s, r, d)
}
