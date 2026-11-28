// Package stack coordinates tunnel providers without delegating lifecycle
// decisions to subprocesses. Providers own their data plane and credentials.
package stack

import (
	"context"
	"time"
)

type ProviderKind string

const (
	ProviderOpenConnect  ProviderKind = "openconnect"
	ProviderAmneziaAWG   ProviderKind = "amnezia-awg"
	ProviderVLESS        ProviderKind = "vless"
	ProviderVLESSReality ProviderKind = "vless-reality"
	ProviderXray         ProviderKind = "xray"
)

type RoutingFragment struct {
	RouteExcludes  []string
	IncludeRoutes  []string
	BypassSuffixes []string
	DirectProcess  []string
}
type DNSFragment struct {
	Domains       []string
	BypassDomains []string
	Nameservers   []string
	SystemServers []string
}
type MemberSpec struct {
	Selector string
	Server   string
	Profile  string
	Kind     ProviderKind
	Role     string
}
type PreparedMember struct {
	Spec      MemberSpec
	Routing   RoutingFragment
	DNS       DNSFragment
	Interface string
	Payload   any `json:"-"`
}
type MemberState struct {
	Spec      MemberSpec
	Active    bool
	Status    string
	SessionID string
	PID       int
	Interface string
	LogPath   string
	PAC       string
	Error     string
}
type TunnelProvider interface {
	Kind() ProviderKind
	Prepare(context.Context, MemberSpec, []PreparedMember) (PreparedMember, error)
	Start(context.Context, PreparedMember, RoutingFragment, DNSFragment) (MemberState, error)
	Stop(context.Context, MemberSpec, bool, time.Duration) (MemberState, error)
	Status(context.Context, MemberSpec) (MemberState, error)
}

// FragmentProvider supplies live, emitted fragments after activation. Prepare
// alone cannot know DHCP-assigned DNS or routes.
type FragmentProvider interface {
	Fragments(context.Context, MemberSpec) (RoutingFragment, DNSFragment, error)
}

// Reconciler applies one coordinated render to an existing egress. During
// Order B, a first call excludes resolved gateway addresses before overlay auth;
// a second call consumes the overlay's live fragments after auth completes.
type Reconciler interface {
	Reconcile(context.Context, MemberSpec, RoutingFragment, DNSFragment) (MemberState, error)
}

type ResolveMemberFunc func(context.Context, string) (MemberSpec, error)
