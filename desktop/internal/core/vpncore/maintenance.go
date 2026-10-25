package vpncore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var maintenanceDrainTTL = 60 * time.Second

// Writers hold mutation. The short state lock keeps ping independent of slow
// mutating handlers and disk operations, preserving diagnostic availability.
func (d *serviceDaemon) setMaintenanceState(token string, until time.Time) {
	d.drainStateMu.Lock()
	defer d.drainStateMu.Unlock()
	d.drainToken = token
	d.drainUntil = until
}

func (d *serviceDaemon) maintenanceDrainState() *MaintenanceDrainState {
	d.drainStateMu.RLock()
	defer d.drainStateMu.RUnlock()
	state := &MaintenanceDrainState{Active: time.Now().Before(d.drainUntil)}
	if state.Active {
		state.ExpiresAt = d.drainUntil.UTC().Format(time.RFC3339)
	}
	return state
}

// Drain and renew run under mutation, so a child cannot start between the idle check
// and the drain transition. Tracker locking includes accepted, unread requests.
func (d *serviceDaemon) withIdle(requestID uint64, transition func() error) error {
	d.children.mu.Lock()
	defer d.children.mu.Unlock()
	d.requests.mu.Lock()
	defer d.requests.mu.Unlock()

	counts := make(map[string]int)
	for _, child := range d.children.children {
		counts[child.kind]++
	}
	var kinds []string
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	var busy []string
	for _, kind := range kinds {
		busy = append(busy, fmt.Sprintf("%d %s", counts[kind], kind))
	}
	if len(busy) != 0 {
		busy = []string{strings.Join(busy, ", ") + " child active"}
	}
	otherRequests := len(d.requests.queued) + len(d.requests.active)
	if _, ok := d.requests.active[requestID]; ok {
		otherRequests--
	}
	if otherRequests != 0 {
		busy = append(busy, fmt.Sprintf("%d other request(s) in flight", otherRequests))
	}
	if len(busy) != 0 {
		return fmt.Errorf("vpn core is busy: %s", strings.Join(busy, "; "))
	}
	return transition()
}

func (d *serviceDaemon) drain(requestID uint64) (string, error) {
	var token string
	err := d.withIdle(requestID, func() error {
		var bytes [32]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return fmt.Errorf("generate maintenance token: %w", err)
		}
		nextToken := hex.EncodeToString(bytes[:])
		until := time.Now().Add(maintenanceDrainTTL)
		if err := d.persistMaintenanceLease(nextToken, until); err != nil {
			return fmt.Errorf("persist maintenance drain: %w", err)
		}
		token = nextToken
		d.setMaintenanceState(nextToken, until)
		return nil
	})
	return token, err
}

func validMaintenanceToken(token string) bool {
	if len(token) != 64 || strings.ToLower(token) != token {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// Called under mutation. Expired owners cannot release or renew a successor.
func (d *serviceDaemon) requireDrainToken(token string) error {
	if !d.drainActive() {
		return errors.New("vpn core maintenance drain expired or inactive")
	}
	if token == "" || token != d.drainToken {
		return errors.New("vpn core maintenance drain token does not match")
	}
	return nil
}

func (d *serviceDaemon) undrain(token string) error {
	if err := d.requireDrainToken(token); err != nil {
		return err
	}
	if err := d.removeMaintenanceLease(); err != nil {
		return fmt.Errorf("remove maintenance drain: %w", err)
	}
	d.setMaintenanceState("", time.Time{})
	return nil
}

func (d *serviceDaemon) renew(token string, requestID uint64) error {
	if err := d.requireDrainToken(token); err != nil {
		return err
	}
	return d.withIdle(requestID, func() error {
		// Lock acquisition must not revive a token that expired while waiting.
		if err := d.requireDrainToken(token); err != nil {
			return err
		}
		until := time.Now().Add(maintenanceDrainTTL)
		if err := d.persistMaintenanceLease(token, until); err != nil {
			return fmt.Errorf("persist maintenance renewal: %w", err)
		}
		d.setMaintenanceState(token, until)
		return nil
	})
}

// MaintenanceOptions controls the explicit operator override for service changes.
type MaintenanceOptions struct {
	AllowDisruption bool
}

var maintenanceCallVPNCore = call
var maintenancePingVPNCore = func(cfg ServiceConfig, timeout time.Duration) (Response, error) {
	return callWithTimeout(cfg, Request{Action: "ping"}, timeout)
}

const maintenanceReadyTimeout = 10 * time.Second

// InstallMaintenanceError distinguishes a completed installation needing drain
// recovery from a bootstrap failure that may leave a lease in retained runtime.
// ExpiresAt comes from ping for an active inherited drain, or is a conservative
// client-side upper bound from the renewal reply when owned recovery failed.
type InstallMaintenanceError struct {
	Installed   bool
	DrainActive bool
	ExpiresAt   time.Time
	Err         error
}

func (e *InstallMaintenanceError) Error() string {
	if e.DrainActive {
		return fmt.Sprintf("warning: tunnel starts are blocked until %s by a maintenance lease from an earlier operation", e.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if e.ExpiresAt.IsZero() {
		return fmt.Sprintf("%v; warning: could not verify whether tunnel starts are blocked by a maintenance lease", e.Err)
	}
	return fmt.Sprintf("%v; warning: tunnel starts may remain blocked until %s by an inherited maintenance drain (including on a later bootstrap of retained runtime), or until the daemon answers and accepts owned undrain", e.Err, e.ExpiresAt.UTC().Format(time.RFC3339Nano))
}

func (e *InstallMaintenanceError) Unwrap() error { return e.Err }

type maintenanceLease struct {
	cfg   ServiceConfig
	token string
	until time.Time
}

type maintenanceGuard struct {
	leases   map[string]maintenanceLease
	configs  map[string]ServiceConfig
	override bool
}

// All services are drained before any privilege or installed-path mutation.
// Only unavailable sockets bypass the handshake; identity and protocol errors
// fail closed through the ordinary authenticated RPC client.
func drainServices(configs []ServiceConfig, options []MaintenanceOptions) (*maintenanceGuard, error) {
	guard := &maintenanceGuard{leases: make(map[string]maintenanceLease), configs: make(map[string]ServiceConfig)}
	if len(options) != 0 && options[0].AllowDisruption {
		guard.override = true
		return guard, nil
	}
	for _, cfg := range configs {
		guard.configs[cfg.Label] = cfg
		if err := guard.acquire(cfg); err != nil {
			guard.release()
			return nil, err
		}
	}
	return guard, nil
}

func (g *maintenanceGuard) acquire(cfg ServiceConfig) error {
	response, err := maintenanceCallVPNCore(cfg, Request{Action: "maintenance.drain"})
	if isUnavailable(err) {
		return nil // Provisional only: beforeBootout must probe again.
	}
	if err == nil && (!response.OK || response.Error != "" || !validMaintenanceToken(response.Token)) {
		err = errors.New("unexpected maintenance.drain response (valid token required)")
	}
	if err != nil {
		if strings.Contains(err.Error(), "unsupported vpn core action") {
			return fmt.Errorf("running daemon %s cannot confirm idleness: %w; stop the tunnels, then rerun with --allow-disruption to proceed", cfg.Label, err)
		}
		return fmt.Errorf("cannot drain vpn core %s: %w; stop the tunnels or rerun with --allow-disruption", cfg.Label, err)
	}
	g.leases[cfg.Label] = maintenanceLease{cfg: cfg, token: response.Token, until: installNowVPNCore().Add(maintenanceDrainTTL)}
	return nil
}

type maintenanceBootoutError struct{ error }

func (g *maintenanceGuard) beforeBootout(label string) error {
	if g.override {
		return nil
	}
	cfg, ok := g.configs[label]
	if !ok {
		return &maintenanceBootoutError{fmt.Errorf("no maintenance configuration for %s", label)}
	}
	if _, held := g.leases[label]; !held {
		if err := g.acquire(cfg); err != nil {
			return &maintenanceBootoutError{err}
		}
		if _, held := g.leases[label]; !held {
			return nil // Still unreachable at this final probe.
		}
	}
	lease := g.leases[label]
	response, err := maintenanceCallVPNCore(lease.cfg, Request{Action: "maintenance.renew", Token: lease.token})
	if err == nil && (!response.OK || response.Error != "" || response.Token != lease.token) {
		err = errors.New("unexpected maintenance.renew response")
	}
	if err != nil {
		return &maintenanceBootoutError{fmt.Errorf("cannot renew vpn core maintenance drain before bootout of %s: %w; retry", label, err)}
	}
	lease.until = installNowVPNCore().Add(maintenanceDrainTTL)
	g.leases[label] = lease
	// No privileged command may intervene before bootout. This bounded lease
	// lapses if launchctl bootout itself starts more than 60 seconds after renew.
	return nil
}

// Every bootstrap checks authenticated readiness and drain status. Only an
// installer holding ownership may release a lease restored by its replacement.
func (g *maintenanceGuard) releaseReplacement(cfg ServiceConfig) error {
	lease, held := g.leases[cfg.Label]
	deadline := installNowVPNCore().Add(maintenanceReadyTimeout)
	for {
		remaining := deadline.Sub(installNowVPNCore())
		if remaining <= 0 {
			return errors.New("installed daemon did not answer authenticated ping within 10s")
		}
		// The client bounds dial and response separately; their sum fits the
		// remaining readiness budget. No status or launchctl probe is needed.
		response, err := maintenancePingVPNCore(cfg, remaining/2)
		if err == nil && response.OK && response.Error == "" {
			break
		}
		if err == nil {
			err = errors.New("unexpected ping response")
		}
		remaining = deadline.Sub(installNowVPNCore())
		if remaining <= 0 {
			return fmt.Errorf("installed daemon did not answer authenticated ping within 10s: %w", err)
		}
		installSleepVPNCore(minDuration(100*time.Millisecond, remaining))
	}
	if held {
		response, err := maintenanceCallVPNCore(lease.cfg, Request{Action: "maintenance.undrain", Token: lease.token})
		if err == nil && (!response.OK || response.Error != "") {
			err = errors.New("unexpected maintenance.undrain response")
		}
		if err != nil {
			return fmt.Errorf("installed daemon refused maintenance.undrain: %w", err)
		}
		g.forgotten(cfg.Label)
	}
	response, err := maintenancePingVPNCore(cfg, maintenanceReadyTimeout/2)
	if err == nil && (!response.OK || response.Error != "" || response.MaintenanceDrain == nil) {
		err = errors.New("unexpected ping response (maintenance drain state required)")
	}
	if err != nil {
		return fmt.Errorf("installed daemon drain state could not be verified: %w", err)
	}
	if response.MaintenanceDrain.Active {
		expiry, err := time.Parse(time.RFC3339, response.MaintenanceDrain.ExpiresAt)
		if err != nil {
			return errors.New("installed daemon returned invalid maintenance drain expiry")
		}
		return &InstallMaintenanceError{Installed: true, DrainActive: true, ExpiresAt: expiry}
	}
	return nil
}

func (g *maintenanceGuard) forgotten(label string) { delete(g.leases, label) }

func (g *maintenanceGuard) release() {
	for _, lease := range g.leases {
		// A refused stale release is harmless and must preserve the original failure.
		_, _ = maintenanceCallVPNCore(lease.cfg, Request{Action: "maintenance.undrain", Token: lease.token})
	}
}

func maintenanceConfigs(cfg ServiceConfig) []ServiceConfig {
	configs := []ServiceConfig{cfg}
	for _, compat := range compatibilityServiceConfigsVPNCore(cfg) {
		configs = append(configs, compat.ServiceConfig)
	}
	return configs
}
