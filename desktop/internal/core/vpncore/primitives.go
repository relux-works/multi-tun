package vpncore

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

type ProcEnsureRequest struct {
	Slot        string                   `json:"slot,omitempty"`
	Kind        string                   `json:"kind"`
	ConfigJSON  []byte                   `json:"config_json,omitempty"`
	OpenConnect *OpenConnectStartRequest `json:"openconnect,omitempty"`
	LogMaxLines int                      `json:"log_max_lines,omitempty"`
	SetPGID     bool                     `json:"setpgid,omitempty"`
	Replace     bool                     `json:"replace,omitempty"`
	Interface   string                   `json:"interface,omitempty"`
	Filter      []string                 `json:"filter,omitempty"`
	ApplePCAPNG bool                     `json:"apple_pcapng,omitempty"`
	RunAsUser   bool                     `json:"run_as_user,omitempty"`
}

type ProcEnsureResult struct {
	PID     int    `json:"pid"`
	Handle  string `json:"handle"`
	Slot    string `json:"slot,omitempty"`
	Kind    string `json:"kind"`
	Running bool   `json:"running"`
	Path    string `json:"path,omitempty"`
}

type ProcStopRequest struct {
	Handle string `json:"handle,omitempty"`
	Slot   string `json:"slot,omitempty"`
	Signal string `json:"signal,omitempty"`
}

type ProcStopResult struct {
	Path    string `json:"path,omitempty"`
	Stopped bool   `json:"stopped"`
}

type ProcStatusRequest struct {
	Slot   string `json:"slot,omitempty"`
	Handle string `json:"handle,omitempty"`
}

// ManagedProcessInfo deliberately contains no opaque handle.
type ManagedProcessInfo struct {
	Slot      string    `json:"slot,omitempty"`
	Kind      string    `json:"kind"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Running   bool      `json:"running"`
}

type NetDNSRequest struct {
	Op      string   `json:"op"`
	Stdin   string   `json:"stdin,omitempty"`
	Service string   `json:"service,omitempty"`
	Servers []string `json:"servers,omitempty"`
}

type PFAnchorRequest struct {
	Op         string             `json:"op"`
	FailClosed *FailClosedRequest `json:"fail_closed,omitempty"`
}

var slotPatternVPNCore = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,64}$`)
var handlePatternVPNCore = regexp.MustCompile(`^[0-9a-f]{48}$`)

func validateProcessFilter(slot, handle string) error {
	if slot != "" && !slotPatternVPNCore.MatchString(slot) {
		return errors.New("invalid process slot")
	}
	if handle != "" && !handlePatternVPNCore.MatchString(handle) {
		return errors.New("handle must be 48 lowercase hexadecimal characters")
	}
	return nil
}

func validateProcEnsure(req ProcEnsureRequest) error {
	if err := validateProcessFilter(req.Slot, ""); err != nil {
		return err
	}
	if req.LogMaxLines < 0 || req.LogMaxLines > 1_000_000 {
		return errors.New("log_max_lines is outside 0..1000000")
	}
	captureFields := req.Interface != "" || len(req.Filter) != 0 || req.ApplePCAPNG || req.RunAsUser
	switch req.Kind {
	case "sing-box":
		if req.OpenConnect != nil || captureFields {
			return errors.New("sing-box contains fields outside its typed schema")
		}
		return ValidateSingBoxConfig(req.ConfigJSON)
	case "openconnect":
		if req.OpenConnect == nil || len(req.ConfigJSON) != 0 || captureFields {
			return errors.New("openconnect requires only typed openconnect options")
		}
	case "tcpdump":
		if req.OpenConnect != nil || len(req.ConfigJSON) != 0 || req.LogMaxLines != 0 {
			return errors.New("tcpdump contains fields outside its typed schema")
		}
		if !req.RunAsUser {
			return errors.New("tcpdump requires run_as_user=true")
		}
		_, err := buildTCPDumpCommand(req.Interface, req.Filter, req.ApplePCAPNG, "", "/capture.pcap")
		return err
	default:
		return errors.New("unsupported managed process kind")
	}
	return nil
}

func validateNetDNS(req NetDNSRequest) error {
	switch req.Op {
	case "scutil":
		if req.Service != "" || len(req.Servers) != 0 {
			return errors.New("scutil contains unexpected fields")
		}
		return validateSCUtilInput(req.Stdin)
	case "networksetup":
		if req.Stdin != "" || len(req.Service) > 256 || len(req.Servers) > 64 {
			return errors.New("networksetup contains unexpected or oversized fields")
		}
		if req.Service == "" || strings.IndexFunc(req.Service, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return errors.New("invalid network service")
		}
		if !(len(req.Servers) == 1 && req.Servers[0] == "Empty") && !allIPs(req.Servers, false) {
			return errors.New("invalid DNS servers")
		}
	case "resolver_cleanup":
		if req.Stdin != "" || req.Service != "" || len(req.Servers) != 0 {
			return errors.New("resolver_cleanup contains unexpected fields")
		}
	default:
		return errors.New("unsupported net.dns operation")
	}
	return nil
}

func (d *serviceDaemon) handleNetDNS(req NetDNSRequest) error {
	if err := validateNetDNS(req); err != nil {
		return err
	}
	switch req.Op {
	case "scutil":
		return d.handleSCUtil(Request{Stdin: req.Stdin})
	case "networksetup":
		return d.handleNetworkSetup(Request{Service: req.Service, Servers: req.Servers})
	default:
		return d.handleResolverCleanup()
	}
}

func (d *serviceDaemon) handleProcEnsure(req ProcEnsureRequest, logFile *os.File) (ProcEnsureResult, error) {
	// Ownership transfers to the child only on successful start. All refusals and
	// idempotent reuse close the received descriptor here.
	ownsLog := logFile != nil
	defer func() {
		if ownsLog {
			_ = logFile.Close()
		}
	}()
	if err := validateProcEnsure(req); err != nil {
		return ProcEnsureResult{}, err
	}
	if req.Kind != "tcpdump" && logFile == nil {
		return ProcEnsureResult{}, errors.New("process requires a log file descriptor")
	}
	if req.Kind == "tcpdump" && logFile != nil {
		return ProcEnsureResult{}, errors.New("tcpdump does not accept a log file descriptor")
	}
	oldHandle, old, exists := d.children.bySlot(req.Slot)
	if exists && old.kind != req.Kind && !req.Replace {
		return ProcEnsureResult{}, errors.New("process slot kind mismatch")
	}
	if exists && !req.Replace {
		return ProcEnsureResult{PID: old.pid, Handle: oldHandle, Slot: req.Slot, Kind: old.kind, Running: true, Path: old.resultPath}, nil
	}
	legacy := Request{Action: "singbox.start", ConfigJSON: req.ConfigJSON, OpenConnect: req.OpenConnect, LogMaxLines: req.LogMaxLines, SetPGID: req.SetPGID, Interface: req.Interface, Filter: req.Filter, ApplePCAPNG: req.ApplePCAPNG, RunAsUser: req.RunAsUser}
	// Prepare and check everything that can refuse the new configuration before
	// stopping the old child. A staged sing-box config is reused for launch.
	var dir, configPath string
	if exists && req.Replace {
		switch req.Kind {
		case "sing-box":
			var err error
			dir, configPath, err = d.prepareSingBox(req.ConfigJSON)
			if err != nil {
				return ProcEnsureResult{}, err
			}
			defer func() {
				if dir != "" {
					_ = os.RemoveAll(dir)
				}
			}()
		case "openconnect":
			if err := validateOpenConnectStart(*req.OpenConnect, d.clientUID); err != nil {
				return ProcEnsureResult{}, err
			}
			binary, err := openConnectBinaryVPNCore()
			if err != nil {
				return ProcEnsureResult{}, errors.New("trusted openconnect binary is unavailable")
			}
			owner, ownerErr := openConnectHomebrewUIDVPNCore(binary)
			if ownerErr != nil {
				owner = 0
			}
			if err := noSymlinksOpenConnect(binary, false); err != nil {
				return ProcEnsureResult{}, err
			}
			if err := validateOpenConnectExecutable(binary, owner, true); err != nil {
				return ProcEnsureResult{}, err
			}
		case "tcpdump":
			if _, err := lookupUserVPNCore(fmt.Sprint(d.clientUID)); err != nil {
				return ProcEnsureResult{}, errors.New("client identity is unavailable")
			}
		}
		if _, err := d.children.signal(oldHandle, syscall.SIGTERM); err != nil {
			if _, stillTracked := d.children.get(oldHandle); stillTracked && !errors.Is(err, syscall.ESRCH) {
				return ProcEnsureResult{}, err
			}
		}
		if err := d.children.waitStopped(oldHandle); err != nil {
			return ProcEnsureResult{}, err
		}
	}
	var pid int
	var handle string
	var err error
	switch req.Kind {
	case "sing-box":
		if dir != "" {
			pid, handle, err = d.startPreparedSingBox(legacy, logFile, dir, configPath, req.Slot)
		} else if req.Slot != "" {
			var prepDir, prepPath string
			prepDir, prepPath, err = d.prepareSingBox(req.ConfigJSON)
			if err == nil {
				pid, handle, err = d.startPreparedSingBox(legacy, logFile, prepDir, prepPath, req.Slot)
			}
		} else {
			pid, handle, err = d.startSingBox(legacy, logFile)
		}
	case "openconnect":
		pid, handle, err = d.startOpenConnect(legacy, logFile, req.SetPGID, req.Slot)
	case "tcpdump":
		pid, handle, err = d.startTCPDumpWithSlot(legacy, req.Slot)
	}
	if err != nil {
		return ProcEnsureResult{}, err
	}
	ownsLog = false
	dir = "" // Child cleanup now owns the staged directory.
	d.children.mu.Lock()
	child, present := d.children.children[handle]
	if present && req.Slot != "" && child.slot == "" {
		child.slot = req.Slot
		d.children.children[handle] = child
	}
	d.children.mu.Unlock()
	return ProcEnsureResult{PID: pid, Handle: handle, Slot: req.Slot, Kind: req.Kind, Running: present, Path: child.resultPath}, nil
}

func (r *childRegistry) bySlot(slot string) (string, childRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if slot != "" {
		for handle, child := range r.children {
			if child.slot == slot {
				return handle, child, true
			}
		}
	}
	return "", childRecord{}, false
}

func (r *childRegistry) waitStopped(handle string) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, ok := r.get(handle); !ok {
			return nil
		}
		select {
		case <-deadline.C:
			return errors.New("timed out waiting for replaced process to exit")
		case <-tick.C:
		}
	}
}

func (d *serviceDaemon) handleProcStop(req ProcStopRequest) (ProcStopResult, error) {
	if err := validateProcessFilter(req.Slot, req.Handle); err != nil {
		return ProcStopResult{}, err
	}
	if (req.Slot == "") == (req.Handle == "") {
		return ProcStopResult{}, errors.New("exactly one of handle or slot is required")
	}
	if req.Signal == "" {
		req.Signal = "-TERM"
	}
	sig, err := parseSignal(req.Signal)
	if err != nil {
		return ProcStopResult{}, err
	}
	if req.Slot != "" {
		handle, _, ok := d.children.bySlot(req.Slot)
		if !ok {
			return ProcStopResult{}, errors.New("process slot not found")
		}
		req.Handle = handle
	}
	path, err := d.children.signal(req.Handle, sig)
	return ProcStopResult{Path: path, Stopped: err == nil}, err
}

func (r *childRegistry) status(req ProcStatusRequest) []ManagedProcessInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]ManagedProcessInfo, 0, len(r.children))
	for handle, child := range r.children {
		if req.Slot != "" && child.slot != req.Slot || req.Handle != "" && handle != req.Handle {
			continue
		}
		result = append(result, ManagedProcessInfo{Slot: child.slot, Kind: child.kind, PID: child.pid, StartedAt: child.startedAt, Running: true})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Slot != result[j].Slot {
			return result[i].Slot < result[j].Slot
		}
		return result[i].PID < result[j].PID
	})
	return result
}

// Only an explicit unknown action/field refusal proves an old helper performed
// no effects. Transport errors and timeouts must never trigger a retry.
func olderDaemonRefusal(err error) bool {
	var refused *RefusedError
	return errors.As(err, &refused) && (strings.Contains(refused.Message, "unsupported vpn core action") || strings.Contains(refused.Message, "json: unknown field"))
}

func callPrimitiveOrLegacy(cfg ServiceConfig, primitive, legacy Request, logFile *os.File) (Response, error) {
	response, err := callActiveWithLog(cfg, primitive, logFile)
	if olderDaemonRefusal(err) {
		return callActiveWithLog(cfg, legacy, logFile)
	}
	return response, err
}

func EnsureProcess(cfg ServiceConfig, req ProcEnsureRequest, logPath string) (ProcEnsureResult, error) {
	var file *os.File
	if req.Kind == "sing-box" || req.Kind == "openconnect" {
		var err error
		file, err = openClientLog(logPath)
		if err != nil {
			return ProcEnsureResult{}, err
		}
		defer file.Close()
	}
	response, err := callActiveWithLog(cfg, Request{Action: "proc.ensure", ProcEnsure: &req}, file)
	if err != nil {
		return ProcEnsureResult{}, err
	}
	if response.PID <= 0 || response.Handle == "" {
		return ProcEnsureResult{}, errors.New("vpn core did not return child pid and handle")
	}
	return ProcEnsureResult{PID: response.PID, Handle: response.Handle, Slot: response.Slot, Kind: response.Kind, Running: response.Running, Path: response.Path}, nil
}

func StopProcess(cfg ServiceConfig, req ProcStopRequest) (ProcStopResult, error) {
	response, err := callActive(cfg, Request{Action: "proc.stop", ProcStop: &req})
	return ProcStopResult{Path: response.Path, Stopped: response.Stopped}, err
}

func QueryProcessStatus(cfg ServiceConfig, req ProcStatusRequest) ([]ManagedProcessInfo, error) {
	response, err := callActive(cfg, Request{Action: "proc.status", ProcStatus: &req})
	return response.Processes, err
}

func ApplyNetDNS(cfg ServiceConfig, req NetDNSRequest) error {
	_, err := callActive(cfg, Request{Action: "net.dns", NetDNS: &req})
	return err
}

func ApplyNetRoute(cfg ServiceConfig, req NetRouteRequest) error {
	_, err := callActive(cfg, Request{Action: "net.route", NetRoute: &req})
	return err
}

func ApplyPFAnchor(cfg ServiceConfig, interfaces, table []string) error {
	_, err := callActive(cfg, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "apply", FailClosed: &FailClosedRequest{Interfaces: append([]string(nil), interfaces...), Table: append([]string(nil), table...)}}})
	return err
}

func ClearPFAnchor(cfg ServiceConfig) error {
	_, err := callActive(cfg, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "clear"}})
	return err
}

func QueryPFAnchorStatus(cfg ServiceConfig) (FailClosedStatus, error) {
	response, err := callActive(cfg, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status"}})
	if err != nil {
		return FailClosedStatus{}, err
	}
	if response.FailClosed == nil {
		return FailClosedStatus{}, errors.New("vpn core did not return fail-closed status")
	}
	return *response.FailClosed, nil
}

func QueryBinPins(cfg ServiceConfig, verify bool) ([]PinnedBinaryStatus, error) {
	op := "status"
	if verify {
		op = "verify"
	}
	response, err := callActive(cfg, Request{Action: "bin.pin", BinPin: &BinPinRequest{Op: op}})
	return response.PinnedBins, err
}

func primitiveAction(action string) bool {
	switch action {
	case "proc.ensure", "proc.stop", "proc.status", "net.dns", "net.route", "pf.anchor", "bin.pin":
		return true
	}
	return false
}

func requestMutates(req Request) bool {
	switch req.Action {
	case "ping", "failclosed.status", "proc.status", "bin.pin":
		return false
	case "pf.anchor":
		return req.PFAnchor == nil || req.PFAnchor.Op != "status"
	}
	return true
}

func validatePrimitiveShape(req Request) error {
	// Strip only this action's payload. The remaining outer request must have
	// exactly the empty ping shape, including no other primitive payload.
	outer := req
	outer.Action = "ping"
	switch req.Action {
	case "proc.ensure":
		outer.ProcEnsure = nil
	case "proc.stop":
		outer.ProcStop = nil
	case "proc.status":
		outer.ProcStatus = nil
	case "net.dns":
		outer.NetDNS = nil
	case "net.route":
		outer.NetRoute = nil
	case "pf.anchor":
		outer.PFAnchor = nil
	case "bin.pin":
		outer.BinPin = nil
	}
	if err := validateRequestShape(outer); err != nil {
		return err
	}
	switch req.Action {
	case "proc.ensure":
		if req.ProcEnsure == nil {
			return errors.New("proc.ensure requires proc_ensure")
		}
		return validateProcEnsure(*req.ProcEnsure)
	case "proc.stop":
		if req.ProcStop == nil {
			return errors.New("proc.stop requires proc_stop")
		}
		r := req.ProcStop
		if (r.Handle == "") == (r.Slot == "") {
			return errors.New("exactly one of handle or slot is required")
		}
		if err := validateProcessFilter(r.Slot, r.Handle); err != nil {
			return err
		}
		if r.Signal != "" {
			_, err := parseSignal(r.Signal)
			return err
		}
	case "proc.status":
		if req.ProcStatus != nil {
			return validateProcessFilter(req.ProcStatus.Slot, req.ProcStatus.Handle)
		}
	case "net.dns":
		if req.NetDNS == nil {
			return errors.New("net.dns requires net_dns")
		}
		return validateNetDNS(*req.NetDNS)
	case "net.route":
		if req.NetRoute == nil {
			return errors.New("net.route requires net_route")
		}
		_, err := netRouteArgs(*req.NetRoute)
		return err
	case "pf.anchor":
		if req.PFAnchor == nil {
			return errors.New("pf.anchor requires pf_anchor")
		}
		r := req.PFAnchor
		switch r.Op {
		case "apply":
			return validateRequestShape(Request{Action: "failclosed.apply", FailClosed: r.FailClosed})
		case "clear", "status":
			if r.FailClosed != nil {
				return errors.New("pf.anchor clear/status forbids fail_closed")
			}
		default:
			return errors.New("unsupported pf.anchor operation")
		}
	case "bin.pin":
		if req.BinPin != nil && req.BinPin.Op != "" && req.BinPin.Op != "status" && req.BinPin.Op != "verify" {
			return errors.New("unsupported bin.pin operation")
		}
	}
	return nil
}

// Legacy actions are decoded against their original closed schemas, then use
// exactly the same handlers as the thin protocol. Diagnostics retain the action
// the caller sent. No legacy action gains additional request fields.
func primitiveRequest(req Request) Request {
	switch req.Action {
	case "singbox.start":
		return Request{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", ConfigJSON: req.ConfigJSON, LogMaxLines: req.LogMaxLines, SetPGID: req.SetPGID}}
	case "openconnect.start":
		return Request{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "openconnect", OpenConnect: req.OpenConnect, SetPGID: true}}
	case "tcpdump.start":
		return Request{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "tcpdump", Interface: req.Interface, Filter: req.Filter, ApplePCAPNG: req.ApplePCAPNG, RunAsUser: req.RunAsUser}}
	case "signal":
		return Request{Action: "proc.stop", ProcStop: &ProcStopRequest{Handle: req.Handle, Signal: req.Signal}}
	case "dns.scutil":
		return Request{Action: "net.dns", NetDNS: &NetDNSRequest{Op: "scutil", Stdin: req.Stdin}}
	case "dns.networksetup":
		return Request{Action: "net.dns", NetDNS: &NetDNSRequest{Op: "networksetup", Service: req.Service, Servers: req.Servers}}
	case "resolver.cleanup":
		return Request{Action: "net.dns", NetDNS: &NetDNSRequest{Op: "resolver_cleanup"}}
	case "failclosed.apply":
		return Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "apply", FailClosed: req.FailClosed}}
	case "failclosed.clear":
		return Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "clear"}}
	case "failclosed.status":
		return Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status"}}
	}
	return req
}
