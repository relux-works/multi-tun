package vpncore

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	requestOutcomeOK    = "ok"
	requestOutcomeError = "error"
)

type trackedRequest struct {
	id      uint64
	action  string
	started time.Time
}

type completedTrackedRequest struct {
	action    string
	outcome   string
	duration  time.Duration
	completed time.Time
}

type requestTracker struct {
	mu            sync.Mutex
	nextID        uint64
	queued        map[uint64]trackedRequest
	active        map[uint64]trackedRequest
	lastCompleted *completedTrackedRequest
}

func newRequestTracker() *requestTracker {
	return &requestTracker{
		queued: make(map[uint64]trackedRequest),
		active: make(map[uint64]trackedRequest),
	}
}

func (t *requestTracker) enqueue() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.nextID++
	id := t.nextID
	t.queued[id] = trackedRequest{id: id, action: "pending", started: time.Now()}
	return id
}

func (t *requestTracker) begin(id uint64, action string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.queued, id)
	action = safeRequestAction(action)
	if action == "ping" {
		return
	}
	t.active[id] = trackedRequest{id: id, action: action, started: time.Now()}
}

func (t *requestTracker) abandon(id uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.queued, id)
}

func (t *requestTracker) complete(id uint64, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	request, found := t.active[id]
	if !found {
		return
	}
	delete(t.active, id)
	now := time.Now()
	outcome := requestOutcomeError
	if ok {
		outcome = requestOutcomeOK
	}
	t.lastCompleted = &completedTrackedRequest{
		action:    request.action,
		outcome:   outcome,
		duration:  now.Sub(request.started),
		completed: now,
	}
}

func (t *requestTracker) snapshot() *HelperSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	result := &HelperSnapshot{
		ActiveRequests: requestSnapshots(t.active, now),
		QueuedRequests: requestSnapshots(t.queued, now),
	}
	if t.lastCompleted != nil {
		result.LastCompletedRequest = &CompletedRequestSnapshot{
			Action:         safeRequestAction(t.lastCompleted.action),
			Outcome:        safeRequestOutcome(t.lastCompleted.outcome),
			DurationMillis: durationMillis(t.lastCompleted.duration),
			AgeMillis:      durationMillis(now.Sub(t.lastCompleted.completed)),
		}
	}
	return result
}

func requestSnapshots(requests map[uint64]trackedRequest, now time.Time) []RequestSnapshot {
	ordered := make([]trackedRequest, 0, len(requests))
	for _, request := range requests {
		ordered = append(ordered, request)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].id < ordered[j].id
	})

	result := make([]RequestSnapshot, 0, len(ordered))
	for _, request := range ordered {
		result = append(result, RequestSnapshot{
			Action:    safeRequestAction(request.action),
			AgeMillis: durationMillis(now.Sub(request.started)),
		})
	}
	return result
}

func durationMillis(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	return value.Milliseconds()
}

func safeRequestAction(action string) string {
	switch strings.TrimSpace(action) {
	case "ping", "run", "spawn", "signal", "pending", "other":
		return strings.TrimSpace(action)
	default:
		return "other"
	}
}

func safeRequestOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case requestOutcomeOK, requestOutcomeError:
		return strings.TrimSpace(outcome)
	default:
		return "unknown"
	}
}

// FormatRequestSnapshots renders active or queued request metadata without
// trusting action strings received over the helper socket.
func FormatRequestSnapshots(requests []RequestSnapshot) string {
	if len(requests) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(requests))
	for _, request := range requests {
		parts = append(parts, fmt.Sprintf(
			"%s(age=%dms)",
			safeRequestAction(request.Action),
			maxInt64(request.AgeMillis, 0),
		))
	}
	return strings.Join(parts, ",")
}

// FormatCompletedRequestSnapshot renders the last-completed request metadata.
func FormatCompletedRequestSnapshot(request *CompletedRequestSnapshot) string {
	if request == nil {
		return "none"
	}
	return fmt.Sprintf(
		"%s(outcome=%s,duration=%dms,age=%dms)",
		safeRequestAction(request.Action),
		safeRequestOutcome(request.Outcome),
		maxInt64(request.DurationMillis, 0),
		maxInt64(request.AgeMillis, 0),
	)
}

// FormatHelperSnapshot renders the complete redacted helper request summary.
func FormatHelperSnapshot(snapshot *HelperSnapshot) string {
	if snapshot == nil {
		return "unavailable"
	}
	return fmt.Sprintf(
		"active_requests=%s queued_requests=%s last_completed_request=%s",
		FormatRequestSnapshots(snapshot.ActiveRequests),
		FormatRequestSnapshots(snapshot.QueuedRequests),
		FormatCompletedRequestSnapshot(snapshot.LastCompletedRequest),
	)
}

func formatTimeoutServiceStatus(status *ServiceStatus) string {
	if status == nil {
		return "state=unavailable"
	}
	if !status.Reachable {
		return "state=missing"
	}
	return fmt.Sprintf(
		"state=reachable daemon_pid=%d %s",
		status.DaemonPID,
		FormatHelperSnapshot(status.HelperSnapshot),
	)
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
