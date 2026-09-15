package gateway

import (
	"context"
	"io"
	"log"
	"sync"
	"time"

	ksv1 "github.com/aryanference/securedeck/gen/go/killswitch/v1"
)

// DenyList is an in-memory cache of suspended/terminated agent IDs, kept warm
// by a streaming subscription to the Kill Switch with a periodic full-sync
// fallback. It intentionally does NOT depend on the Kill Switch being
// reachable at request time: the gateway checks its local cache, never makes
// a live call to the Kill Switch on the hot path (SEC-10 — the Kill Switch's
// independence must not become a dependency that can be used to DoS the
// gateway by taking the Kill Switch down).
type DenyList struct {
	client ksv1.KillSwitchServiceClient

	mu           sync.RWMutex
	denied       map[string]ksv1.DenyStatus
	lastSyncedAt time.Time

	fullSyncInterval time.Duration
	staleWarnAfter   time.Duration
}

// NewDenyList constructs a DenyList. client may be nil (e.g. Kill Switch not
// yet deployed / reachable) — in that case the deny list simply stays empty
// and every agent is treated as not-denied by this check, which is correct:
// an unreachable Kill Switch must never cause the gateway to fail closed.
func NewDenyList(client ksv1.KillSwitchServiceClient) *DenyList {
	return &DenyList{
		client:           client,
		denied:           make(map[string]ksv1.DenyStatus),
		fullSyncInterval: 10 * time.Second,
		staleWarnAfter:   30 * time.Second,
	}
}

// IsDenied reports whether agentID is currently suspended or terminated.
func (d *DenyList) IsDenied(agentID string) (bool, ksv1.DenyStatus) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	status, ok := d.denied[agentID]
	if !ok {
		return false, ksv1.DenyStatus_DENY_STATUS_UNSPECIFIED
	}
	return true, status
}

// Start runs the initial sync, then the streaming subscription, with a
// periodic full-sync fallback in case updates are missed. It blocks until
// ctx is cancelled and is meant to be run in its own goroutine.
func (d *DenyList) Start(ctx context.Context) {
	if d.client == nil {
		log.Printf("gateway: no kill switch client configured, deny list will stay empty")
		return
	}

	d.fullSync(ctx)

	ticker := time.NewTicker(d.fullSyncInterval)
	defer ticker.Stop()

	go d.subscribe(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.fullSync(ctx)
		}
	}
}

func (d *DenyList) fullSync(ctx context.Context) {
	stream, err := d.client.GetDenyList(ctx, &ksv1.GetDenyListRequest{})
	if err != nil {
		d.warnIfStale()
		return
	}

	fresh := make(map[string]ksv1.DenyStatus)
	for {
		entry, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			d.warnIfStale()
			return
		}
		fresh[entry.AgentId] = entry.Status
	}

	d.mu.Lock()
	d.denied = fresh
	d.lastSyncedAt = time.Now()
	d.mu.Unlock()
}

func (d *DenyList) subscribe(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		stream, err := d.client.SubscribeDenyList(ctx, &ksv1.SubscribeDenyListRequest{})
		if err != nil {
			d.warnIfStale()
			time.Sleep(2 * time.Second)
			continue
		}

		for {
			update, err := stream.Recv()
			if err != nil {
				d.warnIfStale()
				break
			}
			if update.IsFullSyncMarker {
				continue
			}
			d.applyUpdate(update.Entry)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (d *DenyList) applyUpdate(entry *ksv1.DenyListEntry) {
	if entry == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry.Status == ksv1.DenyStatus_DENY_STATUS_UNSPECIFIED {
		delete(d.denied, entry.AgentId)
	} else {
		d.denied[entry.AgentId] = entry.Status
	}
	d.lastSyncedAt = time.Now()
}

// warnIfStale logs (but never blocks enforcement on) a deny list that hasn't
// synced successfully in over staleWarnAfter. The gateway continues serving
// requests against the last-known-good cache — see SEC-10 rationale above.
func (d *DenyList) warnIfStale() {
	d.mu.RLock()
	last := d.lastSyncedAt
	d.mu.RUnlock()

	if last.IsZero() || time.Since(last) > d.staleWarnAfter {
		log.Printf("gateway: kill switch unreachable for >%s, continuing with stale deny list", d.staleWarnAfter)
	}
}
