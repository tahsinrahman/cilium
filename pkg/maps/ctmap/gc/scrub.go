// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/time"
)

// scrubTicket is shared by all the callers whose IPs are served by one walk.
type scrubTicket struct {
	// done is closed once the walk finished, err is written before that.
	done chan struct{}
	err  error
}

type mapGCFunc func(m *ctmap.Map, filter ctmap.GCFilter) (int, error)

// errScrubAborted is returned by ScrubIPs when the GC stopped before the
// scrub could complete.
var errScrubAborted = errors.New("conntrack scrub aborted")

// scrubState coalesces concurrent ScrubIPs calls: a single loop walks the CT
// maps for all the IPs requested since its previous walk started. A walk
// started before a request was added never serves it, as the entries it
// already passed could have been created for the previous owner of the IP.
// The zero value is ready to use, next and pending are created by ScrubIPs.
type scrubState struct {
	mu lock.Mutex
	// next is the ticket of the walk that will serve pending, nil if nothing
	// is pending.
	next    *scrubTicket
	pending map[ctmap.NetAddr]struct{}
	// running is set while the loop goroutine exists, and is only cleared in
	// the critical section that found nothing left to do.
	running bool
	// stopped is set by stop, see there.
	stopped bool

	// Test hooks.
	mapGC      mapGCFunc
	beforeExit func()
}

// stop makes the loop, and the scrubs queued or requested from now on, fail
// with errScrubAborted. It is called before OnStop waits for the loop, so that
// no loop is started afterwards, and the running one, which is checked before
// each map, does not start another walk.
func (s *scrubState) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.next != nil {
		s.next.err = errScrubAborted
		close(s.next.done)
		s.next, s.pending = nil, nil
	}
}

// ScrubIPs implements ctmap.GCRunner. Invalid addresses are not filtered out,
// callers pass valid ones.
func (gc *GC) ScrubIPs(ctx context.Context, addrs ...netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s := &gc.scrub
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return errScrubAborted
	}
	if s.next == nil {
		s.next = &scrubTicket{done: make(chan struct{})}
		s.pending = make(map[ctmap.NetAddr]struct{}, len(addrs))
	}
	for _, a := range addrs {
		s.pending[ctmap.NetAddr{Addr: a}] = struct{}{}
	}
	ticket := s.next
	if !s.running {
		s.running = true
		// stop sets stopped under mu before OnStop's gcWG.Wait(), so this Go
		// cannot race with that Wait.
		gc.gcWG.Go(gc.scrubLoop)
	}
	s.mu.Unlock()

	// When ctx is done first the IPs stay pending: they are scrubbed anyway.
	select {
	case <-ticket.done:
		return ticket.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// scrubLoop walks the CT maps for the pending IPs until there are none left.
// It holds no CT lock between walks, so the periodic GC, which takes the same
// per-map locks, waits for at most one scrub walk of one map: a sync.Mutex
// waiter blocked for over 1ms is handed the lock directly on unlock.
func (gc *GC) scrubLoop() {
	s := &gc.scrub
	for {
		s.mu.Lock()
		if s.next == nil {
			// Same critical section as the emptiness check, otherwise a
			// request added in between would wait for a loop that is exiting.
			s.running = false
			s.mu.Unlock()
			if s.beforeExit != nil {
				s.beforeExit()
			}
			return
		}
		batch, ticket := s.pending, s.next
		s.next, s.pending = nil, nil
		s.mu.Unlock()

		start := time.Now()
		deleted, stopped := gc.scrubMaps(batch)
		if stopped {
			ticket.err = errScrubAborted
		} else {
			took := time.Since(start)
			level := slog.LevelDebug
			if took > time.Second {
				level = slog.LevelInfo
			}
			gc.logger.Log(context.Background(), level, "Scrubbed conntrack entries of endpoint IPs",
				logfields.Count, len(batch),
				logfields.Duration, took,
				logfields.Deleted, deleted,
			)
		}
		close(ticket.done)
	}
}

// scrubMaps removes the entries of the batch's IPs, and the expired ones as
// the walk visits them anyway, from every active global CT map. It reports
// whether it stopped early because of OnStop, which is checked before each map
// as the maps are closed once OnStop returns.
func (gc *GC) scrubMaps(batch map[ctmap.NetAddr]struct{}) (deleted int, stopped bool) {
	filter := ctmap.GCFilter{RemoveExpired: true, MatchIPs: batch}
	for _, m := range gc.ctMaps.ActiveMaps() {
		gc.scrub.mu.Lock()
		stopped = gc.scrub.stopped
		gc.scrub.mu.Unlock()
		if stopped {
			break
		}

		var n int
		var err error
		if gc.scrub.mapGC != nil {
			n, err = gc.scrub.mapGC(m, filter)
		} else {
			n, err = m.GC(filter, gc.next4, gc.next6)
		}
		if err != nil {
			gc.logger.Error("Failed to scrub conntrack entries",
				logfields.BPFMapName, m.Name(),
				logfields.Error, err,
			)
		}
		deleted += n
	}
	return deleted, stopped
}
