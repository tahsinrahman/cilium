// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// These tests run in a synctest bubble and coordinate on channels only: the
// scrub state mutex is not durably blocking.

type fakeCTMaps []*ctmap.Map

func (f fakeCTMaps) ActiveMaps() []*ctmap.Map { return f }

// newScrubGC returns a GC that was not built by newGC, with n fake maps.
func newScrubGC(t *testing.T, n int, mapGC mapGCFunc) *GC {
	ms := make(fakeCTMaps, n)
	for i := range ms {
		ms[i] = &ctmap.Map{}
	}
	gc := &GC{logger: hivetest.Logger(t), ctMaps: ms}
	gc.scrub.mapGC = mapGC
	return gc
}

func scrubIP(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}) }

// addrs returns the addresses of a batch in a stable order.
func addrs(batch map[ctmap.NetAddr]struct{}) []netip.Addr {
	out := make([]netip.Addr, 0, len(batch))
	for a := range batch {
		out = append(out, a.Addr)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// walk is a walk of one map that blocks until released. ips is a copy of what
// the walk was asked to match when it started.
type walk struct {
	removeExpired bool
	ips           []netip.Addr
	release       chan struct{}
}

// newGatedScrubGC returns a GC with one map whose walks are published on the
// returned channel and block until released.
func newGatedScrubGC(t *testing.T) (*GC, chan *walk) {
	walks := make(chan *walk, 16)
	return newScrubGC(t, 1, func(_ *ctmap.Map, f ctmap.GCFilter) (int, error) {
		w := &walk{removeExpired: f.RemoveExpired, ips: addrs(f.MatchIPs), release: make(chan struct{})}
		walks <- w
		<-w.release
		return 0, nil
	}), walks
}

func scrubAsync(ctx context.Context, gc *GC, errs chan<- error, ips ...netip.Addr) {
	go func() { errs <- gc.ScrubIPs(ctx, ips...) }()
}

func TestScrubCoalesces100Callers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gc, walks := newGatedScrubGC(t)
		errs := make(chan error, 100)

		scrubAsync(t.Context(), gc, errs, scrubIP(0))
		first := <-walks
		// 99 callers, asking for 50 distinct IPs, arrive during the walk.
		for i := 1; i < 100; i++ {
			scrubAsync(t.Context(), gc, errs, scrubIP(i%50+1))
		}
		synctest.Wait()
		require.Empty(t, errs, "a caller returned while the walk that did not serve it was running")

		close(first.release)
		second := <-walks
		synctest.Wait()
		require.Len(t, errs, 1, "callers returned before the walk that serves them finished")
		require.Equal(t, []netip.Addr{scrubIP(0)}, first.ips, "the first walk was given IPs requested during it")
		require.Len(t, second.ips, 50, "the repeated IPs are not one entry each")
		require.True(t, first.removeExpired)
		require.True(t, second.removeExpired)

		close(second.release)
		synctest.Wait()
		require.Len(t, errs, 100)
		for range 100 {
			require.NoError(t, <-errs)
		}
		require.Empty(t, walks, "more than two walks")
	})
}

// A request that arrives while the loop is exiting must not wait for a loop
// that is gone.
func TestScrubNoLostWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu lock.Mutex
		var walked [][]netip.Addr
		gc := newScrubGC(t, 1, func(_ *ctmap.Map, f ctmap.GCFilter) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			walked = append(walked, addrs(f.MatchIPs))
			return 0, nil
		})
		var once sync.Once
		var lateErr error
		gc.scrub.beforeExit = func() {
			once.Do(func() { lateErr = gc.ScrubIPs(t.Context(), scrubIP(2)) })
		}

		require.NoError(t, gc.ScrubIPs(t.Context(), scrubIP(1)))
		// The late request is made by the exiting loop goroutine, which the
		// bubble does not end before it returned.
		synctest.Wait()
		require.NoError(t, lateErr)
		require.Equal(t, [][]netip.Addr{{scrubIP(1)}, {scrubIP(2)}}, walked)
	})
}

func TestScrubAfterStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var walks int
		gc := newScrubGC(t, 1, func(*ctmap.Map, ctmap.GCFilter) (int, error) {
			walks++
			return 0, nil
		})
		gc.scrub.stop()

		require.ErrorIs(t, gc.ScrubIPs(t.Context(), scrubIP(1)), errScrubAborted)
		synctest.Wait()
		require.Zero(t, walks)
		require.False(t, gc.scrub.running)
	})
}

// Stop aborts the callers queued for the next walk at once. The walk that is
// running skips the remaining maps and aborts its callers.
func TestScrubStopBetweenMaps(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		var seen []*ctmap.Map
		gc := newScrubGC(t, 2, func(m *ctmap.Map, _ ctmap.GCFilter) (int, error) {
			seen = append(seen, m)
			close(started)
			<-release
			return 0, nil
		})
		errs := make(chan error, 2)

		scrubAsync(t.Context(), gc, errs, scrubIP(1))
		<-started
		scrubAsync(t.Context(), gc, errs, scrubIP(2))
		synctest.Wait()

		// The queued caller is released at once, without waiting for the walk.
		gc.scrub.stop()
		synctest.Wait()
		require.Len(t, errs, 1)
		require.ErrorIs(t, <-errs, errScrubAborted)

		// The walk that was running skips the second map and is aborted.
		close(release)
		synctest.Wait()
		require.Len(t, errs, 1)
		require.ErrorIs(t, <-errs, errScrubAborted)
		require.Len(t, seen, 1, "the walk went on to the second map")
		require.False(t, gc.scrub.running)
	})
}

// A caller whose context is done does not wait, and its IPs are not queued if
// it is done before the call. If it is done after, they are still scrubbed.
func TestScrubCtxCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gc, walks := newGatedScrubGC(t)
		errs := make(chan error, 1)

		scrubAsync(t.Context(), gc, errs, scrubIP(1))
		first := <-walks

		dead, cancel := context.WithCancel(t.Context())
		cancel()
		require.ErrorIs(t, gc.ScrubIPs(dead, scrubIP(2)), context.Canceled)
		require.Nil(t, gc.scrub.next, "a done caller was queued")

		ctx, cancel := context.WithCancel(t.Context())
		canceled := make(chan error, 1)
		scrubAsync(ctx, gc, canceled, scrubIP(3))
		synctest.Wait()
		cancel()
		synctest.Wait()
		require.ErrorIs(t, <-canceled, context.Canceled)

		close(first.release)
		second := <-walks
		require.Equal(t, []netip.Addr{scrubIP(3)}, second.ips)
		close(second.release)
		synctest.Wait()
		require.NoError(t, <-errs)
	})
}

func TestScrubBareGC(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var walks int
		gc := newScrubGC(t, 2, func(*ctmap.Map, ctmap.GCFilter) (int, error) {
			walks++
			return 1, nil
		})

		// Nothing to scrub.
		require.NoError(t, gc.ScrubIPs(t.Context()))
		synctest.Wait()
		require.Zero(t, walks)
		require.Nil(t, gc.scrub.next)

		require.NoError(t, gc.ScrubIPs(t.Context(), scrubIP(1)))
		require.Equal(t, 2, walks, "one walk per map")
		require.NoError(t, gc.ScrubIPs(t.Context(), scrubIP(1)))
		require.Equal(t, 4, walks, "the loop did not restart after it exited")
		synctest.Wait()
		require.False(t, gc.scrub.running)
		require.Empty(t, gc.scrub.pending)
	})
}
