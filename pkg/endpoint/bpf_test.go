// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	fakeloader "github.com/cilium/cilium/pkg/datapath/loader/fake"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
)

// newRegenTestEndpoint returns an endpoint that regenerateBPF can run on up to
// the point where it needs a policy map.
func newRegenTestEndpoint(t *testing.T, repo *policy.Repository, endpointPolicy *policy.EndpointPolicy) *Endpoint {
	ep := &Endpoint{
		aliveCtx:                   t.Context(),
		orchestrator:               &fakeendpoint.FakeOrchestrator{},
		compilationLock:            &lock.RWMutex{},
		policyRepo:                 repo,
		dnsRulesAPI:                noopDNSRulesAPI{},
		desiredPolicy:              endpointPolicy,
		realizedPolicy:             endpointPolicy,
		initialEnvoyPolicyComputed: make(chan struct{}),
		ctScrubDone:                ctScrubSkipped,
	}
	ep.logger.Store(hivetest.Logger(t))
	return ep
}

func TestRegenerateBPFFailureReverts(t *testing.T) {
	endpointPolicy := &policy.EndpointPolicy{}
	ep := newRegenTestEndpoint(t, &policy.Repository{}, endpointPolicy)
	datapath := &datapathRegenerationContext{
		policyResult: &policyGenerateResult{endpointPolicy: endpointPolicy},
	}
	var reverted bool
	datapath.revertibles.AddRevert(func() error {
		reverted = true
		return nil
	})

	ep.buildMutex.Lock()
	defer ep.buildMutex.Unlock()
	_, err := ep.regenerateBPF(&regenerationContext{
		parentContext:               t.Context(),
		datapathRegenerationContext: datapath,
	})
	require.ErrorContains(t, err, "endpoint has nil policyMapFactory")
	require.True(t, reverted)
}

// An endpoint's first regeneration reuses the policy that ComputeInitialPolicy
// computed, unless the endpoint's identity or the policy changed in between.
func TestFirstRegenerationComputesPolicyOnce(t *testing.T) {
	f := newPolicyTestFixture(t)
	otherID := identity.NewIdentity(f.podID.ID+1, labels.Labels{"other": labels.NewLabel("k8s:other", "", "")})
	f.idManager.Add(otherID)

	for _, tc := range []struct {
		name       string
		change     func(t *testing.T, ep *Endpoint)
		recomputed bool
	}{
		{"unchanged", func(*testing.T, *Endpoint) {}, false},
		{"policy changed", func(t *testing.T, ep *Endpoint) {
			_, err := f.polComputer.RecomputeIdentityPolicyForAllIdentities(f.repo.BumpRevision())
			require.NoError(t, err)
		}, true},
		{"labels changed", func(_ *testing.T, ep *Endpoint) {
			ep.identityRevision++
		}, true},
		{"identity changed", func(t *testing.T, ep *Endpoint) {
			ep.SecurityIdentity = otherID
			computePolicyForEPAndWait(t, ep, f.polComputer, f.repo.GetRevision())
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := newRegenTestEndpoint(t, f.repo, policy.NewEndpointPolicy(hivetest.Logger(t), f.repo))
			ep.policyFetcher = f.polComputer
			ep.SecurityIdentity = f.podID
			ep.Options = option.NewIntOptions(&EndpointMutableOptionLibrary)
			computePolicyForEPAndWait(t, ep, f.polComputer, f.repo.GetRevision())

			regenCtx := &regenerationContext{
				parentContext:               t.Context(),
				datapathRegenerationContext: &datapathRegenerationContext{},
			}
			err, release := ep.ComputeInitialPolicy(regenCtx)
			require.NoError(t, err)
			defer release()
			require.NotNil(t, regenCtx.datapathRegenerationContext.policyResult, "initial policy was not computed")

			tc.change(t, ep)

			// runPreCompilationSteps times the policy calculation only when it
			// does not reuse the initial result.
			regenCtx.Stats = regenerationStatistics{}
			func() {
				ep.buildMutex.Lock()
				defer ep.buildMutex.Unlock()
				_, err = ep.regenerateBPF(regenCtx)
			}()
			// The regeneration gets past the policy step and fails once it
			// needs a policy map.
			require.ErrorContains(t, err, "endpoint has nil policyMapFactory")
			require.Equal(t, tc.recomputed, regenCtx.Stats.policyCalculation.Total() > 0)
		})
	}
}

type recordingGCRunner struct {
	ctmap.GCRunner
	filter ctmap.GCFilter
}

func (r *recordingGCRunner) Run(filter ctmap.GCFilter) (int, error) {
	r.filter = filter
	return 0, nil
}

func TestScrubIPsInConntrackTableFilter(t *testing.T) {
	gc := &recordingGCRunner{GCRunner: ctmap.NewFakeGCRunner()}
	ep := &Endpoint{
		ctMapGC: gc,
		IPv4:    netip.MustParseAddr("10.0.0.1"),
		IPv6:    netip.MustParseAddr("fd00::1"),
	}

	ep.scrubIPsInConntrackTable(ep.ctScrubIPsLocked())

	require.Equal(t, ctmap.GCFilter{
		RemoveExpired: true,
		MatchIPs: map[ctmap.NetAddr]struct{}{
			{Addr: ep.IPv4}: {},
			{Addr: ep.IPv6}: {},
		},
	}, gc.filter)
}

// recvOrFail receives from ch, failing the test if nothing arrives in time.
func recvOrFail[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// requireQuiet checks that nothing arrives on ch for a short while.
func requireQuiet[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected %s", what)
	case <-time.After(100 * time.Millisecond):
	}
}

// requireMutexFree checks that the endpoint mutex can be taken. It cannot use
// TryLock, which lockdebug mutexes lack. The goroutine only leaks when the
// test is already failing.
func requireMutexFree(t *testing.T, e *Endpoint) {
	t.Helper()
	locked := make(chan struct{})
	go func() {
		e.unconditionalLock()
		e.unlock()
		close(locked)
	}()
	recvOrFail(t, locked, "the endpoint mutex")
}

// gatedGCRunner blocks every Run until the test closes the gate that the Run
// published on runs, so that each walk is controlled independently. All walks
// are released when the test ends.
type gatedGCRunner struct {
	ctmap.GCRunner
	ctx  context.Context
	runs chan chan struct{}
}

func newGatedGCRunner(t *testing.T) *gatedGCRunner {
	return &gatedGCRunner{
		GCRunner: ctmap.NewFakeGCRunner(),
		ctx:      t.Context(),
		runs:     make(chan chan struct{}, 8),
	}
}

func (g *gatedGCRunner) Run(ctmap.GCFilter) (int, error) {
	gate := make(chan struct{})
	g.runs <- gate
	select {
	case <-gate:
	case <-g.ctx.Done():
	}
	return 0, nil
}

func newCTScrubTestEndpoint(t *testing.T, gc ctmap.GCRunner) *Endpoint {
	t.Helper()
	ep := &Endpoint{
		ctMapGC:    gc,
		IPv4:       netip.MustParseAddr("10.0.0.1"),
		properties: map[string]any{},
	}
	ep.logger.Store(hivetest.Logger(t))
	return ep
}

// The initial scrub walks the whole CT map: it must not hold the endpoint
// mutex, and regenerations that start while it is in flight (such as the retry
// after a failed first regeneration) must reuse it instead of walking again.
func TestInitialCTScrubSingleFlight(t *testing.T) {
	gc := newGatedGCRunner(t)
	ep := newCTScrubTestEndpoint(t, gc)

	ep.unconditionalLock()
	first := ep.startInitialCTScrubLocked()
	second := ep.startInitialCTScrubLocked()
	ep.unlock()
	t.Cleanup(func() { recvOrFail(t, first, "the initial scrub to stop") })

	require.Equal(t, first, second, "second call started a new scrub")
	gate := recvOrFail(t, gc.runs, "the CT walk to start")
	requireMutexFree(t, ep)
	requireQuiet(t, first, "scrub completion")

	close(gate)
	recvOrFail(t, first, "the initial scrub")

	ep.unconditionalLock()
	third := ep.startInitialCTScrubLocked()
	ep.unlock()
	require.Equal(t, first, third, "a finished endpoint started a new scrub")
	requireQuiet(t, gc.runs, "CT walk")
}

func TestCTScrubIPsLocked(t *testing.T) {
	v4, v6 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")
	set := func(ips ...netip.Addr) map[ctmap.NetAddr]struct{} {
		s := map[ctmap.NetAddr]struct{}{}
		for _, ip := range ips {
			s[ctmap.NetAddr{Addr: ip}] = struct{}{}
		}
		return s
	}

	for _, tc := range []struct {
		name string
		fake bool
		ipv6 netip.Addr
		want map[ctmap.NetAddr]struct{}
	}{
		{name: "IPv4 and IPv6", ipv6: v6, want: set(v4, v6)},
		{name: "fake endpoint", fake: true, ipv6: v6, want: set()},
		{name: "invalid IPv6", want: set(v4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := newCTScrubTestEndpoint(t, ctmap.NewFakeGCRunner())
			ep.IPv6 = tc.ipv6
			ep.SetPropertyValue(endpointtypes.PropertyFakeEndpoint, tc.fake)

			require.Equal(t, tc.want, ep.ctScrubIPsLocked())
		})
	}
}

// noopLXCMap lets Delete run the non-fake endpoint path.
type noopLXCMap struct{ lxcmap.Map }

func (noopLXCMap) DeleteElement(*slog.Logger, lxcmap.EndpointFrontend) []error { return nil }

// newCTScrubDeleteEndpoint returns a started, non-fake endpoint that Delete can
// run on.
func newCTScrubDeleteEndpoint(t *testing.T, gc *gatedGCRunner) *Endpoint {
	t.Helper()
	// These tests hold buildMutex for longer than the lockdebug threshold, which
	// is then logged through a logger that is unset in unit tests.
	lock.SetLogger(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { lock.SetLogger(nil) })

	p := createTestEndpointParams(t)
	p.CTMapGC = gc
	p.LxcMap = noopLXCMap{}
	ep, err := NewEndpointFromChangeModel(p, noopDNSRulesAPI{}, &FakeEndpointProxy{}, newTestEndpointModel(1234, StateReady), nil)
	require.NoError(t, err)
	ep.Start(uint16(ep.ID))
	ep.loader = &fakeloader.Loader{}
	ep.IPv4 = netip.MustParseAddr("10.0.0.1")
	ep.SetPropertyValue(endpointtypes.PropertyFakeEndpoint, false)
	return ep
}

func startDelete(t *testing.T, ep *Endpoint) <-chan struct{} {
	t.Helper()
	deleted := make(chan struct{})
	go func() {
		defer close(deleted)
		ep.Delete(DeleteConfig{NoIdentityRelease: true, NoIPRelease: true})
	}()
	t.Cleanup(func() { recvOrFail(t, deleted, "Delete to return") })
	return deleted
}

// Delete must scrub without the endpoint mutex, and still finish the scrub
// before it returns so that the IP is not released while the walk is running.
func TestDeleteScrubsAfterUnlock(t *testing.T) {
	gc := newGatedGCRunner(t)
	ep := newCTScrubDeleteEndpoint(t, gc)

	deleted := startDelete(t, ep)

	gate := recvOrFail(t, gc.runs, "the CT walk to start")
	requireMutexFree(t, ep)
	requireQuiet(t, deleted, "Delete returning")

	close(gate)
	recvOrFail(t, deleted, "Delete to return")
}

// Delete must wait for a still running initial scrub before scrubbing and
// returning: the initial scrub is not stopped by a failed regeneration or by
// Stop, and must not resume after the IP was handed to a new endpoint.
func TestDeleteJoinsInitialScrub(t *testing.T) {
	gc := newGatedGCRunner(t)
	ep := newCTScrubDeleteEndpoint(t, gc)

	ep.unconditionalLock()
	initial := ep.startInitialCTScrubLocked()
	ep.unlock()
	initialGate := recvOrFail(t, gc.runs, "the initial CT walk to start")

	deleted := startDelete(t, ep)

	requireQuiet(t, gc.runs, "CT walk")
	requireMutexFree(t, ep)
	requireQuiet(t, deleted, "Delete returning")

	close(initialGate)
	recvOrFail(t, initial, "the initial scrub")
	deleteGate := recvOrFail(t, gc.runs, "the delete CT walk to start")
	requireQuiet(t, deleted, "Delete returning")

	close(deleteGate)
	recvOrFail(t, deleted, "Delete to return")
}

func TestWriteInformationalComments(t *testing.T) {
	s := setupEndpointSuite(t)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := createEndpointParams(t, s.orchestrator, s.repo, s.fetcher)
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
	require.NoError(t, err)

	e.Start(uint16(model.ID))
	t.Cleanup(e.Stop)

	var f bytes.Buffer
	err = e.writeInformationalComments(&f)
	require.NoError(t, err)
}

type writeFunc func(io.Writer) error

func BenchmarkWriteHeaderfile(b *testing.B) {
	testutils.IntegrationTest(b)

	s := setupEndpointSuite(b)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := createEndpointParams(b, s.orchestrator, s.repo, s.fetcher)
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
	require.NoError(b, err)

	e.Start(uint16(model.ID))
	b.Cleanup(e.Stop)

	configWriter := &linuxConfig.HeaderfileWriter{}

	targetComments := func(w io.Writer) error {
		return e.writeInformationalComments(w)
	}
	targetConfig := func(w io.Writer) error {
		return configWriter.WriteEndpointConfig(w, e)
	}

	var buf bytes.Buffer
	memoryBacked := func() (io.Writer, func() error) {
		return &buf, func() error { buf.Reset(); return nil }
	}

	f, err := os.CreateTemp("", "cilium_ep_bench_")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	fileBacked := func() (io.Writer, func() error) {
		return f, func() error {
			_, err := f.Seek(0, io.SeekStart)
			return err
		}
	}

	benchmarks := []struct {
		name       string
		outputFunc func() (io.Writer, func() error)
		write      writeFunc
	}{
		{"in-memory-info", memoryBacked, targetComments},
		{"in-memory-cfg", memoryBacked, targetConfig},
		{"to-disk-info", fileBacked, targetComments},
		{"to-disk-cfg", fileBacked, targetConfig},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			output, reset := bm.outputFunc()
			// Prewarn caches, buffers and the golang JSON marshaller. Since we use b.Loop() this will not be counted
			if err := bm.write(output); err != nil {
				b.Fatal(err)
			}

			for b.Loop() {
				// Reset buffer/file offset to avoid allocating unbounded amounts of memory or disk
				if err := reset(); err != nil {
					b.Fatal(err)
				}
				if err := bm.write(output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
