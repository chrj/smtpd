package middleware

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/chrj/smtpd/v2"
)

// checkTriple runs one RecipientCheck for a made-up triple.
func checkTriple(g *GreylistChecker, i int) error {
	peer := smtpd.Peer{Addr: &net.TCPAddr{
		IP:   net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
		Port: 25,
	}}
	return g.RecipientCheck(context.Background(), peer, fmt.Sprintf("r%d@example.net", i))
}

// TestGreylistBoundsMemory verifies that the map stops growing at the cap. A
// client that sends many different triples must not be able to make the
// server hold all of them.
func TestGreylistBoundsMemory(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	g := Greylist(
		WithGreylistMaxEntries(100),
		withGreylistClock(func() time.Time { return now }),
	)

	for i := range 1000 {
		_ = checkTriple(g, i)
	}

	g.mu.Lock()
	got := len(g.entries)
	g.mu.Unlock()

	if got > 100 {
		t.Fatalf("expected at most 100 entries, got %d", got)
	}
}

// TestGreylistEvictsOldestFirst verifies that the cap drops the oldest
// entries. A triple that was seen recently has to survive an eviction, or a
// sender that is part way through the delay starts over.
func TestGreylistEvictsOldestFirst(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	g := Greylist(
		WithGreylistMaxEntries(50),
		withGreylistClock(func() time.Time { return now }),
	)

	// The oldest triple goes in first.
	_ = checkTriple(g, 0)

	// Every later triple is one second newer.
	for i := 1; i < 500; i++ {
		now = now.Add(time.Second)
		_ = checkTriple(g, i)
	}

	g.mu.Lock()
	_, oldestKept := g.entries[keyOf(0)]
	_, newestKept := g.entries[keyOf(499)]
	g.mu.Unlock()

	if oldestKept {
		t.Error("expected the oldest entry to be evicted")
	}
	if !newestKept {
		t.Error("expected the newest entry to be kept")
	}
}

// keyOf builds the map key that checkTriple produces for i.
func keyOf(i int) string {
	ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
	return ip.String() + "|" + "" + "|" + fmt.Sprintf("r%d@example.net", i)
}

// TestGreylistExpiryDoesNotDependOnTheSweep verifies that a triple past the
// TTL is treated as new, even when the sweep that reclaims memory has not run
// yet. Correctness must not depend on when the sweep happens.
func TestGreylistExpiryDoesNotDependOnTheSweep(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	g := Greylist(
		WithGreylistDelay(5*time.Minute),
		WithGreylistTTL(time.Hour),
		withGreylistClock(func() time.Time { return now }),
	)

	if err := checkTriple(g, 1); err == nil {
		t.Fatal("expected the first attempt to be greylisted")
	}

	// Move past the TTL. The entry is stale, so the triple starts over.
	now = now.Add(2 * time.Hour)

	if err := checkTriple(g, 1); err == nil {
		t.Fatal("expected a triple past the TTL to be greylisted again")
	}

	// It is now a fresh entry, so the delay applies from this point.
	now = now.Add(10 * time.Minute)

	if err := checkTriple(g, 1); err != nil {
		t.Fatalf("expected the retry after the delay to pass, got %v", err)
	}
}

// TestGreylistSweepIsNotRunOnEveryCheck verifies that the sweep is amortized.
// A sweep on every check makes each one cost as much as the whole map.
func TestGreylistSweepIsNotRunOnEveryCheck(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	g := Greylist(
		WithGreylistMaxEntries(10_000),
		withGreylistClock(func() time.Time { return now }),
	)

	for i := range 200 {
		_ = checkTriple(g, i)
	}

	g.mu.Lock()
	sweeps := g.sweeps
	g.mu.Unlock()

	// The clock does not move, so only the first check may sweep.
	if sweeps > 1 {
		t.Fatalf("expected at most 1 sweep over 200 checks, got %d", sweeps)
	}
}

// TestGreylistTinyCap covers a cap so small that the low-water mark rounds
// down to zero.
func TestGreylistTinyCap(t *testing.T) {
	t.Parallel()

	for _, max := range []int{1, 2, 5} {
		now := time.Unix(1_700_000_000, 0)
		g := Greylist(
			WithGreylistMaxEntries(max),
			withGreylistClock(func() time.Time { return now }),
		)
		for i := range 20 {
			now = now.Add(time.Second)
			_ = checkTriple(g, i)
		}
		g.mu.Lock()
		got := len(g.entries)
		g.mu.Unlock()
		if got > max {
			t.Errorf("max=%d: expected at most %d entries, got %d", max, max, got)
		}
	}
}
