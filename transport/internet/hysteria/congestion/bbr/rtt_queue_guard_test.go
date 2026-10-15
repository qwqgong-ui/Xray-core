package bbr

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRTTQueueGuardWorksWithoutECNAndConverges(t *testing.T) {
	b, rtt := newECNTestSender()
	b.mode, b.isAtFullBandwidth = bbrModeProbeBw, true
	require.False(t, b.ecn.capable)
	rtt.latestRTT = 28 * time.Millisecond
	initial := b.pacingRate
	b.applyRTTQueueGuard(true)
	require.False(t, b.queueGuard.active, "one moderate sample is insufficient")
	require.Equal(t, initial, b.pacingRate)
	b.applyRTTQueueGuard(true)
	require.True(t, b.queueGuard.active)
	require.Less(t, b.pacingRate, initial)
	last := b.pacingRate
	for range 4 {
		b.pacingRate = initial // normal BBR recalculation must not undo drain
		b.applyRTTQueueGuard(true)
		require.Less(t, b.pacingRate, last)
		require.GreaterOrEqual(t, b.congestionWindow, b.minCongestionWindow)
		last = b.pacingRate
	}
	rtt.latestRTT = 22 * time.Millisecond
	b.applyRTTQueueGuard(true)
	require.False(t, b.queueGuard.active, "drain clears below the lower threshold")
}

func TestRTTQueueGuardSevereSpikeAndMigration(t *testing.T) {
	b, rtt := newECNTestSender()
	rtt.latestRTT = 80 * time.Millisecond
	b.applyRTTQueueGuard(false)
	require.True(t, b.queueGuard.active)
	b.OnPathMigration()
	require.False(t, b.queueGuard.active)
	require.Zero(t, b.queueGuard.rate)
}

func TestZeroCESteadyStatePreservesProbeGain(t *testing.T) {
	b, _ := newECNTestSender()
	b.mode, b.isAtFullBandwidth = bbrModeProbeBw, true
	b.pacingRate = testBandwidth * 3 / 4 // PROBE_BW drain gain
	window := b.congestionWindow
	b.OnECNFeedback(true, false, 64, 0, 0)
	b.applyECNPolicy(true, false)
	require.Equal(t, testBandwidth*3/4, b.pacingRate)
	require.Equal(t, window, b.congestionWindow)
}

func TestRTTQueueGuardCannotUndoProbeRTTOrRecovery(t *testing.T) {
	b, rtt := newECNTestSender()
	b.mode = bbrModeProbeRtt
	b.pacingRate = testBandwidth / 10
	b.congestionWindow = b.minCongestionWindow
	rtt.latestRTT = 80 * time.Millisecond
	b.applyRTTQueueGuard(true)
	require.LessOrEqual(t, b.pacingRate, testBandwidth/10)
	require.Equal(t, b.minCongestionWindow, b.congestionWindow)
}
