package bbr

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestAdaptiveRateGuardStillDiscoversHigherCapacity(t *testing.T) {
	b, _ := newECNTestSender()
	b.applyProfile(ProfileAggressive)
	b.pacingGain = b.highGain
	b.pacingRate = testBandwidth * 3
	now := monotime.Now()
	b.minRttTimestamp = now
	const size = congestion.ByteCount(1200)
	b.OnPacketSent(now, size, 1, size, true)
	b.OnAppLimited()
	now = now.Add(100 * time.Millisecond)
	b.OnPacketSent(now, size, 2, size, true)
	b.maxBandwidth.Update(testBandwidth*5, b.roundTripCount)
	previous := b.PacingRate()
	for i := 1; i <= 16; i++ {
		// Isolate the rate limiter from the bandwidth sampler: this is the
		// same valid, higher-capacity model at each controller recalculation.
		b.pacingRate = testBandwidth * 5
		b.limitPacingRateIncrease(now.Add(time.Duration(i)*20*time.Millisecond), true)
		rate := b.PacingRate()
		require.LessOrEqual(t, rate, previous+previous/4, "one round cannot accumulate a large rate jump")
		previous = rate
	}
	require.Greater(t, b.PacingRate(), testBandwidth*4, "this is not a permanent upload cap")
	require.Equal(t, testBandwidth*5, b.bandwidthEstimate(), "do not rewrite the capacity model")
}

func TestSparseReadinessDoesNotArmIdleRateGuard(t *testing.T) {
	b, _ := newECNTestSender()
	b.maxBandwidth = NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth])
	b.maxBandwidth.Update(100_000, b.roundTripCount)
	b.pacingRate = 300_000
	now := monotime.Now()
	b.OnPacketSent(now, 1200, 1, 1200, true)
	b.OnAppLimited()
	b.OnPacketSent(now.Add(100*time.Millisecond), 1200, 2, 1200, true)
	require.Zero(t, b.rateGuard.rate)
	require.Equal(t, Bandwidth(300_000), b.PacingRate())
}

func TestBriefApplicationGapDoesNotDisableCapacityProbing(t *testing.T) {
	b, _ := newECNTestSender()
	b.pacingRate = testBandwidth * 3
	now := monotime.Now()
	b.OnPacketSent(now, 1200, 1, 1200, true)
	b.OnAppLimited()
	b.OnPacketSent(now.Add(time.Millisecond), 1200, 2, 1200, true)
	require.Zero(t, b.rateGuard.rate, "brief producer gaps do not make an established path restart every batch")
	require.Equal(t, testBandwidth*3, b.PacingRate())
}

func TestCompressedRoundsDoNotAccumulateRateIncrease(t *testing.T) {
	b, _ := newECNTestSender()
	now := monotime.Now()
	b.rateGuard = pacingRateGuard{rate: testBandwidth / 4, lastIncrease: now}
	for i := 1; i <= 10; i++ {
		b.limitPacingRateIncrease(now.Add(time.Duration(i)*time.Microsecond), true)
		require.Equal(t, testBandwidth/4, b.PacingRate())
	}
	b.limitPacingRateIncrease(now.Add(-time.Millisecond), true)
	require.Equal(t, testBandwidth/4, b.PacingRate(), "a backwards clock gives no growth credit")
	b.limitPacingRateIncrease(now.Add(20*time.Millisecond), true)
	require.Equal(t, testBandwidth*5/16, b.PacingRate())
}

func TestRateGuardMigrationAndIntegerBoundary(t *testing.T) {
	b, _ := newECNTestSender()
	now := monotime.Now()
	b.rateGuard = pacingRateGuard{rate: infBandwidth - 100, lastIncrease: now}
	b.pacingRate = infBandwidth
	b.limitPacingRateIncrease(now.Add(20*time.Millisecond), true)
	require.Equal(t, infBandwidth, b.PacingRate(), "near-limit growth cannot wrap")
	b.rateGuard.rate = testBandwidth
	b.OnAppLimited()
	b.OnPathMigration()
	require.Zero(t, b.rateGuard.rate)
	require.True(t, b.rateGuard.lastIncrease.IsZero())
	require.False(t, b.appIdle)
	require.True(t, b.lastDataSent.IsZero())
}

func TestIdleRestartDoesNotReapplyStartupMultiplier(t *testing.T) {
	b, _ := newECNTestSender()
	b.applyProfile(ProfileAggressive)
	b.pacingGain = b.highGain
	b.pacingRate = testBandwidth * 3
	now := monotime.Now()
	b.OnPacketSent(now, 1200, 1, 1200, true)
	b.OnAppLimited()
	b.OnPacketSent(now.Add(100*time.Millisecond), 1200, 2, 1200, true)
	require.LessOrEqual(t, b.PacingRate(), testBandwidth, "an established idle path must resume at delivery rate, not 3x STARTUP")
	confirmZeroCE(b)
	require.LessOrEqual(t, b.PacingRate(), testBandwidth, "zero CE must not bypass the idle restart guard")
	require.Equal(t, testBandwidth, b.bandwidthEstimate(), "the capacity model remains available")
}

func TestHealthyAckCannotImmediatelyUndoRTTDrain(t *testing.T) {
	b, rtt := newECNTestSender()
	now := monotime.Now()
	b.minRttTimestamp = now
	const size = congestion.ByteCount(1200)
	b.OnPacketSent(now, size, 1, size, true)
	b.OnPacketSent(now.Add(time.Millisecond), 2*size, 2, size, true)
	rtt.latestRTT = 80 * time.Millisecond
	b.OnCongestionEventEx(2*size, now.Add(80*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: size}}, nil)
	require.True(t, b.queueGuard.active)
	drainRate := b.PacingRate()
	rtt.latestRTT = 20 * time.Millisecond
	b.OnCongestionEventEx(size, now.Add(80*time.Millisecond+100*time.Microsecond), []congestion.AckedPacketInfo{{PacketNumber: 2, BytesAcked: size}}, nil)
	require.LessOrEqual(t, b.PacingRate(), drainRate, "a single healthy compressed ACK must not restore the high rate")
}

func TestAppLimitedSamplesCannotSuppressCongestedStartupExit(t *testing.T) {
	for _, reason := range []string{"queue", "loss"} {
		t.Run(reason, func(t *testing.T) {
			b, _ := newECNTestSender()
			b.lastSampleIsAppLimited = true
			if reason == "queue" {
				b.queueGuard.active = true
			} else {
				b.numLossEventsInRound = defaultStartupFullLossCount
				b.bytesLostInRound = 1200
			}
			b.checkIfFullBandwidthReached(&sendTimeState{isValid: true, isAppLimited: true, bytesInFlight: 1200})
			require.True(t, b.isAtFullBandwidth, "real congestion ends STARTUP even for an application-limited sample")
		})
	}
}
