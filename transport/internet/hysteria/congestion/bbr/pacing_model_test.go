package bbr

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestApplicationIdlePreservesModelPacing(t *testing.T) {
	b, _ := newECNTestSender()
	b.pacingRate = testBandwidth * 3
	now := monotime.Now()
	b.OnPacketSent(now, 1200, 1, 1200, true)
	b.OnAppLimited()
	b.OnPacketSent(now.Add(100*time.Millisecond), 1200, 2, 1200, true)
	require.Equal(t, testBandwidth*3, b.PacingRate(), "application idle must not add a cap to the BBR model")
	require.Equal(t, testBandwidth, b.bandwidthEstimate())
}

func TestEDTFallsBackWhenWindowCannotCoverDeliveryRTT(t *testing.T) {
	b, rtt := newECNTestSender()
	b.mode, b.isAtFullBandwidth = bbrModeProbeBw, true
	b.pacingRate = 800_000_000
	b.congestionWindow = 800_000
	for _, check := range []struct {
		rtt    time.Duration
		active bool
	}{{4 * time.Millisecond, true}, {10 * time.Millisecond, false}, {4 * time.Millisecond, true}} {
		rtt.smoothedRTT = check.rtt
		require.Equal(t, check.active, b.PacingRateBytesPerSecond() != 0)
		require.Equal(t, Bandwidth(800_000_000), b.PacingRate())
		require.Equal(t, congestion.ByteCount(800_000), b.GetCongestionWindow())
	}
	b.recoveryState = bbrRecoveryStateConservation
	b.recoveryWindow = b.minCongestionWindow
	require.Zero(t, b.PacingRateBytesPerSecond())
	b.recoveryState = bbrRecoveryStateNotInRecovery
	b.mode = bbrModeProbeRtt
	require.Zero(t, b.PacingRateBytesPerSecond())
}

func TestEmptyFlightDoesNotSkipAnExpiredRTTProbe(t *testing.T) {
	b, _ := newECNTestSender()
	now := monotime.Now()
	b.mode, b.isAtFullBandwidth = bbrModeProbeBw, true
	b.minRttTimestamp = now.Add(-11 * time.Second)
	b.OnPacketSent(now, 1200, 1, 1200, true)
	expired := b.maybeUpdateMinRtt(now, 80*time.Millisecond)
	require.True(t, expired)
	b.maybeEnterOrExitProbeRtt(now, true, expired)
	require.Equal(t, bbrMode(bbrModeProbeRtt), b.mode, "ACK batch draining a flight is not application idle")
}

func TestRefillingAfterRTTProbeKeepsLowSamplesProtected(t *testing.T) {
	for _, full := range []bool{false, true} {
		b, _ := newECNTestSender()
		now := monotime.Now()
		b.mode, b.isAtFullBandwidth = bbrModeProbeRtt, full
		b.bytesInFlight = 0
		b.exitProbeRttAt = now
		b.probeRttRoundPassed = true
		b.maybeEnterOrExitProbeRtt(now, true, false)
		mode := bbrMode(bbrModeStartup)
		if full {
			mode = bbrModeProbeBw
		}
		require.Equal(t, mode, b.mode)
		b.OnPacketSent(now.Add(time.Millisecond), b.GetCongestionWindow(), 1, 1200, true)
		require.True(t, b.sampler.connectionStateMap.GetEntry(1).sendTimeState.isAppLimited)
		b.OnCongestionEventEx(b.GetCongestionWindow(), now.Add(5*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200}}, nil)
		require.False(t, b.sampler.IsAppLimited())
	}
}

func TestApplicationIdleDoesNotExtendProbeRecovery(t *testing.T) {
	b, _ := newECNTestSender()
	now := monotime.Now()
	b.mode, b.isAtFullBandwidth = bbrModeProbeRtt, false
	b.bytesInFlight = 0
	b.exitProbeRttAt = now
	b.probeRttRoundPassed = true
	b.maybeEnterOrExitProbeRtt(now, true, false)
	b.OnPacketSent(now.Add(time.Millisecond), b.GetCongestionWindow(), 1, 1200, true)
	b.OnAppLimited()
	b.OnCongestionEventEx(b.GetCongestionWindow(), now.Add(5*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200}}, nil)
	require.True(t, b.sampler.IsAppLimited())
	require.False(t, b.sampler.probeRTTLimited)
	b.OnPacketSent(now.Add(6*time.Millisecond), b.GetCongestionWindow(), 2, 1200, true)
	require.False(t, b.sampler.connectionStateMap.GetEntry(2).sendTimeState.isAppLimited)
}

func TestFullCruiseFlightUpdatesOldBandwidthDespiteProducerQueueGaps(t *testing.T) {
	for _, fullFlight := range []bool{false, true} {
		b, _ := newECNTestSender()
		now := monotime.Now()
		b.mode, b.isAtFullBandwidth = bbrModeProbeBw, true
		b.minRttTimestamp = now
		b.OnPacketSent(now, 1200, 0, 1200, true)
		b.OnCongestionEventEx(1200, now.Add(4*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 0, BytesAcked: 1200}}, nil)
		b.roundTripCount = 11
		for number := congestion.PacketNumber(1); number <= 3; number++ {
			sent := now.Add(time.Duration(number) * 10 * time.Millisecond)
			b.OnAppLimited()
			flight := congestion.ByteCount(2400)
			if fullFlight {
				flight = b.GetCongestionWindow()
			}
			b.OnPacketSent(sent, flight, number, 1200, true)
			require.Equal(t, !fullFlight, b.sampler.connectionStateMap.GetEntry(number).sendTimeState.isAppLimited)
			b.OnCongestionEventEx(flight, sent.Add(4*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: number, BytesAcked: 1200}}, nil)
		}
		require.Equal(t, fullFlight, b.bandwidthEstimate() < testBandwidth)
	}
}
