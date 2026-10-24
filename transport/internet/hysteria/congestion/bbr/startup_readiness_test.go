package bbr

import (
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestExplicitIdleSurvivesTailFlight(t *testing.T) {
	b, _ := newECNTestSender()
	b.bytesInFlight = b.getTargetCongestionWindow(1) * 2
	require.False(t, b.sampler.IsAppLimited())
	b.OnAppLimited()
	require.True(t, b.sampler.IsAppLimited(), "explicit transport idle must survive a full tail flight")
}

func TestReadinessTrafficDoesNotEndStartup(t *testing.T) {
	b, _ := newECNTestSender()
	small := sendTimeState{isValid: true, bytesInFlight: 1200}
	for i := 0; i < 20; i++ {
		b.checkIfFullBandwidthReached(&small)
	}
	require.False(t, b.isAtFullBandwidth)
	require.Zero(t, b.roundsWithoutBandwidthGain)
	require.False(t, b.lastSampleIsAppLimited, "do not infer application limitation from a small flight")
	full := sendTimeState{isValid: true, bytesInFlight: b.initialCongestionWindow}
	for i := int64(0); i <= b.numStartupRtts; i++ {
		b.checkIfFullBandwidthReached(&full)
	}
	require.True(t, b.isAtFullBandwidth, "a saturated plateau still exits STARTUP")
}

func TestReadinessGuardPreservesLossExit(t *testing.T) {
	b, _ := newECNTestSender()
	small := sendTimeState{isValid: true, bytesInFlight: 1200}
	b.numLossEventsInRound = defaultStartupFullLossCount
	b.bytesLostInRound = congestion.ByteCount(1200)
	b.checkIfFullBandwidthReached(&small)
	require.True(t, b.isAtFullBandwidth)
}

func TestAppLimitedSamplesCannotSuppressLossStartupExit(t *testing.T) {
	b, _ := newECNTestSender()
	b.lastSampleIsAppLimited = true
	b.numLossEventsInRound = defaultStartupFullLossCount
	b.bytesLostInRound = 1200
	b.checkIfFullBandwidthReached(&sendTimeState{isValid: true, isAppLimited: true, bytesInFlight: 1200})
	require.True(t, b.isAtFullBandwidth, "loss still ends STARTUP for an application-limited sample")
}

func TestFullFlightPlateauExitsDespiteProducerQueueGaps(t *testing.T) {
	for _, fullFlight := range []bool{false, true} {
		b, _ := newECNTestSender()
		b.congestionWindow = b.getTargetCongestionWindow(b.highCwndGain)
		b.lastSampleIsAppLimited = true
		state := sendTimeState{isValid: true, isAppLimited: true, bytesInFlight: 1200}
		if fullFlight {
			state.bytesInFlight = b.congestionWindow
		}
		for i := int64(0); i <= b.numStartupRtts; i++ {
			b.OnAppLimited()
			b.OnPacketSent(monotime.Now(), state.bytesInFlight, congestion.PacketNumber(i+1), 1200, true)
			state = b.sampler.connectionStateMap.GetEntry(congestion.PacketNumber(i + 1)).sendTimeState
			b.lastSampleIsAppLimited = state.isAppLimited
			b.checkIfFullBandwidthReached(&state)
		}
		require.Equal(t, fullFlight, b.isAtFullBandwidth, "满窗口与真正稀疏流量必须区分")
	}
}
