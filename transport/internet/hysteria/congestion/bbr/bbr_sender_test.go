package bbr

import (
	"math"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestSetMaxDatagramSizeRescalesPacketSizedWindows(t *testing.T) {
	const oldMaxDatagramSize = congestion.ByteCount(1000)
	const newMaxDatagramSize = congestion.ByteCount(1400)
	const initialCongestionWindowPackets = congestion.ByteCount(20)
	const maxCongestionWindowPackets = congestion.ByteCount(80)

	b := newBbrSender(
		DefaultClock{},
		oldMaxDatagramSize,
		initialCongestionWindowPackets*oldMaxDatagramSize,
		maxCongestionWindowPackets*oldMaxDatagramSize,
		ProfileStandard,
	)
	b.congestionWindow = b.initialCongestionWindow

	b.SetMaxDatagramSize(newMaxDatagramSize)

	require.Equal(t, initialCongestionWindowPackets*newMaxDatagramSize, b.initialCongestionWindow)
	require.Equal(t, maxCongestionWindowPackets*newMaxDatagramSize, b.maxCongestionWindow)
	require.Equal(t, minCongestionWindowPackets*newMaxDatagramSize, b.minCongestionWindow)
	require.Equal(t, initialCongestionWindowPackets*newMaxDatagramSize, b.congestionWindow)
}

func TestBBRPostSendFlightStartsAndRestartsSampler(t *testing.T) {
	b, _ := newECNTestSender()
	const size = congestion.ByteCount(1200)
	now := monotime.Now()
	b.OnPacketSent(now, size, 1, size, true)
	require.True(t, b.exitingQuiescence)
	state := b.sampler.connectionStateMap.GetEntry(1)
	require.Equal(t, size, state.sendTimeState.bytesInFlight)
	require.Equal(t, now, state.lastAckedPacketSentTime)
	b.OnCongestionEventEx(size, now.Add(20*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: size}}, nil)
	require.Positive(t, b.bandwidthEstimate())
	b.exitingQuiescence = false
	b.OnPacketSent(now.Add(time.Second), size, 2, size, true)
	require.True(t, b.exitingQuiescence)
	require.Equal(t, now.Add(time.Second), b.sampler.connectionStateMap.GetEntry(2).lastAckedPacketSentTime)
	// ACK-only packets do not represent a new flight of application data.
	b.exitingQuiescence = false
	b.OnPacketSent(now.Add(2*time.Second), 0, 3, 40, false)
	require.False(t, b.exitingQuiescence)
}

func TestBBRLossOnlyEventEntersAndExtendsRecovery(t *testing.T) {
	b, _ := newECNTestSender()
	b.isAtFullBandwidth = true
	now := monotime.Now()
	for i := congestion.PacketNumber(1); i <= 3; i++ {
		b.OnPacketSent(now, congestion.ByteCount(i)*1200, i, 1200, true)
	}
	b.OnCongestionEventEx(3600, now.Add(time.Second), nil, []congestion.LostPacketInfo{{PacketNumber: 1, BytesLost: 1200}})
	require.True(t, b.InRecovery())
	require.Equal(t, congestion.PacketNumber(3), b.endRecoveryAt)
	b.OnPacketSent(now.Add(2*time.Second), 3600, 4, 1200, true)
	b.OnCongestionEventEx(3600, now.Add(3*time.Second), nil, []congestion.LostPacketInfo{{PacketNumber: 2, BytesLost: 1200}})
	require.Equal(t, congestion.PacketNumber(4), b.endRecoveryAt)
	require.NotPanics(t, func() { b.OnCongestionEventEx(0, now, nil, nil) })
}

func TestBBREffectivePacingRatePreservesSlowLink(t *testing.T) {
	b, _ := newECNTestSender()
	b.pacingRate = 8_000
	require.Equal(t, uint64(1000), b.PacingRateBytesPerSecond())
	b.pacingRate = 1
	require.Equal(t, uint64(1), b.PacingRateBytesPerSecond())
}

func TestBBRSmallFlightACKIsNotApplicationLimited(t *testing.T) {
	b, _ := newECNTestSender()
	now := monotime.Now()
	b.OnPacketSent(now, 1200, 1, 1200, true)
	b.OnCongestionEventEx(1200, now.Add(20*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200}}, nil)
	require.False(t, b.sampler.IsAppLimited())
	b.OnAppLimited()
	require.True(t, b.sampler.IsAppLimited())
}

func TestBBRBandwidthArithmeticDoesNotOverflow(t *testing.T) {
	const bytes = congestion.ByteCount(1_000_000_000)
	require.Equal(t, Bandwidth(8_000_000_000), BandwidthFromDelta(bytes, time.Second))
	require.Equal(t, bytes, bytesFromBandwidthAndTimeDelta(8_000_000_000, time.Second))
	require.Equal(t, time.Second, timeDeltaFromBytesAndBandwidth(bytes, 8_000_000_000))
	require.Equal(t, congestion.ByteCount(math.MaxInt64), bytesFromBandwidthAndTimeDelta(infBandwidth, time.Hour))
	require.Equal(t, infBandwidth, BandwidthFromDelta(math.MaxInt64, time.Nanosecond))
}

func TestSetMaxDatagramSizeClampsCongestionWindow(t *testing.T) {
	const oldMaxDatagramSize = congestion.ByteCount(1000)
	const newMaxDatagramSize = congestion.ByteCount(1400)

	b := NewBbrSender(DefaultClock{}, oldMaxDatagramSize, ProfileStandard)
	b.congestionWindow = b.minCongestionWindow + oldMaxDatagramSize
	b.recoveryWindow = b.minCongestionWindow + oldMaxDatagramSize

	b.SetMaxDatagramSize(newMaxDatagramSize)

	require.Equal(t, b.minCongestionWindow, b.congestionWindow)
	require.Equal(t, b.minCongestionWindow, b.recoveryWindow)
}

func TestNewBbrSenderAppliesProfiles(t *testing.T) {
	testCases := []struct {
		name                                string
		profile                             Profile
		highGain                            float64
		highCwndGain                        float64
		congestionWindowGainConstant        float64
		numStartupRtts                      int64
		drainToTarget                       bool
		detectOvershooting                  bool
		bytesLostMultiplier                 uint8
		enableAckAggregationDuringStartup   bool
		expireAckAggregationInStartup       bool
		enableOverestimateAvoidance         bool
		reduceExtraAckedOnBandwidthIncrease bool
	}{
		{
			name:                         "standard",
			profile:                      ProfileStandard,
			highGain:                     defaultHighGain,
			highCwndGain:                 derivedHighCWNDGain,
			congestionWindowGainConstant: 2.0,
			numStartupRtts:               roundTripsWithoutGrowthBeforeExitingStartup,
			bytesLostMultiplier:          2,
		},
		{
			name:                                "conservative",
			profile:                             ProfileConservative,
			highGain:                            2.25,
			highCwndGain:                        1.75,
			congestionWindowGainConstant:        1.75,
			numStartupRtts:                      2,
			drainToTarget:                       true,
			detectOvershooting:                  true,
			bytesLostMultiplier:                 1,
			enableOverestimateAvoidance:         true,
			reduceExtraAckedOnBandwidthIncrease: true,
		},
		{
			name:                              "aggressive",
			profile:                           ProfileAggressive,
			highGain:                          3.0,
			highCwndGain:                      2.5,
			congestionWindowGainConstant:      3.0,
			numStartupRtts:                    4,
			bytesLostMultiplier:               2,
			enableAckAggregationDuringStartup: true,
			expireAckAggregationInStartup:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBbrSender(DefaultClock{}, congestion.InitialPacketSize, tc.profile)
			require.Equal(t, tc.profile, b.profile)
			require.Equal(t, tc.highGain, b.highGain)
			require.Equal(t, tc.highCwndGain, b.highCwndGain)
			require.Equal(t, tc.congestionWindowGainConstant, b.congestionWindowGainConstant)
			require.Equal(t, tc.numStartupRtts, b.numStartupRtts)
			require.Equal(t, tc.drainToTarget, b.drainToTarget)
			require.Equal(t, tc.detectOvershooting, b.detectOvershooting)
			require.Equal(t, tc.bytesLostMultiplier, b.bytesLostMultiplierWhileDetectingOvershooting)
			require.Equal(t, tc.enableAckAggregationDuringStartup, b.enableAckAggregationDuringStartup)
			require.Equal(t, tc.expireAckAggregationInStartup, b.expireAckAggregationInStartup)
			require.Equal(t, tc.enableOverestimateAvoidance, b.sampler.IsOverestimateAvoidanceEnabled())
			require.Equal(t, tc.reduceExtraAckedOnBandwidthIncrease, b.sampler.maxAckHeightTracker.reduceExtraAckedOnBandwidthIncrease)
			require.Equal(t, b.highGain, b.pacingGain)
			require.Equal(t, b.highCwndGain, b.congestionWindowGain)
		})
	}
}

func TestParseProfile(t *testing.T) {
	profile, err := ParseProfile("")
	require.NoError(t, err)
	require.Equal(t, ProfileStandard, profile)

	profile, err = ParseProfile("Aggressive")
	require.NoError(t, err)
	require.Equal(t, ProfileAggressive, profile)

	_, err = ParseProfile("turbo")
	require.EqualError(t, err, `unsupported BBR profile "turbo"`)
}
