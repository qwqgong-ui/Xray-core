package bbr

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"

	"github.com/stretchr/testify/require"
)

const testBandwidth = Bandwidth(100_000_000)

type ecnTestRTTStats struct {
	minRTT      time.Duration
	latestRTT   time.Duration
	smoothedRTT time.Duration
}

func (s *ecnTestRTTStats) MinRTT() time.Duration                  { return s.minRTT }
func (s *ecnTestRTTStats) LatestRTT() time.Duration               { return s.latestRTT }
func (s *ecnTestRTTStats) SmoothedRTT() time.Duration             { return s.smoothedRTT }
func (s *ecnTestRTTStats) MeanDeviation() time.Duration           { return 0 }
func (s *ecnTestRTTStats) MaxAckDelay() time.Duration             { return 0 }
func (s *ecnTestRTTStats) PTO(bool) time.Duration                 { return s.smoothedRTT }
func (s *ecnTestRTTStats) UpdateRTT(time.Duration, time.Duration) {}
func (s *ecnTestRTTStats) SetMaxAckDelay(time.Duration)           {}
func (s *ecnTestRTTStats) SetInitialRTT(time.Duration)            {}

func newECNTestSender() (*bbrSender, *ecnTestRTTStats) {
	rtt := &ecnTestRTTStats{
		minRTT:      20 * time.Millisecond,
		latestRTT:   20 * time.Millisecond,
		smoothedRTT: 20 * time.Millisecond,
	}
	b := NewBbrSender(DefaultClock{}, congestion.InitialPacketSize, ProfileStandard)
	b.SetRTTStatsProvider(rtt)
	b.minRtt = rtt.minRTT
	b.maxBandwidth.Update(testBandwidth, b.roundTripCount)
	b.pacingRate = testBandwidth
	return b, rtt
}

func confirmZeroCE(b *bbrSender) {
	b.OnECNFeedback(true, false, 64, 0, 0)
	b.applyECNPolicy(false, false)
}

func TestECNZeroCEFastGrowAndMonotonicFloors(t *testing.T) {
	b, _ := newECNTestSender()
	confirmZeroCE(b)
	firstBandwidthFloor := b.ecn.btlBwFloor
	firstInflightFloor := b.ecn.inflightFloor

	require.Equal(t, ecnPhaseFastGrow, b.currentECNPhase())
	require.Equal(t, testBandwidth, firstBandwidthFloor)
	require.GreaterOrEqual(t, b.pacingRate, Bandwidth(b.highGain*float64(testBandwidth)))

	b.pacingRate = testBandwidth / 2
	b.congestionWindow = b.minCongestionWindow
	confirmZeroCE(b)
	require.GreaterOrEqual(t, b.ecn.btlBwFloor, firstBandwidthFloor)
	require.GreaterOrEqual(t, b.ecn.inflightFloor, firstInflightFloor)
}

func TestECNFirstCEFreezesWithoutImmediateReduction(t *testing.T) {
	b, _ := newECNTestSender()
	confirmZeroCE(b)
	beforePacing := b.pacingRate
	beforeInflight := b.congestionWindow

	b.OnECNFeedback(true, false, 63, 0, 1)
	b.applyECNPolicy(false, false)

	require.Equal(t, ecnPhaseFreeze, b.currentECNPhase())
	require.Equal(t, beforePacing, b.pacingRate)
	require.Equal(t, beforeInflight, b.congestionWindow)
	require.InDelta(t, 1.0/64.0, b.ecn.lastRatio, 1e-9)
}

func TestECNSustainedCEShrinksAndEventuallyLowersFloors(t *testing.T) {
	b, _ := newECNTestSender()
	confirmZeroCE(b)
	confirmZeroCE(b)
	b.OnECNFeedback(true, false, 15, 0, 1)
	b.applyECNPolicy(false, false)
	originalPacing := b.pacingRate
	originalFloor := b.ecn.btlBwFloor

	for epoch := 0; epoch < ecnFloorReductionEpochs; epoch++ {
		b.roundTripCount++
		b.OnECNFeedback(true, false, 15, 0, 1)
		b.applyECNPolicy(true, false)
	}

	require.Equal(t, ecnPhaseShrink, b.currentECNPhase())
	require.Less(t, b.pacingRate, originalPacing)
	require.Less(t, b.ecn.btlBwFloor, originalFloor)
	require.Greater(t, b.ecn.alpha, 0.0)
}

func TestECNCEClearsAndFastGrowthResumes(t *testing.T) {
	b, _ := newECNTestSender()
	confirmZeroCE(b)
	b.OnECNFeedback(true, false, 15, 0, 1)
	b.applyECNPolicy(false, false)
	b.roundTripCount++
	b.OnECNFeedback(true, false, 15, 0, 1)
	b.applyECNPolicy(true, false)
	shrunk := b.pacingRate

	b.OnECNFeedback(true, false, 16, 0, 0)
	b.applyECNPolicy(false, false)

	require.Equal(t, ecnPhaseFastGrow, b.currentECNPhase())
	require.Greater(t, b.pacingRate, shrunk)
}

func TestECNValidationFailureUsesLossFallback(t *testing.T) {
	b, _ := newECNTestSender()
	beforePacing := b.pacingRate
	b.OnECNFeedback(false, true, 0, 0, 0)
	b.applyECNPolicy(false, false)

	require.Equal(t, ecnPhaseFallback, b.currentECNPhase())
	require.Equal(t, beforePacing, b.pacingRate)
	require.True(t, b.hasSafetyLoss(100_000, []congestion.LostPacketInfo{{BytesLost: 1}}))
}

func TestECNCapablePathUsesOnlySafetyLoss(t *testing.T) {
	b, _ := newECNTestSender()
	confirmZeroCE(b)

	require.False(t, b.hasSafetyLoss(100_000, []congestion.LostPacketInfo{{BytesLost: 9_999}}))
	require.True(t, b.hasSafetyLoss(100_000, []congestion.LostPacketInfo{{BytesLost: 10_000}}))
}

func TestECNRTTWatchdogDrainsBandwidthDropAndRecovers(t *testing.T) {
	b, rtt := newECNTestSender()
	confirmZeroCE(b)
	floor := b.ecn.btlBwFloor
	beforeDrain := b.pacingRate
	b.maxBandwidth = NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth])
	b.maxBandwidth.Update(testBandwidth/4, b.roundTripCount)
	rtt.latestRTT = 40 * time.Millisecond
	b.applyECNPolicy(false, false)

	require.Equal(t, testBandwidth/4, b.bandwidthEstimate())
	require.Equal(t, ecnPhaseDrain, b.currentECNPhase())
	require.Less(t, b.pacingRate, beforeDrain)
	require.Equal(t, floor, b.ecn.btlBwFloor)

	b.maxBandwidth = NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth])
	b.maxBandwidth.Update(testBandwidth, b.roundTripCount)
	rtt.latestRTT = 22 * time.Millisecond
	b.OnECNFeedback(true, false, 32, 0, 0)
	b.applyECNPolicy(false, false)
	require.Equal(t, ecnPhaseFastGrow, b.currentECNPhase())
	require.Greater(t, b.pacingRate, Bandwidth(float64(floor)))
}

func TestECNPathMigrationDecaysPathStateAndRevalidates(t *testing.T) {
	b, _ := newECNTestSender()
	confirmZeroCE(b)
	confirmZeroCE(b)
	oldBandwidthFloor := b.ecn.btlBwFloor
	oldInflightFloor := b.ecn.inflightFloor

	b.OnPathMigration()

	require.Equal(t, ecnPhaseFallback, b.currentECNPhase())
	require.False(t, b.ecn.capable)
	require.Zero(t, b.ecn.alpha)
	require.Equal(t, scaleBandwidth(oldBandwidthFloor, ecnPathMigrationDecay), b.ecn.btlBwFloor)
	require.Equal(t, max(b.minCongestionWindow, scaleWindow(oldInflightFloor, ecnPathMigrationDecay)), b.ecn.inflightFloor)
	require.Zero(t, b.bandwidthEstimate())
	require.Zero(t, b.minRtt)
}
