package bbr

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

// EDT 可能被后发控制包越过，包号差不能代替实际确认或丢失。
func TestReorderedFeedbackPreservesOutstandingSamples(t *testing.T) {
	for _, lost := range []bool{false, true} {
		b, _ := newECNTestSender()
		now := monotime.Now()
		b.OnPacketSent(now, 1200, 1, 1200, true)
		b.OnPacketSent(now.Add(200*time.Microsecond), 1240, 100, 40, true)
		if lost {
			b.OnCongestionEventEx(1240, now.Add(500*time.Microsecond), nil, []congestion.LostPacketInfo{{PacketNumber: 100, BytesLost: 40}})
		} else {
			b.OnCongestionEventEx(1240, now.Add(500*time.Microsecond), []congestion.AckedPacketInfo{{PacketNumber: 100, BytesAcked: 40}}, nil)
		}
		require.NotNil(t, b.sampler.connectionStateMap.GetEntry(1))
		require.Nil(t, b.sampler.connectionStateMap.GetEntry(100))
		b.OnCongestionEventEx(1200, now.Add(5*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200}}, nil)
		want := congestion.ByteCount(1240)
		if lost {
			want = 1200
		}
		require.Equal(t, want, b.sampler.TotalBytesAcked())
		require.True(t, b.sampler.connectionStateMap.IsEmpty())
	}
}

func TestConservativeRetainsCruisePhases(t *testing.T) {
	b := NewBbrSender(DefaultClock{}, 1200, ProfileConservative)
	now := monotime.Now()
	b.minRtt = 8 * time.Millisecond
	b.maxBandwidth.Update(Bandwidth(100_000_000), 0)
	b.mode = bbrModeProbeBw
	b.cycleCurrentOffset = 0
	b.pacingGain = 1.25
	b.lastCycleStart = now
	b.bytesInFlight = b.getTargetCongestionWindow(1.5)
	var gains []float64
	for tick := 1; tick <= 8; tick++ {
		b.updateGainCyclePhase(now.Add(time.Duration(tick)*9*time.Millisecond), b.bytesInFlight, false)
		gains = append(gains, b.pacingGain)
	}
	require.Equal(t, []float64{.75, 1, 1, 1, 1, 1, 1, 1.25}, gains)
}

func TestSamplerPacketNumberSpanIsBounded(t *testing.T) {
	b := newBandwidthSampler(10)
	now := monotime.Now()
	b.OnPacketSent(now, 1, 1200, 0, true)
	b.OnPacketSent(now, 1<<30, 1200, 1200, true)
	require.LessOrEqual(t, b.connectionStateMap.EntrySlotsUsed(), 65536)
	require.NotNil(t, b.connectionStateMap.GetEntry(1<<30))
}

func TestWindowLimitedSendIsNotApplicationLimited(t *testing.T) {
	for _, probe := range []bool{false, true} {
		b, _ := newECNTestSender()
		if probe {
			b.mode = bbrModeProbeRtt
		}
		b.OnAppLimited()
		b.OnPacketSent(monotime.Now(), b.GetCongestionWindow(), 1, 1200, true)
		sample := b.sampler.connectionStateMap.GetEntry(1)
		require.NotNil(t, sample)
		require.Equal(t, probe, sample.sendTimeState.isAppLimited)
	}
}
