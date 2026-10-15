package bbr

import (
	"github.com/apernet/quic-go/congestion"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestECNSmallLossCallbacksAccumulateIntoRecovery(t *testing.T) {
	b, _ := newECNTestSender()
	confirmZeroCE(b)
	b.isAtFullBandwidth = true
	b.congestionWindow = 100_000
	now := b.clock.Now()
	for i := 1; i <= 100; i++ {
		b.OnPacketSent(now, b.bytesInFlight, congestion.PacketNumber(i), 1000, true)
	}
	for i := 1; i <= 10; i++ {
		prior := b.bytesInFlight
		b.OnCongestionEventEx(prior, now.Add(time.Duration(i)*time.Millisecond), nil, []congestion.LostPacketInfo{{PacketNumber: congestion.PacketNumber(i), BytesLost: 1000}})
	}
	require.GreaterOrEqual(t, b.bytesLostInRound, congestion.ByteCount(10_000))
	require.True(t, b.InRecovery(), "ten small loss callbacks must not bypass zero-CE loss safety")
}
