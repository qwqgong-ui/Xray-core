package bbr

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestAckOnlyDoesNotStarvePacing(t *testing.T) {
	b, _ := newECNTestSender()
	b.pacingRate = 8_000 // Receive-credit updates must progress on slow links too.
	now := monotime.Now()
	var number congestion.PacketNumber
	for b.HasPacingBudget(now) {
		number++
		b.OnPacketSent(now, congestion.ByteCount(number)*b.maxDatagramSize,
			number, b.maxDatagramSize, true)
	}
	nextSend := b.TimeUntilSend(0)
	for i := 1; i <= 100; i++ {
		number++
		b.OnPacketSent(now.Add(time.Duration(i)*20*time.Millisecond), 0, number, 60, false)
	}
	require.Equal(t, nextSend, b.TimeUntilSend(0), "unpaced ACKs must not postpone the next paced packet")
	require.True(t, b.HasPacingBudget(now.Add(2*time.Second)), "a data/control packet must regain send credit")
}
