package common

import (
	"math"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestPacerFutureTimeDoesNotCreateBudget(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 1200 })
	p.SetMaxDatagramSize(1200)
	now := monotime.Now()
	p.SentPacket(now.Add(time.Second), 12000)
	require.Zero(t, p.Budget(now))
	require.Zero(t, p.Budget(now.Add(time.Second)))
	require.Equal(t, congestion.ByteCount(1200), p.Budget(now.Add(2*time.Second)))
	require.Equal(t, now.Add(2*time.Second), p.TimeUntilSend())
}

func TestPacerLargeRateAndIdleDoNotOverflow(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 1_000_000_000 })
	now := monotime.Now()
	p.SentPacket(now, p.Budget(now))
	require.Positive(t, p.Budget(now.Add(time.Hour)))
	require.Equal(t, p.maxBurstSize(), p.Budget(now.Add(time.Hour)))
	require.Equal(t, uint64(math.MaxUint64), MulDiv(math.MaxUint64, math.MaxUint64, 1))
}

func TestPacerZeroRateCannotDivideByZero(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 0 })
	now := monotime.Now()
	p.SentPacket(now, p.Budget(now))
	require.True(t, p.TimeUntilSend().After(now))
}
