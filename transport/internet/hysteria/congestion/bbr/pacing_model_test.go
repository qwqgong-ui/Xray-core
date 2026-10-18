package bbr

import (
	"testing"
	"time"

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
