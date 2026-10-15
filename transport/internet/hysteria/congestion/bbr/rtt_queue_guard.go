package bbr

import (
	"github.com/apernet/quic-go/congestion"
	"time"
)

type rttQueueGuard struct {
	active     bool
	highRounds uint8
	rate       Bandwidth
	window     congestion.ByteCount
}

// The latency guard is independent of ECN and the OS pacing backend. It is
// applied last, so ECN floors cannot restore a rate while a queue is draining.
// Require sustained excess delay, or a severe spike, and use a lower exit
// threshold to keep ordinary RTT variation from toggling the controller.
func (b *bbrSender) applyRTTQueueGuard(roundStart bool) {
	if b.rttStats == nil || b.bandwidthEstimate() == 0 {
		return
	}
	base, latest := b.getMinRtt(), b.rttStats.LatestRTT()
	if base <= 0 || latest <= 0 {
		return
	}
	budget := min(5*time.Millisecond, max(2*time.Millisecond, base/8))
	g := &b.queueGuard
	if latest <= base+budget {
		*g = rttQueueGuard{}
		return
	}
	if latest > base+2*budget {
		if roundStart && g.highRounds < 2 {
			g.highRounds++
		}
		if g.highRounds >= 2 || latest > base+max(base, 4*budget) {
			g.active = true
		}
	} else if !g.active {
		g.highRounds = 0
	}
	if !g.active {
		return
	}
	rate := scaleBandwidth(b.bandwidthEstimate(), 0.75)
	window := b.getTargetCongestionWindow(1)
	if g.rate != 0 {
		previousRate, previousWindow := g.rate, g.window
		if roundStart {
			previousRate = scaleBandwidth(previousRate, 0.85)
			previousWindow = scaleWindow(previousWindow, 0.85)
		}
		rate = min(rate, previousRate)
		window = min(window, previousWindow)
	}
	if rate != 0 {
		b.pacingRate = min(b.pacingRate, rate)
	}
	b.congestionWindow = max(b.minCongestionWindow, min(b.congestionWindow, window))
	g.rate, g.window = b.pacingRate, b.congestionWindow
}
