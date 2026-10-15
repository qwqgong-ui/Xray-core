package bbr

import "github.com/apernet/quic-go/monotime"

// This is a temporary limit on rate increases, not a bandwidth estimate.
// Empty application queues and a completed drain must not immediately restore
// STARTUP's multiplier. Normal probing can regain its rate without a fixed cap.
type pacingRateGuard struct {
	rate         Bandwidth
	lastIncrease monotime.Time
}

func (b *bbrSender) limitIdleRestart() {
	bw := b.bandwidthEstimate()
	// A sparse readiness sample must not constrain a new, unsaturated path.
	if bw == 0 || bw < BandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt()) {
		return
	}
	rate := min(b.PacingRate(), bw)
	if b.rateGuard.rate == 0 || rate < b.rateGuard.rate {
		b.rateGuard.rate = rate
	}
}

func (b *bbrSender) limitPacingRateIncrease(now monotime.Time, roundStart bool) {
	g := &b.rateGuard
	rate := b.pacingRate
	if rate == 0 {
		return
	}
	if b.queueGuard.active || b.InRecovery() || b.mode == bbrModeDrain || b.mode == bbrModeProbeRtt {
		if g.rate == 0 || rate < g.rate {
			g.rate = rate
		}
		g.lastIncrease = max(g.lastIncrease, now)
		return
	}
	if g.rate == 0 {
		return
	}
	g.rate = min(g.rate, rate)
	// Packet rounds can advance quickly on compressed ACKs. Wall-clock RTT
	// spacing also matters; unused idle time is never accumulated as credit.
	if g.lastIncrease.IsZero() || !roundStart || now.Sub(g.lastIncrease) < b.getMinRtt() {
		return
	}
	step := max(Bandwidth(1), g.rate/4)
	if step >= rate-g.rate {
		*g = pacingRateGuard{}
	} else {
		g.rate += step // less than target: addition cannot overflow
		g.lastIncrease = now
	}
}
