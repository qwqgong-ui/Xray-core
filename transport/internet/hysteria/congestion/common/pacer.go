package common

import (
	"math"
	"math/bits"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	maxBurstPackets               = 10
	maxBurstPacingDelayMultiplier = 4
)

// Pacer implements a token bucket pacing algorithm.
type Pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() congestion.ByteCount // in bytes/s
}

func NewPacer(getBandwidth func() congestion.ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * congestion.InitialPacketSize,
		maxDatagramSize:  congestion.InitialPacketSize,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime monotime.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = max(p.lastSentTime, sendTime)
}

func (p *Pacer) Budget(now monotime.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	burst := p.maxBurstSize()
	if now <= p.lastSentTime {
		return min(burst, p.budgetAtLastSent)
	}
	credit := MulDiv(uint64(max(1, p.getBandwidth())), uint64(now.Sub(p.lastSentTime)), uint64(time.Second))
	missing := max(0, burst-p.budgetAtLastSent)
	if credit >= uint64(missing) {
		return burst
	}
	return p.budgetAtLastSent + congestion.ByteCount(credit)
}

func (p *Pacer) maxBurstSize() congestion.ByteCount {
	return max(
		congestion.ByteCount(min(uint64(math.MaxInt64), MulDiv(uint64(max(1, p.getBandwidth())), uint64(maxBurstPacingDelayMultiplier*congestion.MinPacingDelay), uint64(time.Second)))),
		maxBurstPackets*p.maxDatagramSize,
	)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns the zero value if a packet can be sent immediately.
func (p *Pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := uint64(max(1, p.getBandwidth()))
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(congestion.MinPacingDelay, time.Duration(d)*time.Nanosecond))
}

// MulDiv calculates a*b/divisor without overflowing the intermediate product.
// Saturation also keeps pathological model samples from wrapping into a low rate.
func MulDiv(a, b, divisor uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if divisor == 0 || hi >= divisor {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, divisor)
	return q
}

func (p *Pacer) SetMaxDatagramSize(s congestion.ByteCount) {
	p.maxDatagramSize = s
}
