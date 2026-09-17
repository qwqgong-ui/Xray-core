package hysteria

import (
	"encoding/binary"
	"time"
)

const (
	// udpReorderHold bounds how long datagrams that overtook a missing one
	// wait for it. Swapped neighbours arrive well under a millisecond apart,
	// so only real loss waits this long.
	udpReorderHold = 2 * time.Millisecond
	// udpReorderWindow is the largest packet ID gap still treated as
	// reordering rather than loss or a restarted counter.
	udpReorderWindow = 32
	// udpReorderStreak is how many consecutive packet IDs a session must show
	// before anything is held. Senders that leave the ID at zero or randomise
	// it for fragments never get there and pass straight through.
	udpReorderStreak = 8
)

// udpReorder restores the sender's order of one UDP session's datagrams after
// the network swapped them. sing-quic clients such as mihomo number messages
// sequentially per session, and fragments of a message share its packet ID.
type udpReorder struct {
	started bool
	last    uint16
	streak  int
	pending []udpReorderDatagram

	timer *time.Timer
	gen   uint64
}

type udpReorderDatagram struct {
	id uint16
	d  []byte
}

// datagramPacketID returns the packet ID of a raw UDP message:
// session ID (4 bytes), packet ID (2), fragment ID (1), fragment count (1).
func datagramPacketID(d []byte) (uint16, bool) {
	if len(d) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint16(d[4:6]), true
}

// distance returns how far id lies ahead of the last released packet ID.
// sing-quic counts modulo 65535 and never sends 0xFFFF, so crossing the wrap
// does not count 0xFFFF as a gap.
func (r *udpReorder) distance(id uint16) uint16 {
	dist := id - r.last
	if id < r.last && r.last != 0xFFFF && dist > 1 {
		dist--
	}
	return dist
}

// push accepts a datagram and returns the datagrams that may be delivered now,
// in order. Datagrams that overtook a missing one stay pending until it
// arrives or flush is called.
func (r *udpReorder) push(id uint16, d []byte) [][]byte {
	if !r.started {
		r.started = true
		r.last = id
		return [][]byte{d}
	}
	switch dist := r.distance(id); {
	case dist == 0:
		// Another fragment of the last message, or a sender that does not
		// number its messages.
		return [][]byte{d}
	case dist == 1:
		r.last = id
		if r.streak < udpReorderStreak {
			r.streak++
		}
		return r.release([][]byte{d})
	case dist <= udpReorderWindow && r.streak >= udpReorderStreak:
		r.insert(id, dist, d)
		if len(r.pending) > 2*udpReorderWindow {
			return r.flush()
		}
		return nil
	case dist >= 1<<16-udpReorderWindow:
		// Arrived after its successors were already released.
		return [][]byte{d}
	default:
		// A gap too large to wait for, or a sender that does not number
		// messages sequentially.
		ready := append(r.flush(), d)
		r.last = id
		r.streak = 0
		return ready
	}
}

// insert keeps pending sorted by distance, preserving arrival order among
// fragments that share a packet ID.
func (r *udpReorder) insert(id uint16, dist uint16, d []byte) {
	i := len(r.pending)
	for i > 0 && r.distance(r.pending[i-1].id) > dist {
		i--
	}
	r.pending = append(r.pending, udpReorderDatagram{})
	copy(r.pending[i+1:], r.pending[i:])
	r.pending[i] = udpReorderDatagram{id: id, d: d}
}

// release appends the pending datagrams that now follow the last released
// packet ID without a gap.
func (r *udpReorder) release(ready [][]byte) [][]byte {
	n := 0
	for ; n < len(r.pending); n++ {
		p := r.pending[n]
		switch r.distance(p.id) {
		case 0:
		case 1:
			r.last = p.id
		default:
			r.drop(n)
			return ready
		}
		ready = append(ready, p.d)
	}
	r.drop(n)
	return ready
}

// flush releases every pending datagram in order, giving up on the gaps.
func (r *udpReorder) flush() [][]byte {
	if len(r.pending) == 0 {
		return nil
	}
	ready := make([][]byte, 0, len(r.pending))
	for _, p := range r.pending {
		ready = append(ready, p.d)
		r.last = p.id
	}
	r.drop(len(r.pending))
	return ready
}

func (r *udpReorder) drop(n int) {
	if n == 0 {
		return
	}
	rest := copy(r.pending, r.pending[n:])
	clear(r.pending[rest:])
	r.pending = r.pending[:rest]
}
