package hysteria

import (
	"encoding/binary"
	"testing"
	"time"
)

func reorderDatagram(session uint32, id uint16, frag, count, tag byte) []byte {
	d := make([]byte, 9)
	binary.BigEndian.PutUint32(d, session)
	binary.BigEndian.PutUint16(d[4:], id)
	d[6], d[7], d[8] = frag, count, tag
	return d
}

// pushIDs pushes one datagram per ID, tagged with its position, and returns
// the tags in delivery order.
func pushIDs(r *udpReorder, ids ...uint16) []byte {
	var tags []byte
	for i, id := range ids {
		for _, d := range r.push(id, reorderDatagram(1, id, 0, 1, byte(i))) {
			tags = append(tags, d[8])
		}
	}
	return tags
}

func warmUp(t *testing.T, r *udpReorder, last uint16) {
	t.Helper()
	ids := make([]uint16, 0, udpReorderStreak+1)
	for id := last - udpReorderStreak; id != last+1; id++ {
		ids = append(ids, id)
	}
	if got := pushIDs(r, ids...); len(got) != len(ids) {
		t.Fatalf("warm-up delivered %d of %d datagrams", len(got), len(ids))
	}
	if r.streak < udpReorderStreak {
		t.Fatalf("streak = %d after warm-up", r.streak)
	}
}

func equalTags(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestUDPReorderPassesOrderedStream(t *testing.T) {
	r := &udpReorder{}
	for id := uint16(1); id <= 200; id++ {
		got := r.push(id, reorderDatagram(1, id, 0, 1, 0))
		if len(got) != 1 || len(r.pending) != 0 {
			t.Fatalf("id %d: delivered %d, pending %d", id, len(got), len(r.pending))
		}
	}
}

func TestUDPReorderRestoresSwappedNeighbours(t *testing.T) {
	r := &udpReorder{}
	warmUp(t, r, 8)

	if got := r.push(10, reorderDatagram(1, 10, 0, 1, 10)); len(got) != 0 {
		t.Fatalf("datagram ahead of a gap delivered immediately: %v", got)
	}
	got := r.push(9, reorderDatagram(1, 9, 0, 1, 9))
	if len(got) != 2 || got[0][8] != 9 || got[1][8] != 10 {
		t.Fatalf("swapped pair not restored: %v", got)
	}
	if len(r.pending) != 0 {
		t.Fatalf("pending = %d after the gap filled", len(r.pending))
	}
	if got := r.push(11, reorderDatagram(1, 11, 0, 1, 11)); len(got) != 1 {
		t.Fatalf("next datagram held: %v", got)
	}
}

func TestUDPReorderFlushGivesUpOnLoss(t *testing.T) {
	r := &udpReorder{}
	warmUp(t, r, 8)

	r.push(10, reorderDatagram(1, 10, 0, 1, 10))
	r.push(12, reorderDatagram(1, 12, 0, 1, 12))
	got := r.flush()
	if len(got) != 2 || got[0][8] != 10 || got[1][8] != 12 {
		t.Fatalf("flush order: %v", got)
	}
	if r.last != 12 {
		t.Fatalf("last = %d after flush, want 12", r.last)
	}
	if got := r.push(13, reorderDatagram(1, 13, 0, 1, 13)); len(got) != 1 {
		t.Fatalf("datagram after flush held: %v", got)
	}
	if got := r.push(9, reorderDatagram(1, 9, 0, 1, 9)); len(got) != 1 {
		t.Fatalf("late datagram not delivered: %v", got)
	}
}

func TestUDPReorderPassesUnnumberedSenders(t *testing.T) {
	r := &udpReorder{}
	for i := range 100 {
		if got := r.push(0, reorderDatagram(1, 0, 0, 1, byte(i))); len(got) != 1 {
			t.Fatalf("zero packet ID %d held", i)
		}
	}

	r = &udpReorder{}
	// Random fragment IDs, as Xray and the official client use.
	for i, id := range []uint16{31337, 4242, 4244, 4243, 60001, 60003, 17, 19, 18, 900} {
		for frag := byte(0); frag < 2; frag++ {
			if got := r.push(id, reorderDatagram(1, id, frag, 2, byte(i))); len(got) != 1 {
				t.Fatalf("random packet ID %d held", id)
			}
		}
	}
}

func TestUDPReorderCrossesSingQUICWrap(t *testing.T) {
	r := &udpReorder{}
	warmUp(t, r, 0xFFFE)
	// sing-quic counts modulo 65535, so 0xFFFE is followed by 0.
	if got := pushIDs(r, 0, 1, 2); len(got) != 3 || len(r.pending) != 0 {
		t.Fatalf("wrap held datagrams: delivered %d, pending %d", len(got), len(r.pending))
	}

	r = &udpReorder{}
	warmUp(t, r, 0xFFFE)
	// A sender that uses the full range still wraps in order.
	if got := pushIDs(r, 0xFFFF, 0, 1); len(got) != 3 || len(r.pending) != 0 {
		t.Fatalf("full-range wrap held datagrams: delivered %d, pending %d", len(got), len(r.pending))
	}

	r = &udpReorder{}
	warmUp(t, r, 0xFFFD)
	// 0xFFFE missing, then 0 overtakes it across the wrap.
	if got := pushIDs(r, 0); len(got) != 0 {
		t.Fatalf("datagram across a gap at the wrap delivered: %v", got)
	}
	if got := pushIDs(r, 0xFFFE); !equalTags(got, []byte{0, 0}) {
		t.Fatalf("gap at the wrap not restored: %v", got)
	}
}

func TestUDPReorderKeepsFragmentsTogether(t *testing.T) {
	r := &udpReorder{}
	warmUp(t, r, 8)

	r.push(10, reorderDatagram(1, 10, 0, 2, 'a'))
	r.push(10, reorderDatagram(1, 10, 1, 2, 'b'))
	got := r.push(9, reorderDatagram(1, 9, 0, 1, '9'))
	var tags []byte
	for _, d := range got {
		tags = append(tags, d[8])
	}
	if !equalTags(tags, []byte("9ab")) {
		t.Fatalf("delivery order %q, want \"9ab\"", tags)
	}

	// A further fragment of the last message passes straight through.
	if got := r.push(10, reorderDatagram(1, 10, 1, 2, 'c')); len(got) != 1 {
		t.Fatalf("fragment of the last message held: %v", got)
	}
}

func TestUDPReorderLargeGapResetsStreak(t *testing.T) {
	r := &udpReorder{}
	warmUp(t, r, 8)

	r.push(10, reorderDatagram(1, 10, 0, 1, 10))
	got := r.push(8+udpReorderWindow+10, reorderDatagram(1, 8+udpReorderWindow+10, 0, 1, 99))
	if len(got) != 2 || got[0][8] != 10 || got[1][8] != 99 {
		t.Fatalf("large gap: %v", got)
	}
	if r.streak != 0 {
		t.Fatalf("streak = %d after a large gap", r.streak)
	}
	// Until the streak rebuilds, gaps pass straight through.
	next := uint16(8 + udpReorderWindow + 12)
	if got := r.push(next, reorderDatagram(1, next, 0, 1, 0)); len(got) != 1 {
		t.Fatalf("datagram held without a streak: %v", got)
	}
}

func TestUDPReorderBoundsPending(t *testing.T) {
	r := &udpReorder{}
	warmUp(t, r, 8)

	var delivered int
	for i := range 2*udpReorderWindow + 1 {
		delivered += len(r.push(10, reorderDatagram(1, 10, byte(i), 255, byte(i))))
	}
	if delivered != 2*udpReorderWindow+1 || len(r.pending) != 0 {
		t.Fatalf("overflow: delivered %d, pending %d", delivered, len(r.pending))
	}
}

func receiveTags(t *testing.T, ch chan []byte, n int, timeout time.Duration) []byte {
	t.Helper()
	var tags []byte
	deadline := time.After(timeout)
	for len(tags) < n {
		select {
		case d, ok := <-ch:
			if !ok {
				t.Fatal("session channel closed")
			}
			tags = append(tags, d[8])
		case <-deadline:
			t.Fatalf("received %v, want %d datagrams", tags, n)
		}
	}
	return tags
}

func TestUDPSessionManagerReordersAndFlushes(t *testing.T) {
	m := &udpSessionManager{m: make(map[uint32]*InterConn), reorderUDP: true}
	udpConn := &InterConn{id: 7, ch: make(chan []byte, 64), reorder: &udpReorder{}}
	m.m[udpConn.id] = udpConn

	// The first datagram only sets the starting ID.
	for id := uint16(1); id <= udpReorderStreak+1; id++ {
		m.feed(7, reorderDatagram(7, id, 0, 1, byte(id)))
	}
	m.feed(7, reorderDatagram(7, 11, 0, 1, 11))
	m.feed(7, reorderDatagram(7, 10, 0, 1, 10))
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	if got := receiveTags(t, udpConn.ch, len(want), time.Second); !equalTags(got, want) {
		t.Fatalf("delivery order %v, want %v", got, want)
	}

	// 12 is lost: 13 is released once the hold expires.
	start := time.Now()
	m.feed(7, reorderDatagram(7, 13, 0, 1, 13))
	if got := receiveTags(t, udpConn.ch, 1, time.Second); got[0] != 13 {
		t.Fatalf("flushed %v, want 13", got)
	}
	if waited := time.Since(start); waited < udpReorderHold {
		t.Fatalf("datagram released after %v, before the %v hold", waited, udpReorderHold)
	}
	m.feed(7, reorderDatagram(7, 14, 0, 1, 14))
	if got := receiveTags(t, udpConn.ch, 1, time.Second); got[0] != 14 {
		t.Fatalf("received %v, want 14", got)
	}
}

func TestUDPSessionManagerCloseStopsPendingFlush(t *testing.T) {
	m := &udpSessionManager{m: make(map[uint32]*InterConn), reorderUDP: true}
	udpConn := &InterConn{id: 7, ch: make(chan []byte, 64), reorder: &udpReorder{}}
	m.m[udpConn.id] = udpConn

	for id := uint16(1); id <= udpReorderStreak+1; id++ {
		m.feed(7, reorderDatagram(7, id, 0, 1, byte(id)))
	}
	m.feed(7, reorderDatagram(7, 11, 0, 1, 11))
	udpConn.reorderMutex.Lock()
	armed := udpConn.reorder.timer != nil
	udpConn.reorderMutex.Unlock()
	if !armed {
		t.Fatal("datagram ahead of a gap did not arm the flush timer")
	}

	m.Lock()
	m.close(udpConn)
	m.Unlock()

	// A flush after close would send on the closed channel and panic.
	time.Sleep(5 * udpReorderHold)
	udpConn.reorderMutex.Lock()
	defer udpConn.reorderMutex.Unlock()
	if udpConn.reorder.timer != nil || len(udpConn.reorder.pending) != 0 {
		t.Fatal("close left the reorder timer or pending datagrams behind")
	}
}
