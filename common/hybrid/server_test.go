package hybrid

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeTarget struct {
	up   chan []byte
	down chan []byte
	done chan struct{}
	once sync.Once
}

func (t *fakeTarget) WritePacket(p []byte) error {
	select {
	case t.up <- append([]byte(nil), p...):
		return nil
	case <-t.done:
		return net.ErrClosed
	}
}

func (t *fakeTarget) ReadPacket() ([]byte, error) {
	select {
	case p := <-t.down:
		return p, nil
	case <-t.done:
		return nil, io.EOF
	}
}

func (t *fakeTarget) Close() error {
	t.once.Do(func() { close(t.done) })
	return nil
}

// shortPacket is a 1-RTT packet whose destination connection ID is cid, ending
// in a tag so a test can tell one packet from the next.
func shortPacket(cid string, tag byte) []byte {
	p := make([]byte, 1+len(cid)+1)
	p[0] = 0x40
	copy(p[1:], cid)
	p[len(p)-1] = tag
	return p
}

// harness drives one flow's raw path without a stream handshake: relay is the
// terminal's shared raw socket and client stands in for the client's.
type harness struct {
	server *Server
	flow   *flow
	target *fakeTarget
	relay  net.PacketConn
	client net.PacketConn
	frames chan []byte
}

func listen(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	relay, client := listen(t), listen(t)
	s := NewServer(netip.MustParseAddrPort(relay.LocalAddr().String()))
	if err := s.Attach(relay); err != nil {
		t.Fatalf("attach: %v", err)
	}
	peerSide, flowSide := net.Pipe()
	target := &fakeTarget{up: make(chan []byte, 16), down: make(chan []byte, 16), done: make(chan struct{})}
	_, cancel := context.WithCancel(context.Background())
	f := &flow{server: s, stream: flowSide, target: target, peer: netip.MustParseAddrPort(client.LocalAddr().String()).Addr(), cancel: cancel}
	s.flows[f] = struct{}{}
	h := &harness{server: s, flow: f, target: target, relay: relay, client: client, frames: make(chan []byte, 16)}
	go func() {
		for {
			p, err := ReadFrame(peerSide)
			if err != nil {
				return
			}
			if p != nil {
				h.frames <- p
			}
		}
	}()
	go f.readTarget()
	t.Cleanup(func() {
		target.Close()
		peerSide.Close()
	})
	return h
}

// bind performs the first raw packet, which claims the CID's binding.
func (h *harness) bind(t *testing.T, cid string) {
	t.Helper()
	h.server.claim(h.flow, cid)
	if !h.server.HandleRaw(shortPacket(cid, 0), h.client.LocalAddr()) {
		t.Fatal("the first raw packet did not bind the flow")
	}
	h.recvTarget(t, 0)
}

func (h *harness) recvTarget(t *testing.T, tag byte) {
	t.Helper()
	select {
	case p := <-h.target.up:
		if p[len(p)-1] != tag {
			t.Fatalf("target received tag %d, want %d", p[len(p)-1], tag)
		}
	case <-time.After(time.Second):
		t.Fatalf("target never received tag %d", tag)
	}
}

func (h *harness) recvFrame(t *testing.T, tag byte) {
	t.Helper()
	select {
	case p := <-h.frames:
		if p[len(p)-1] != tag {
			t.Fatalf("stream carried tag %d, want %d", p[len(p)-1], tag)
		}
	case <-time.After(time.Second):
		t.Fatalf("the stream never carried tag %d", tag)
	}
}

func recvRaw(t *testing.T, c net.PacketConn, tag byte) {
	t.Helper()
	b := make([]byte, 64)
	c.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := c.ReadFrom(b)
	if err != nil {
		t.Fatalf("raw never carried tag %d: %v", tag, err)
	}
	if b[n-1] != tag {
		t.Fatalf("raw carried tag %d, want %d", b[n-1], tag)
	}
}

func (h *harness) expectNoRaw(t *testing.T) {
	t.Helper()
	b := make([]byte, 64)
	h.client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := h.client.ReadFrom(b); err == nil {
		t.Fatalf("raw carried %v while it should not have", b[:n])
	}
}

func (h *harness) age(d time.Duration) {
	h.server.mu.Lock()
	h.flow.lastRaw = time.Now().Add(-d)
	h.server.mu.Unlock()
}

func TestRawBindingPausesAndResumes(t *testing.T) {
	h := newHarness(t)
	const cid = "abcdefgh"
	h.bind(t, cid)

	h.target.down <- shortPacket(cid, 1)
	recvRaw(t, h.client, 1)

	// A zero-length frame from the client reaches this, and it is a pause:
	// the binding and the claimed CIDs stay.
	h.flow.pause()
	h.target.down <- shortPacket(cid, 2)
	h.recvFrame(t, 2)
	h.expectNoRaw(t)

	// The client's next raw packet resumes raw in both directions.
	if !h.server.HandleRaw(shortPacket(cid, 3), h.client.LocalAddr()) {
		t.Fatal("raw after a pause was dropped")
	}
	h.recvTarget(t, 3)
	h.target.down <- shortPacket(cid, 4)
	recvRaw(t, h.client, 4)
}

func TestStaleBindingAnswersOnTheStream(t *testing.T) {
	h := newHarness(t)
	const cid = "ijklmnop"
	h.bind(t, cid)

	h.age(2 * rawStale)
	h.target.down <- shortPacket(cid, 1)
	h.recvFrame(t, 1)
	h.expectNoRaw(t)

	// A raw packet from the client makes the binding current again.
	if !h.server.HandleRaw(shortPacket(cid, 2), h.client.LocalAddr()) {
		t.Fatal("raw on a stale binding was dropped")
	}
	h.recvTarget(t, 2)
	h.target.down <- shortPacket(cid, 3)
	recvRaw(t, h.client, 3)
}

func TestBindingGivesWayOnlyWhenStale(t *testing.T) {
	h := newHarness(t)
	const cid = "qrstuvwx"
	h.bind(t, cid)
	moved := listen(t)

	// A live binding is not a NAT remapping the client.
	if h.server.HandleRaw(shortPacket(cid, 1), moved.LocalAddr()) {
		t.Fatal("a live binding gave way to another port")
	}

	h.age(2 * rawStale)
	if !h.server.HandleRaw(shortPacket(cid, 2), moved.LocalAddr()) {
		t.Fatal("a stale binding did not give way")
	}
	h.recvTarget(t, 2)
	h.server.mu.Lock()
	tuple, old := h.flow.tuple.String(), h.server.tuples[netip.MustParseAddrPort(h.client.LocalAddr().String())]
	h.server.mu.Unlock()
	if tuple != moved.LocalAddr().String() || old != nil {
		t.Fatalf("tuple %s, stale entry %v", tuple, old)
	}
	h.target.down <- shortPacket(cid, 3)
	recvRaw(t, moved, 3)
	h.expectNoRaw(t)
}

func TestServerDisableStaysPermanent(t *testing.T) {
	h := newHarness(t)
	const cid = "yzabcdef"
	h.bind(t, cid)

	// The terminal's own failure is not recoverable by the client.
	h.flow.disable()
	if h.server.HandleRaw(shortPacket(cid, 1), h.client.LocalAddr()) {
		t.Fatal("a disabled flow took raw again")
	}
	h.target.down <- shortPacket(cid, 2)
	h.recvFrame(t, 2)
	h.expectNoRaw(t)
}
