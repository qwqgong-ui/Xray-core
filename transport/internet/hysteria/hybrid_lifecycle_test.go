package hysteria

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// stubLink stands in for a flow's target side, so these tests exercise the
// registration path without a socket or a name to resolve.
type stubLink struct {
	mutex   sync.Mutex
	written [][]byte
	closed  bool
	replies chan []byte
}

func newStubLink() *stubLink {
	return &stubLink{replies: make(chan []byte, 8)}
}

func (l *stubLink) WritePacket(payload []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	l.written = append(l.written, append([]byte(nil), payload...))
	return nil
}

func (l *stubLink) ReadPacket() ([]byte, error) {
	payload, ok := <-l.replies
	if !ok {
		return nil, io.EOF
	}
	return payload, nil
}

func (l *stubLink) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if !l.closed {
		l.closed = true
		close(l.replies)
	}
	return nil
}

func (l *stubLink) packets() [][]byte {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return append([][]byte(nil), l.written...)
}

func (l *stubLink) isClosed() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.closed
}

// hybridInitialMessage builds an op=1 registration for a literal IPv6 target.
func hybridInitialMessage(id byte, target netip.Addr, payload string) []byte {
	message := make([]byte, 0, 64)
	message = append(message, hybridMagic...)
	message = append(message, hybridOpInitial)
	flowID := make([]byte, 16)
	flowID[0] = id
	message = append(message, flowID...)
	address := target.As16()
	message = append(message, hybridTargetIPv6)
	message = append(message, address[:]...)
	message = binary.BigEndian.AppendUint16(message, 443)
	return append(message, payload...)
}

func hybridRelayMessage(id byte, payload string) []byte {
	message := make([]byte, 0, 64)
	message = append(message, hybridMagic...)
	message = append(message, hybridOpRelay)
	flowID := make([]byte, 16)
	flowID[0] = id
	message = append(message, flowID...)
	return append(message, payload...)
}

// A client whose tuple changes -- a NAT mapping that expired, a phone that
// moved networks -- keeps sending 1-RTT packets addressed to the connection ID
// this server handed out. quic-go supports that migration natively, so the
// relay has to let those packets reach it rather than dropping them as unknown
// traffic; everything else from a tuple nobody knows still stops here.
func TestHybridMigratedTupleReachesQUIC(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()
	wrapper := manager.wrap()

	// The handshake this server wrote is where the connection ID is learned.
	original := listenLoopback(t)
	serverCID := []byte("server-chosen-id")
	handshake := longHeaderPacket([]byte("client-chosen-id"), serverCID, 'h', 's')
	if _, err := wrapper.WriteTo(handshake, original.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	stranger := listenLoopback(t)
	// Nothing identifies this one, so it must not reach the QUIC listener.
	unknown := shortHeaderPacket([]byte("some-other-id-01"), 'n', 'o')
	if _, err := stranger.WriteToUDP(unknown, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	// This one names the connection, from a tuple the server has never seen.
	migrated := shortHeaderPacket(serverCID, 'm', 'i', 'g')
	if _, err := stranger.WriteToUDP(migrated, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 2048)
	_ = wrapper.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, source, err := wrapper.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], migrated) {
		t.Fatalf("the QUIC listener was handed %q, want the migrated packet", buffer[:n])
	}
	if source.String() != stranger.LocalAddr().String() {
		t.Fatalf("packet came from %v, want %v", source, stranger.LocalAddr())
	}

	// Having proved itself once, the tuple is authorized outright, so the
	// connection keeps working after quic-go rotates to an ID issued under
	// encryption that this side never sees.
	rotated := shortHeaderPacket([]byte("rotated-id-later"), 'o', 'k')
	if _, err = stranger.WriteToUDP(rotated, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = wrapper.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = wrapper.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], rotated) {
		t.Fatalf("the QUIC listener was handed %q, want the rotated packet", buffer[:n])
	}
}

// A flow that never leaves the tunnel lives only in its session's table. The
// idle sweep used to walk the manager's tuple table, which holds bound flows
// alone, so an unbound one kept its link and its goroutine for the whole life
// of the tunnel.
func TestHybridSweepReclaimsUnboundFlows(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()

	session := newTestSession(manager, netip.MustParseAddr("2001:db8::1"))
	link := newStubLink()
	flow := &hybridFlow{
		session:  session,
		id:       [16]byte{1},
		link:     link,
		ready:    true,
		lastSeen: time.Now().Add(-hybridFlowTTL - time.Minute),
	}
	session.mu.Lock()
	session.flows[flow.id] = flow
	session.mu.Unlock()

	manager.sweep(time.Now())

	if !link.isClosed() {
		t.Fatal("an idle unbound flow kept its link open")
	}
	session.mu.Lock()
	remaining := len(session.flows)
	session.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("the session still holds %d flows", remaining)
	}
}

// A bound flow is carrying a live connection on the raw path, and reclaiming it
// black-holes that connection until QUIC gives up. It is held far longer than
// the gap an application leaves between requests.
func TestHybridSweepKeepsIdleBoundFlows(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()

	session := newTestSession(manager, netip.MustParseAddr("2001:db8::1"))
	link := newStubLink()
	flow := &hybridFlow{
		session:  session,
		id:       [16]byte{2},
		link:     link,
		ready:    true,
		bound:    true,
		client:   netip.MustParseAddrPort("[2001:db8::1]:40000"),
		lastSeen: time.Now().Add(-hybridFlowTTL - time.Minute),
	}
	session.mu.Lock()
	session.flows[flow.id] = flow
	session.mu.Unlock()

	manager.sweep(time.Now())
	if link.isClosed() {
		t.Fatal("a bound flow was reclaimed at the unbound flow's timeout")
	}

	// It is still reclaimed once it has been idle for its own, much longer,
	// timeout: nothing is leaked, it is only held long enough to outlast an
	// application's idle gap.
	manager.sweep(time.Now().Add(hybridBoundFlowTTL + time.Minute))
	if !link.isClosed() {
		t.Fatal("a bound flow was never reclaimed")
	}
}

// Each flow costs a link and a goroutine, so one authenticated session cannot
// open them without limit.
func TestHybridSessionFlowLimit(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()

	session := newTestSession(manager, netip.MustParseAddr("2001:db8::1"))
	defer session.close()
	target := netip.MustParseAddr("2001:db8::2")
	dial := func(xnet.Destination) (HybridTargetLink, error) { return newStubLink(), nil }

	for i := 0; i < hybridMaxSessionFlows; i++ {
		var id [16]byte
		binary.BigEndian.PutUint16(id[:2], uint16(i))
		if _, _, err := session.register(id, xnet.UDPDestination(xnet.IPAddress(target.AsSlice()), 443), nil, dial); err != nil {
			t.Fatalf("registration %d was refused: %v", i, err)
		}
	}
	var extra [16]byte
	binary.BigEndian.PutUint16(extra[:2], uint16(hybridMaxSessionFlows))
	if _, _, err := session.register(extra, xnet.UDPDestination(xnet.IPAddress(target.AsSlice()), 443), nil, dial); err == nil {
		t.Fatal("a session registered more flows than its limit allows")
	}
}

// Resolving a name and opening the target side both block, and the control loop
// they run on is shared by every flow of the link. A registration must hand
// that work to a goroutine and hold what arrives meanwhile, or one slow lookup
// stalls the handshake of every other connection on the tunnel.
func TestHybridRegistrationDoesNotBlockTheControlLoop(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()

	session := newTestSession(manager, netip.MustParseAddr("2001:db8::1"))
	defer session.close()

	link := newStubLink()
	release := make(chan struct{})
	dialed := make(chan xnet.Destination, 1)
	dial := func(destination xnet.Destination) (HybridTargetLink, error) {
		dialed <- destination
		<-release
		return link, nil
	}

	tunnel := &recordingTunnel{}
	target := netip.MustParseAddr("2001:db8::2")

	done := make(chan error, 1)
	go func() {
		done <- session.handle(hybridInitialMessage(7, target, "initial"), tunnel.send, dial)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the registration held the control loop while the target was dialled")
	}

	// The loop is free, so the next packet of the same flow is accepted too --
	// and held, since the flow has nowhere to put it yet.
	if err := session.handle(hybridRelayMessage(7, "second"), tunnel.send, dial); err != nil {
		t.Fatal(err)
	}
	if written := link.packets(); len(written) != 0 {
		t.Fatalf("the link received %d packets before it was open", len(written))
	}

	select {
	case destination := <-dialed:
		if destination.Address.IP().String() != target.String() {
			t.Fatalf("dialled %v, want %v", destination, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the target was never dialled")
	}
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for {
		written := link.packets()
		if len(written) == 2 {
			if string(written[0]) != "initial" || string(written[1]) != "second" {
				t.Fatalf("the link received %q, want the buffered packets in order", written)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the link received %q, want both buffered packets", written)
		}
		time.Sleep(time.Millisecond)
	}

	// The acknowledgement carries the address the server opened the flow to,
	// which is the only way a client that registered a name can label the
	// replies arriving on the raw path.
	replies := tunnel.await(t, 1)
	ack := replies[0].payload
	if len(ack) < 22 || string(ack[:4]) != hybridMagic || ack[4] != hybridOpAck {
		t.Fatalf("the tunnel carried %q, want an acknowledgement", ack)
	}
	if ack[21] != hybridAckOK {
		t.Fatal("the registration was not acknowledged as successful")
	}
	if ack[22] != hybridTargetIPv6 || !bytes.Equal(ack[23:39], target.AsSlice()) {
		t.Fatalf("the acknowledgement named %v, want %v", ack[23:39], target)
	}
}

// One id may not be re-registered against a different destination. The port is
// always 443, so comparing it alone let a repeat silently keep the first flow.
func TestHybridFlowIDCollisionIsRefused(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()

	session := newTestSession(manager, netip.MustParseAddr("2001:db8::1"))
	defer session.close()
	dial := func(xnet.Destination) (HybridTargetLink, error) { return newStubLink(), nil }

	first := xnet.UDPDestination(xnet.IPAddress(netip.MustParseAddr("2001:db8::2").AsSlice()), 443)
	second := xnet.UDPDestination(xnet.IPAddress(netip.MustParseAddr("2001:db8::3").AsSlice()), 443)
	id := [16]byte{9}
	if _, _, err := session.register(id, first, nil, dial); err != nil {
		t.Fatal(err)
	}
	if _, _, err := session.register(id, first, nil, dial); err != nil {
		t.Fatalf("a repeat of the same registration was refused: %v", err)
	}
	if _, _, err := session.register(id, second, nil, dial); err == nil {
		t.Fatal("one id was accepted for two destinations")
	}
}
