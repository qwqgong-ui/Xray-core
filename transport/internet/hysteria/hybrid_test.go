package hysteria

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// longHeaderPacket builds the smallest packet longHeaderConnectionIDs accepts:
// a QUIC v1 long header carrying the two connection IDs in cleartext.
func longHeaderPacket(dcid, scid []byte, payload ...byte) []byte {
	packet := []byte{0xc0, 0, 0, 0, 1}
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	if len(payload) == 0 {
		payload = []byte{0x2a}
	}
	return append(packet, payload...)
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// newBoundableFlow builds a flow directly. register resolves and screens the
// target, which a loopback address deliberately cannot pass, so the tests that
// exercise binding construct the flow around a loopback target themselves.
func newBoundableFlow(t *testing.T, session *hybridSession, target *net.UDPConn) *hybridFlow {
	t.Helper()
	targetAddr := target.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp6", nil, targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	var id [16]byte
	id[0] = 1
	flow := &hybridFlow{
		session:  session,
		id:       id,
		target:   targetAddr.AddrPort(),
		conn:     conn,
		lastSeen: time.Now(),
	}
	session.mu.Lock()
	session.flows[id] = flow
	session.mu.Unlock()
	go flow.readTarget()
	return flow
}

func newTestSession(manager *hybridManager, remote netip.Addr) *hybridSession {
	session := &hybridSession{manager: manager, remote: remote, flows: make(map[[16]byte]*hybridFlow)}
	manager.mu.Lock()
	manager.sessions[session] = struct{}{}
	manager.mu.Unlock()
	return session
}

func TestHybridPacketConnRequiresExactRegistration(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()
	wrapper := manager.wrap()

	client := listenLoopback(t)
	if _, err := client.WriteToUDP([]byte("unknown non-initial"), front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	unknown := []byte{0xc0, 0, 0, 0, 1}
	if _, err := client.WriteToUDP(unknown, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1500)
	_ = wrapper.SetReadDeadline(time.Now().Add(time.Second))
	n, source, err := wrapper.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], unknown) || source.String() != client.LocalAddr().String() {
		t.Fatal("unknown tuple did not stay on the QUIC listener path")
	}

	target := listenLoopback(t)
	go func() {
		packet := make([]byte, 1500)
		count, peer, readErr := target.ReadFromUDP(packet)
		if readErr == nil {
			_, _ = target.WriteToUDP(append([]byte("reply:"), packet[:count]...), peer)
		}
	}()

	session := newTestSession(manager, netip.IPv6Loopback())
	flow := newBoundableFlow(t, session, target)
	dcid := []byte("connection-id-01")
	manager.claimCID(flow, string(dcid))

	readDone := make(chan struct{})
	_ = wrapper.SetReadDeadline(time.Time{})
	go func() {
		defer close(readDone)
		_, _, _ = wrapper.ReadFrom(make([]byte, 1500))
	}()

	// A long-header packet naming a claimed connection ID is what binds the raw
	// tuple; nothing was self-reported at registration time.
	raw := longHeaderPacket(dcid, nil, 'h', 'i')
	if _, err = client.WriteToUDP(raw, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, peer, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if peer.String() != front.LocalAddr().String() || !bytes.Equal(buffer[:n], append([]byte("reply:"), raw...)) {
		t.Fatalf("unexpected raw reply %q from %v", buffer[:n], peer)
	}

	clientAddr := client.LocalAddr().(*net.UDPAddr).AddrPort()
	manager.mu.RLock()
	bound := manager.flows[clientAddr]
	manager.mu.RUnlock()
	if bound != flow {
		t.Fatal("observed tuple was not bound to the flow")
	}

	session.close()
	manager.mu.RLock()
	remaining := manager.flows[clientAddr]
	remainingCID := manager.byCID[string(dcid)]
	manager.mu.RUnlock()
	if remaining != nil {
		t.Fatal("session cleanup left raw tuple authorized")
	}
	if remainingCID != nil {
		t.Fatal("session cleanup left connection id claimed")
	}
	if _, err = client.WriteToUDP([]byte{0xc0, 0, 0, 0, 1}, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("session cleanup did not remove raw tuple authorization")
	}
}

// A connection ID travels in cleartext on the raw path, so anyone on that path
// can read one and replay it. Binding must therefore stay inside the address
// the authenticated session was established from.
func TestHybridBindRejectsForeignAddress(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()

	target := listenLoopback(t)
	session := newTestSession(manager, netip.MustParseAddr("2001:db8::1"))
	flow := newBoundableFlow(t, session, target)
	dcid := []byte("connection-id-02")
	manager.claimCID(flow, string(dcid))

	foreign := netip.MustParseAddrPort("[2001:db8::2]:40000")
	if bound := manager.bind(foreign, longHeaderPacket(dcid, nil)); bound != nil {
		t.Fatal("a connection id replayed from another address was accepted")
	}
	manager.mu.RLock()
	registered := manager.flows[foreign]
	manager.mu.RUnlock()
	if registered != nil {
		t.Fatal("a rejected bind still registered the tuple")
	}
}

// A short header does not encode its DCID length, so it cannot identify a flow
// on its own. The first raw packet of a real flow is always long-header.
func TestHybridBindIgnoresShortHeader(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()

	target := listenLoopback(t)
	session := newTestSession(manager, netip.IPv6Loopback())
	flow := newBoundableFlow(t, session, target)
	dcid := []byte("connection-id-03")
	manager.claimCID(flow, string(dcid))

	shortHeader := append([]byte{0x40}, dcid...)
	client := netip.AddrPortFrom(netip.IPv6Loopback(), 40001)
	if bound := manager.bind(client, shortHeader); bound != nil {
		t.Fatal("a short header bound a flow")
	}
}

func TestHybridControlRejectsUnsafeTargets(t *testing.T) {
	session := &hybridSession{remote: netip.MustParseAddr("2001:4860:4860::8888"), flows: make(map[[16]byte]*hybridFlow)}
	message := make([]byte, 0, 64)
	message = append(message, hybridMagic...)
	message = append(message, hybridOpInitial)
	message = append(message, make([]byte, 16)...)
	message = append(message, hybridTargetIPv6)
	message = append(message, netip.IPv6Loopback().AsSlice()...)
	message = append(message, 1, 187) // 443
	message = append(message, 0x2a)
	if err := session.handle(message, nil); err == nil {
		t.Fatal("loopback target was accepted")
	}
}

func TestParseHybridInitialAcceptsDomain(t *testing.T) {
	name := "example.invalid"
	message := make([]byte, 0, 64)
	message = append(message, hybridMagic...)
	message = append(message, hybridOpInitial)
	message = append(message, make([]byte, 16)...)
	message = append(message, hybridTargetDomain, byte(len(name)))
	message = append(message, name...)
	message = append(message, 1, 187) // 443
	message = append(message, 'q', 'u', 'i', 'c')

	_, destination, payload, err := parseHybridInitial(message)
	if err != nil {
		t.Fatal(err)
	}
	if !destination.Address.Family().IsDomain() || destination.Address.Domain() != name {
		t.Fatalf("destination = %v, want the domain %q", destination, name)
	}
	if destination.Port != xnet.Port(443) {
		t.Fatalf("port = %v, want 443", destination.Port)
	}
	if string(payload) != "quic" {
		t.Fatalf("payload = %q, want %q", payload, "quic")
	}
}
