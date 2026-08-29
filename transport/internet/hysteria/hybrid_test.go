package hysteria

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestHybridPacketConnRequiresExactRegistration(t *testing.T) {
	front, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	manager := newHybridManager(front)
	defer manager.close()
	wrapper := manager.wrap()

	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.WriteToUDP([]byte("unknown non-initial"), front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	unknown := []byte{0xc0, 0, 0, 0, 1}
	if _, err = client.WriteToUDP(unknown, front.LocalAddr().(*net.UDPAddr)); err != nil {
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

	target, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		packet := make([]byte, 1500)
		n, peer, readErr := target.ReadFromUDP(packet)
		if readErr == nil {
			_, _ = target.WriteToUDP(append([]byte("reply:"), packet[:n]...), peer)
		}
	}()

	session := &hybridSession{manager: manager, remote: netip.IPv6Loopback(), flows: make(map[[16]byte]*hybridFlow)}
	manager.mu.Lock()
	manager.sessions[session] = struct{}{}
	manager.mu.Unlock()
	var id [16]byte
	id[0] = 1
	clientAddr := client.LocalAddr().(*net.UDPAddr).AddrPort()
	targetAddr := target.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err = session.register(id, clientAddr, targetAddr); err != nil {
		t.Fatal(err)
	}

	raw := []byte("raw payload")
	if _, err = client.WriteToUDP(raw, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	// Keep quic-go's reader active: it consumes the registered tuple internally
	// and waits for another unregistered packet.
	readDone := make(chan struct{})
	_ = wrapper.SetReadDeadline(time.Time{})
	go func() {
		defer close(readDone)
		_, _, _ = wrapper.ReadFrom(make([]byte, 1500))
	}()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, peer, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if peer.String() != front.LocalAddr().String() || string(buffer[:n]) != "reply:raw payload" {
		t.Fatalf("unexpected raw reply %q from %v", buffer[:n], peer)
	}

	session.close()
	manager.mu.RLock()
	remaining := manager.flows[clientAddr]
	manager.mu.RUnlock()
	if remaining != nil {
		t.Fatal("session cleanup left raw tuple authorized")
	}
	afterClose := []byte{0xc0, 0, 0, 0, 1}
	if _, err = client.WriteToUDP(afterClose, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("session cleanup did not remove raw tuple authorization")
	}
}

func TestHybridControlRejectsUnsafeTargets(t *testing.T) {
	session := &hybridSession{remote: netip.MustParseAddr("2001:4860:4860::8888")}
	message := make([]byte, 43)
	copy(message[:4], hybridMagic)
	message[4] = hybridOpInitial
	message[22] = 1
	message[23] = 6
	copy(message[24:40], netip.IPv6Loopback().AsSlice())
	message[40], message[41] = 1, 187 // 443
	message[42] = 1
	if err := session.handle(message); err == nil {
		t.Fatal("loopback target was accepted")
	}
}
