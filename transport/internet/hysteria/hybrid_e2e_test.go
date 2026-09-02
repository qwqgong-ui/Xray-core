package hysteria

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type tunnelReply struct {
	payload []byte
	from    xnet.Destination
}

type recordingTunnel struct {
	mu      sync.Mutex
	replies []tunnelReply
}

func (r *recordingTunnel) send(payload []byte, from xnet.Destination) error {
	r.mu.Lock()
	r.replies = append(r.replies, tunnelReply{payload: append([]byte(nil), payload...), from: from})
	r.mu.Unlock()
	return nil
}

func (r *recordingTunnel) await(t *testing.T, count int) []tunnelReply {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		got := append([]tunnelReply(nil), r.replies...)
		r.mu.Unlock()
		if len(got) >= count {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tunnel carried %d replies, want %d", len(got), count)
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *recordingTunnel) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.replies)
}

// The relay must stay silent on the raw path until the client has spoken there.
// That ordering is what lets the client skip punching a hole, and it is the only
// reason the connection ID the target chose can reach the client at all: it
// travels in a reply the client has no raw path for yet.
func TestHybridRepliesMoveFromTunnelToRawOnBind(t *testing.T) {
	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()
	wrapper := manager.wrap()

	target := listenLoopback(t)
	tunnel := &recordingTunnel{}
	session := newTestSession(manager, netip.IPv6Loopback())
	session.send = tunnel.send
	flow := newBoundableFlow(t, session, target)

	dcid := []byte("connection-id-e2e")
	manager.claimCID(flow, string(dcid))

	// Before anything has identified a raw tuple, a reply from the target has
	// nowhere raw to go and must ride the tunnel, attributed to the target.
	scid := []byte("server-chosen-cid")
	early := longHeaderPacket(nil, scid, 'e', 'a', 'r', 'l', 'y')
	if _, err := target.WriteToUDP(early, flow.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	replies := tunnel.await(t, 1)
	if !bytes.Equal(replies[0].payload, early) {
		t.Fatalf("tunnel reply = %q, want %q", replies[0].payload, early)
	}
	if replies[0].from.Port != xnet.Port(flow.target.Port()) {
		t.Fatalf("tunnel reply was attributed to %v, want the target", replies[0].from)
	}

	// That reply is also what taught the relay the target's connection ID.
	manager.mu.RLock()
	claimed := manager.byCID[string(scid)]
	manager.mu.RUnlock()
	if claimed != flow {
		t.Fatal("the connection id the target chose was not claimed for the flow")
	}

	// wrapper.ReadFrom is the relay's own loop: it consumes packets belonging to
	// a flow and keeps waiting for one that does not. It is left running for the
	// rest of the test and unblocks when the cleanup closes the socket.
	go func() { _, _, _ = wrapper.ReadFrom(make([]byte, 2048)) }()

	// Now the client speaks on the raw path, naming a claimed connection ID.
	client := listenLoopback(t)
	raw := longHeaderPacket(dcid, nil, 'r', 'a', 'w')
	if _, err := client.WriteToUDP(raw, front.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	// The target sees the relayed packet and answers; that answer must now take
	// the raw path rather than the tunnel.
	buffer := make([]byte, 2048)
	_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, peer, err := target.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], raw) {
		t.Fatalf("target received %q, want %q", buffer[:n], raw)
	}
	before := tunnel.count()
	if _, err = target.WriteToUDP([]byte("bound reply"), peer); err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "bound reply" {
		t.Fatalf("raw reply = %q", buffer[:n])
	}
	if from.String() != front.LocalAddr().String() {
		t.Fatalf("raw reply came from %v, want the relay front", from)
	}
	if tunnel.count() != before {
		t.Fatal("a reply still went over the tunnel after the raw tuple was bound")
	}
}
