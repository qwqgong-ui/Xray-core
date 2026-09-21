package freedom

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// plainPacketConn hides *net.UDPConn, so a reader takes the one-datagram path.
type plainPacketConn struct{ net.PacketConn }

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newTestReader(t *testing.T, conn net.PacketConn, peer *net.UDPConn, h *Handler) *PacketReader {
	t.Helper()
	dest := net.DestinationFromAddr(peer.LocalAddr())
	wrapper := &internet.PacketConnWrapper{PacketConn: conn, Dest: peer.LocalAddr()}
	r, ok := NewPacketReader(wrapper, h, nil, net.UDPDestination(nil, 0), dest).(*PacketReader)
	if !ok {
		t.Fatal("not a freedom PacketReader")
	}
	return r
}

func send(t *testing.T, from *net.UDPConn, to net.Addr, p []byte) {
	t.Helper()
	if _, err := from.WriteTo(p, to); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// read collects n datagrams, however many reads that takes.
func read(t *testing.T, r *PacketReader, n int) (buf.MultiBuffer, int) {
	t.Helper()
	var all buf.MultiBuffer
	reads := 0
	for len(all) < n {
		mb, err := r.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		reads++
		all = append(all, mb...)
	}
	return all, reads
}

func TestPacketReaderReturnsQueuedDatagramsTogether(t *testing.T) {
	t.Run("udp4", func(t *testing.T) { testQueuedDatagrams(t, listenUDP(t)) })
	t.Run("dual-stack", func(t *testing.T) {
		// Freedom's own sockets are [::] and receive IPv4 as v4-mapped.
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::")})
		if err != nil {
			t.Skipf("no dual-stack UDP: %v", err)
		}
		defer c.Close()
		testQueuedDatagrams(t, c)
	})
}

func testQueuedDatagrams(t *testing.T, local *net.UDPConn) {
	peer := listenUDP(t)
	r := newTestReader(t, local, peer, &Handler{})
	to := &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: local.LocalAddr().(*net.UDPAddr).Port}
	if r.batch == nil {
		t.Fatal("a plain UDP socket should read in batches")
	}
	want := [][]byte{[]byte("one"), bytes.Repeat([]byte{7}, 1400), []byte("three"), {}, []byte("five")}
	for _, p := range want {
		send(t, peer, to, p)
	}
	got, reads := read(t, r, len(want))
	defer buf.ReleaseMulti(got)
	if runtime.GOOS == "linux" && reads != 1 {
		t.Errorf("took %d reads for datagrams that were all queued", reads)
	}
	for i, b := range got {
		if !bytes.Equal(b.Bytes(), want[i]) {
			t.Fatalf("datagram %d is %q, want %q", i, b.Bytes(), want[i])
		}
		if b.UDP == nil || b.UDP.Port != net.Port(peer.LocalAddr().(*net.UDPAddr).Port) || !b.UDP.Address.Family().IsIPv4() {
			t.Fatalf("datagram %d has source %v", i, b.UDP)
		}
	}
}

// A buffer kept after a blocked datagram still holds its old bytes; the next
// datagram read into it must come out as exactly itself.
func TestPacketReaderReusesBlockedBuffers(t *testing.T) {
	for _, plain := range []bool{false, true} {
		local, peer, blocked := listenUDP(t), listenUDP(t), listenUDP(t)
		rule := &FinalRule{action: RuleAction_Block, port: net.MemoryPortList{{
			From: net.Port(blocked.LocalAddr().(*net.UDPAddr).Port),
			To:   net.Port(blocked.LocalAddr().(*net.UDPAddr).Port),
		}}}
		rule.network[net.Network_UDP] = true
		h := &Handler{finalRules: []*FinalRule{rule}}
		var conn net.PacketConn = local
		if plain {
			conn = plainPacketConn{local}
		}
		r := newTestReader(t, conn, peer, h)

		send(t, blocked, local.LocalAddr(), bytes.Repeat([]byte{0xaa}, 1000))
		send(t, peer, local.LocalAddr(), []byte("abc"))
		got, _ := read(t, r, 1)
		if len(got) != 1 || string(got[0].Bytes()) != "abc" {
			t.Fatalf("plain=%v: got %d datagrams, first %q", plain, len(got), got[0].Bytes())
		}
		buf.ReleaseMulti(got)

		send(t, peer, local.LocalAddr(), []byte("de"))
		got, _ = read(t, r, 1)
		if string(got[0].Bytes()) != "de" {
			t.Fatalf("plain=%v: reused buffer yielded %q", plain, got[0].Bytes())
		}
		buf.ReleaseMulti(got)
	}
}
