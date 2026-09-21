package hybrid

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func sized(sizes ...int) [][]byte {
	ps := make([][]byte, len(sizes))
	for i, n := range sizes {
		ps[i] = make([]byte, n)
	}
	return ps
}

func TestGSORunBoundaries(t *testing.T) {
	cases := []struct {
		sizes []int
		from  int
		end   int
	}{
		{[]int{10}, 0, 1},
		{[]int{10, 10, 10}, 0, 3},
		{[]int{10, 10, 6, 10}, 0, 3}, // a short datagram ends its run
		{[]int{10, 12, 12}, 0, 1},    // a longer one cannot join
		{[]int{10, 12, 12}, 1, 3},
	}
	for _, c := range cases {
		if end := gsoRun(sized(c.sizes...), c.from); end != c.end {
			t.Errorf("gsoRun(%v, %d) = %d, want %d", c.sizes, c.from, end, c.end)
		}
	}
	many := make([]int, gsoSegments+6)
	for i := range many {
		many[i] = 100
	}
	if end := gsoRun(sized(many...), 0); end != gsoSegments {
		t.Errorf("run of %d equal datagrams ends at %d, want %d", len(many), end, gsoSegments)
	}
	big := []int{1400, 1400}
	for i := 0; i < 60; i++ {
		big = append(big, 1400)
	}
	if end := gsoRun(sized(big...), 0); end*1400 > gsoBytes {
		t.Errorf("run of %d x 1400 bytes exceeds %d", end, gsoBytes)
	}
}

// A batch leaves as whole datagrams in order, whether or not it went out as
// one segmented send.
func TestRawBatchKeepsEachDatagram(t *testing.T) {
	h := newHarness(t)
	const cid = "batchcid"
	h.bind(t, cid)
	if !h.server.gso.Load() {
		t.Log("socket has no UDP GSO; this exercises the one-by-one path")
	}
	var ps [][]byte
	for tag := byte(1); tag <= 5; tag++ {
		ps = append(ps, shortPacket(cid, tag))
	}
	ps = append(ps, shortPacket(cid[:3], 6))  // a shorter last segment
	ps = append(ps, shortPacket(cid+"xx", 7)) // longer: a run of its own
	tuple := netip.MustParseAddrPort(h.client.LocalAddr().String())
	if n, err := h.server.writeRaw(h.relay, tuple, ps); err != nil || n != len(ps) {
		t.Fatalf("sent %d of %d: %v", n, len(ps), err)
	}
	b := make([]byte, 64)
	for _, want := range ps {
		n, _, err := h.client.ReadFrom(b)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(b[:n], want) {
			t.Fatalf("received %x, want %x", b[:n], want)
		}
	}
}

// Packets the target returns together keep their order across the raw and
// stream paths.
func TestBatchSplitsBetweenRawAndStream(t *testing.T) {
	h := newHarness(t)
	const cid = "mixedcid"
	h.bind(t, cid)
	long := []byte{0xc0, 0, 0, 0, 1, 0, 0, 9} // long header, empty CIDs
	h.target.down <- shortPacket(cid, 1)
	h.target.down <- long
	h.target.down <- shortPacket(cid, 2)
	recvRaw(t, h.client, 1)
	h.recvFrame(t, 9)
	recvRaw(t, h.client, 2)
}

// Production shares a dual-stack [::]:443 socket and sends to IPv4 clients
// through v4-mapped addresses.
func TestRawBatchFromDualStackSocket(t *testing.T) {
	relay, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		t.Skipf("no dual-stack UDP: %v", err)
	}
	defer relay.Close()
	client := listen(t)
	s := NewServer(netip.MustParseAddrPort("192.0.2.1:443"))
	if err := s.Attach(relay); err != nil {
		t.Fatal(err)
	}
	var ps [][]byte
	for tag := byte(1); tag <= 8; tag++ {
		ps = append(ps, shortPacket("dualstack", tag))
	}
	tuple := netip.MustParseAddrPort(client.LocalAddr().String())
	if n, err := s.writeRaw(relay, tuple, ps); err != nil || n != len(ps) {
		t.Fatalf("sent %d of %d: %v (gso %v)", n, len(ps), err, s.gso.Load())
	}
	b := make([]byte, 64)
	client.SetReadDeadline(time.Now().Add(time.Second))
	for _, want := range ps {
		n, _, err := client.ReadFrom(b)
		if err != nil || !bytes.Equal(b[:n], want) {
			t.Fatalf("received %x, %v; want %x", b[:n], err, want)
		}
	}
}
