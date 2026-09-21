package hybrid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"golang.org/x/net/ipv4"
)

func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h3"},
	}
}

// sharedSetup wraps a socket that has one hybrid flow claiming cid, and
// returns the wrapped connection, a socket standing in for that client, and
// the flow's target.
func sharedSetup(t *testing.T, cid string) (net.PacketConn, net.PacketConn, *fakeTarget) {
	t.Helper()
	relay, client := listen(t), listen(t)
	addr := netip.MustParseAddrPort(relay.LocalAddr().String())
	s := NewServer(addr)
	if err := RegisterShared(addr, s); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { UnregisterShared(addr, s) })
	wrapped, err := WrapShared(relay)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if wrapped == net.PacketConn(relay) {
		t.Fatal("the socket was not wrapped, so nothing here proves anything")
	}

	peerSide, flowSide := net.Pipe()
	t.Cleanup(func() { peerSide.Close(); flowSide.Close() })
	target := &fakeTarget{up: make(chan []byte, 16), down: make(chan []byte, 16), done: make(chan struct{})}
	t.Cleanup(func() { target.Close() })
	_, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &flow{server: s, stream: flowSide, target: target, peer: netip.MustParseAddrPort(client.LocalAddr().String()).Addr(), cancel: cancel}
	s.flows[f] = struct{}{}
	s.claim(f, cid)
	return wrapped, client, target
}

// Hiding the socket's methods costs GSO, ECN and DF; providing them without a
// batch reader costs the raw path entirely. Both have to hold at once.
func TestWrapSharedKeepsOOBCapability(t *testing.T) {
	wrapped, _, _ := sharedSetup(t, "capsched")
	if _, ok := wrapped.(quic.OOBCapablePacketConn); !ok {
		t.Fatal("quic-go would drop to a plain connection: no GSO, no ECN, no DF")
	}
	if _, ok := wrapped.(interface {
		ReadBatch(ms []ipv4.Message, flags int) (int, error)
	}); !ok {
		t.Fatal("quic-go would build its own batch reader from the descriptor and bypass raw demultiplexing")
	}
}

// A socket with nothing extra to offer is still wrapped, just without them.
func TestWrapSharedAcceptsPlainPacketConn(t *testing.T) {
	pc := listen(t)
	addr := netip.MustParseAddrPort(pc.LocalAddr().String())
	s := NewServer(addr)
	if err := RegisterShared(addr, s); err != nil {
		t.Fatalf("register: %v", err)
	}
	defer UnregisterShared(addr, s)
	wrapped, err := WrapShared(plainConn{pc})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, ok := wrapped.(*sharedConn); !ok {
		t.Fatalf("wrapped a plain conn as %T", wrapped)
	}
}

type plainConn struct{ net.PacketConn }

func batchMessages(n int) []ipv4.Message {
	ms := make([]ipv4.Message, n)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 2048)}
		ms[i].OOB = make([]byte, 1024)
	}
	return ms
}

// ReadBatch is the path quic-go reads through, so the raw packets have to come
// out of it and the rest have to survive intact and in order.
func TestReadBatchTakesRawAndKeepsTheRest(t *testing.T) {
	const cid = "batchcid"
	wrapped, client, target := sharedSetup(t, cid)
	br := wrapped.(interface {
		ReadBatch(ms []ipv4.Message, flags int) (int, error)
	})

	// Raw first, last, and in between, so compaction has to move messages.
	for _, p := range [][]byte{
		shortPacket(cid, 1),
		append([]byte{0xc0, 0, 0, 0, 1, 0, 0}, 'A'),
		shortPacket(cid, 2),
		append([]byte{0xc0, 0, 0, 0, 1, 0, 0}, 'B'),
		shortPacket(cid, 3),
	} {
		if _, err := client.WriteTo(p, wrapped.LocalAddr()); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	var got []byte
	deadline := time.Now().Add(3 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		wrapped.SetReadDeadline(time.Now().Add(time.Second))
		ms := batchMessages(8)
		n, err := br.ReadBatch(ms, 0)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		for i := range n {
			b := ms[i].Buffers[0][:ms[i].N]
			if b[0] != 0xc0 {
				t.Fatalf("a raw packet reached the caller: %v", b)
			}
			got = append(got, b[len(b)-1])
		}
	}
	if string(got) != "AB" {
		t.Fatalf("ReadBatch returned %q, want the two QUIC packets in order", got)
	}

	for _, want := range []byte{1, 2, 3} {
		select {
		case p := <-target.up:
			if p[len(p)-1] != want {
				t.Fatalf("the flow's target received tag %d, want %d", p[len(p)-1], want)
			}
		case <-time.After(time.Second):
			t.Fatalf("raw packet %d never reached the flow's target", want)
		}
	}
}

// The whole path at once: a real QUIC connection over the wrapped socket while
// raw packets arrive alongside it.
func TestWrappedSocketCarriesQUICAndRawTogether(t *testing.T) {
	const cid = "livecid1"
	wrapped, client, target := sharedSetup(t, cid)

	tr := &quic.Transport{Conn: wrapped}
	defer tr.Close()
	ln, err := tr.Listen(selfSigned(t), &quic.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	accepted, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer accepted.CloseWithError(0, "")

	// Raw traffic alongside the live QUIC connection.
	if _, err = client.WriteTo(shortPacket(cid, 9), wrapped.LocalAddr()); err != nil {
		t.Fatalf("raw write: %v", err)
	}

	go func() {
		st, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return
		}
		st.Write([]byte("hello"))
		st.Close()
	}()
	st, err := accepted.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}
	b := make([]byte, 5)
	if _, err = io.ReadFull(st, b); err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if string(b) != "hello" {
		t.Fatalf("stream carried %q", b)
	}

	select {
	case p := <-target.up:
		if p[len(p)-1] != 9 {
			t.Fatalf("the flow's target received %v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the raw packet never reached the flow's target while QUIC was running")
	}
}
