package hybrid

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLeaseZeroCIDBindingAndRenewal(t *testing.T) {
	relay, client, stranger := listen(t), listen(t), listen(t)
	s := NewServer(netip.MustParseAddrPort("8.8.8.8:443"))
	if err := s.Attach(relay); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, b := net.Pipe()
	defer a.Close()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	target := &fakeTarget{up: make(chan []byte, 16), down: make(chan []byte, 16), done: make(chan struct{})}
	go s.Serve(context.Background(), b, netip.MustParseAddr("127.0.0.1"), "1.1.1.1:443",
		func(context.Context, string) (Target, netip.AddrPort, error) {
			return target, netip.MustParseAddrPort("1.1.1.1:443"), nil
		}, true)
	var status [1]byte
	if _, err := io.ReadFull(a, status[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAddress(a); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAddress(a); err != nil {
		t.Fatal(err)
	}
	p := []byte{0x40, 31, 72, 99, 1, 2, 3, 4, 5, 6} // no CID required
	if s.HandleRaw(p, client.LocalAddr()) {
		t.Fatal("unregistered raw created binding")
	}
	if err := writeLease(a, leaseControl{kind: leaseBind, seq: 1, digest: sha256.Sum256(p)}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(a, p); err != nil {
		t.Fatal(err)
	}
	<-target.up // the probe is already forwarded reliably
	if s.HandleRaw([]byte{0x40, 99}, client.LocalAddr()) {
		t.Fatal("wrong digest accepted")
	}
	if s.HandleRaw(p, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234}) {
		t.Fatal("wrong peer IP accepted")
	}
	if !s.HandleRaw(p, client.LocalAddr()) {
		t.Fatal("registered proof rejected")
	}
	_, ack, err := readRecord(a)
	if err != nil || ack == nil || ack.kind != leaseBound || ack.seq != 1 {
		t.Fatalf("bind ack: %+v %v", ack, err)
	}
	select {
	case <-target.up:
		t.Fatal("probe forwarded twice")
	default:
	}
	if err := writeLease(a, leaseControl{kind: leaseActivate, seq: 1, digest: [32]byte{99}}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(a, p); err != nil {
		t.Fatal(err)
	}
	<-target.up
	s.mu.Lock()
	for f := range s.flows {
		if !f.paused {
			t.Error("binding activated without reverse-path proof")
		}
	}
	s.mu.Unlock()
	target.down <- p
	if got, err := ReadFrame(a); err != nil || string(got) != string(p) {
		t.Fatalf("pre-activation fallback %x %v", got, err)
	}
	if err := writeLease(a, leaseControl{kind: leaseActivate, seq: 1, digest: sha256.Sum256(p)}); err != nil {
		t.Fatal(err)
	}
	_, ack, err = readRecord(a)
	if err != nil || ack == nil || ack.kind != leaseConfirmed {
		t.Fatalf("reverse confirmation: %+v %v", ack, err)
	}
	// A stream packet is a barrier after the activation control.
	if err := WriteFrame(a, p); err != nil {
		t.Fatal(err)
	}
	<-target.up
	target.down <- p
	client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := client.ReadFrom(buf)
	if err != nil || string(buf[:n]) != string(p) {
		t.Fatalf("zero CID downstream %x %v", buf[:n], err)
	}
	if s.HandleRaw(p, stranger.LocalAddr()) {
		t.Fatal("another port stole live binding")
	}
	s.mu.Lock()
	f := s.tuples[netip.MustParseAddrPort(client.LocalAddr().String())]
	before := f.leaseUntil
	s.mu.Unlock()
	if !s.HandleRaw(p, client.LocalAddr()) {
		t.Fatal("bound raw rejected")
	}
	<-target.up
	s.mu.Lock()
	if !f.leaseUntil.Equal(before) {
		t.Error("raw renewed lease")
	}
	s.mu.Unlock()
	started := time.Now()
	if err := writeLease(a, leaseControl{kind: leaseRenew, seq: 2}); err != nil {
		t.Fatal(err)
	}
	_, ack, err = readRecord(a)
	if err != nil || ack == nil || ack.kind != leaseRenewed {
		t.Fatalf("renew ack: %+v %v", ack, err)
	}
	s.mu.Lock()
	until := f.leaseUntil
	f.leaseUntil = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if until.Before(started.Add(leaseDuration)) || until.After(time.Now().Add(leaseDuration)) {
		t.Fatal("renewal accumulated or exceeded 30 seconds")
	}
	if s.HandleRaw(p, client.LocalAddr()) {
		t.Fatal("raw revived expired binding")
	}
	if err := f.handleLease(leaseControl{kind: leaseRenew, seq: 3}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	expired := !time.Now().Before(f.leaseUntil)
	s.mu.Unlock()
	if !expired {
		t.Fatal("renewal revived expired binding")
	}
	target.down <- p
	if got, err := ReadFrame(a); err != nil || string(got) != string(p) {
		t.Fatalf("expired fallback %x %v", got, err)
	}
}
