package hysteria

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures under testdata are produced by the client's own encoder and are
// checked into both repositories byte for byte. Decoding them here is what
// makes a wire-format drift on either side fail a test, instead of surfacing as
// a silent interop failure against a real peer.
func TestHybridWireFormatGoldens(t *testing.T) {
	var wantID [16]byte
	copy(wantID[:], "0123456789abcdef")
	wantPayload := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}

	tests := []struct {
		name       string
		wantDomain string
		wantIP     string
	}{
		{name: "domain", wantDomain: "example.com"},
		{name: "ipv4", wantIP: "1.1.1.1"},
		{name: "ipv6", wantIP: "2606:4700:4700::1111"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join("testdata", "hqv3_"+test.name+".hex"))
			if err != nil {
				t.Fatal(err)
			}
			message, err := hex.DecodeString(string(bytes.TrimSpace(encoded)))
			if err != nil {
				t.Fatal(err)
			}

			id, destination, payload, err := parseHybridInitial(message)
			if err != nil {
				t.Fatalf("the client's own registration did not parse: %v", err)
			}
			if id != wantID {
				t.Fatalf("flow id = %x, want %x", id, wantID)
			}
			if destination.Port != 443 {
				t.Fatalf("port = %v, want 443", destination.Port)
			}
			if !bytes.Equal(payload, wantPayload) {
				t.Fatalf("payload = %x, want %x", payload, wantPayload)
			}

			if test.wantDomain != "" {
				if !destination.Address.Family().IsDomain() {
					t.Fatalf("address = %v, want the domain %q", destination.Address, test.wantDomain)
				}
				if got := destination.Address.Domain(); got != test.wantDomain {
					t.Fatalf("domain = %q, want %q", got, test.wantDomain)
				}
				return
			}
			if destination.Address.Family().IsDomain() {
				t.Fatalf("address = %v, want the literal %q", destination.Address, test.wantIP)
			}
			got, ok := netip.AddrFromSlice(destination.Address.IP())
			if !ok || got.Unmap() != netip.MustParseAddr(test.wantIP) {
				t.Fatalf("address = %v, want %q", destination.Address, test.wantIP)
			}
		})
	}
}

// The relay op carries a packet of an already-registered flow. Its header is
// fixed at magic, op and flow id, so a client that shifts it would send packets
// this server silently mistakes for something else.
func TestHybridRelayGolden(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testdata", "hqv3_relay.hex"))
	if err != nil {
		t.Fatal(err)
	}
	message, err := hex.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if len(message) < 22 || string(message[:4]) != hybridMagic || message[4] != hybridOpRelay {
		t.Fatalf("the client's own relay message did not parse: %x", message)
	}
	var wantID [16]byte
	copy(wantID[:], "0123456789abcdef")
	if got := [16]byte(message[5:21]); got != wantID {
		t.Fatalf("flow id = %x, want %x", got, wantID)
	}
	wantPayload := []byte{0x42, 0xaa, 0xbb, 0xcc, 0xdd, 0x00}
	if !bytes.Equal(message[21:], wantPayload) {
		t.Fatalf("payload = %x, want %x", message[21:], wantPayload)
	}
	if !isShortHeader(message[21:]) {
		t.Fatal("the relay golden should carry a 1-RTT packet")
	}
}
