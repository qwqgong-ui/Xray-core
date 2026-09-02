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
			encoded, err := os.ReadFile(filepath.Join("testdata", "hqv2_"+test.name+".hex"))
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
