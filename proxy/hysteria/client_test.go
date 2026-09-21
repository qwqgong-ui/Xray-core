package hysteria

import (
	"testing"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
)

// recorder stands in for the QUIC datagram writer, keeping every serialized
// message and optionally refusing ones over limit the way quic-go does.
type recorder struct {
	limit    int
	messages [][]byte
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.limit > 0 && len(p) > r.limit {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(r.limit)}
	}
	r.messages = append(r.messages, append([]byte(nil), p...))
	return len(p), nil
}

func (r *recorder) ids(t *testing.T) []uint16 {
	t.Helper()
	var ids []uint16
	for _, m := range r.messages {
		parsed, err := ParseUDPMessage(m)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ids = append(ids, parsed.PacketID)
	}
	return ids
}

func writeN(t *testing.T, w *UDPWriter, n, size int) {
	t.Helper()
	for range n {
		b := buf.New()
		b.Extend(int32(size))
		if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func TestUDPWriterNumbersMessagesInOrder(t *testing.T) {
	r := &recorder{}
	w := &UDPWriter{writer: r, addr: "203.0.113.1:443"}
	writeN(t, w, 5, 16)
	got := r.ids(t)
	for i, id := range got {
		if int(id) != i+1 {
			t.Fatalf("packet IDs %v, want 1..5", got)
		}
	}
}

// sing-quic counts modulo 65535 and never sends 0xFFFF, which is what lets a
// peer treat the wrap as a step of one rather than a gap.
func TestUDPWriterWrapsWithout0xFFFF(t *testing.T) {
	r := &recorder{}
	w := &UDPWriter{writer: r, addr: "203.0.113.1:443"}
	w.packetID.Store(65532)
	writeN(t, w, 5, 16)
	got := r.ids(t)
	want := []uint16{65533, 65534, 0, 1, 2}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("packet IDs %v, want %v", got, want)
		}
	}
}

func TestUDPWriterFragmentsShareOneID(t *testing.T) {
	r := &recorder{limit: 200}
	w := &UDPWriter{writer: r, addr: "203.0.113.1:443"}
	writeN(t, w, 1, 16)  // fits
	writeN(t, w, 1, 600) // must be fragmented
	writeN(t, w, 1, 16)  // fits again

	got := r.ids(t)
	if len(got) < 4 {
		t.Fatalf("expected the middle message to be fragmented: %v", got)
	}
	if got[0] != 1 {
		t.Fatalf("first message got ID %d, want 1", got[0])
	}
	// Every fragment of the second message carries its ID, and the message
	// after it continues the count.
	last := got[len(got)-1]
	for _, id := range got[1 : len(got)-1] {
		if id != 2 {
			t.Fatalf("fragment IDs %v, want all 2 between the two whole messages", got)
		}
	}
	if last != 3 {
		t.Fatalf("message after the fragments got ID %d, want 3", last)
	}
}
