package hysteria

import (
	"bytes"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// recordingWriter keeps every datagram the sender produced, in one piece.
type recordingWriter struct {
	mutex   sync.Mutex
	packets [][]byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.mutex.Lock()
	w.packets = append(w.packets, append([]byte(nil), p...))
	w.mutex.Unlock()
	return len(p), nil
}

// One hybrid control link is written by the control loop and by every flow's
// reader goroutine at once. UDPWriter serializes each message through a buffer
// it owns, so without a lock two replies interleave inside that buffer and
// reach the client spliced together. Run under -race this fails on the data
// race; run without, it fails on the corrupted payloads.
func TestHybridControlSenderIsConcurrent(t *testing.T) {
	writer := &recordingWriter{}
	send := newHybridControlSender(writer, "192.0.2.1:443")

	const senders = 8
	const perSender = 64
	payloads := make([][]byte, senders)
	for i := range payloads {
		// Long enough that two messages sharing one buffer cannot help but
		// overlap, and distinct enough that any splice is visible.
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 512)
	}

	var group sync.WaitGroup
	for i := 0; i < senders; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			from := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, byte(i + 1)}), net.Port(443))
			for j := 0; j < perSender; j++ {
				if err := send(payloads[i], from); err != nil {
					t.Errorf("send: %v", err)
					return
				}
			}
		}(i)
	}
	group.Wait()

	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	if len(writer.packets) != senders*perSender {
		t.Fatalf("wrote %d datagrams, want %d", len(writer.packets), senders*perSender)
	}
	for _, packet := range writer.packets {
		message, err := ParseUDPMessage(packet)
		if err != nil {
			t.Fatalf("a datagram did not parse as one message: %v", err)
		}
		matched := false
		for _, payload := range payloads {
			if bytes.Equal(message.Data, payload) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("a datagram carried spliced payload %q", message.Data)
		}
	}
}
