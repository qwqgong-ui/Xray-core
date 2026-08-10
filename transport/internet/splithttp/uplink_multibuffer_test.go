package splithttp

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type abUplinkReader struct {
	remaining int
	reads     atomic.Int32
}

func (r *abUplinkReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), buf.Size, r.remaining)
	for i := 0; i < n; i++ {
		p[i] = byte(r.reads.Load() + 1)
	}
	r.remaining -= n
	r.reads.Add(1)
	return n, nil
}

func (r *abUplinkReader) Close() error { return nil }

type discardWriteCloser struct{}

func (discardWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriteCloser) Close() error                { return nil }

func TestXHTTPUplinkMultiBufferAB(t *testing.T) {
	source := &abUplinkReader{remaining: 22 << 10}
	conn := &splitConn{reader: source, writer: discardWriteCloser{}}

	// The optional interface keeps this exact test source runnable against the
	// pre-change tree, where splitConn has no read-ahead implementation.
	starter, enabled := any(conn).(interface{ enableReadyInput() })
	if enabled {
		starter.enableReadyInput()
		deadline := time.Now().Add(time.Second)
		for source.reads.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}

	reader := buf.NewReader(conn)
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)

	wantBuffers := 1
	wantBytes := int32(buf.Size)
	if enabled {
		wantBuffers = 3
		wantBytes = 22 << 10
	}
	if got := len(mb); got != wantBuffers {
		t.Fatalf("MultiBuffer blocks = %d, want %d", got, wantBuffers)
	}
	if got := mb.Len(); got != wantBytes {
		t.Fatalf("MultiBuffer bytes = %d, want %d", got, wantBytes)
	}
	t.Logf("xhttp_uplink blocks=%d bytes=%d", len(mb), mb.Len())
}
