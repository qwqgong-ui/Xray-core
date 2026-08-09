package splithttp

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

type recordingResponseWriter struct {
	mu       sync.Mutex
	header   http.Header
	writes   [][]byte
	flushes  int
	writeErr error
}

func (w *recordingResponseWriter) Header() http.Header {
	return w.header
}

func (w *recordingResponseWriter) WriteHeader(int) {}

func (w *recordingResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	w.writes = append(w.writes, bytes.Clone(p))
	return len(p), nil
}

func (w *recordingResponseWriter) Flush() {
	w.mu.Lock()
	w.flushes++
	w.mu.Unlock()
}

func (w *recordingResponseWriter) snapshot() ([][]byte, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	writes := make([][]byte, len(w.writes))
	for i := range w.writes {
		writes[i] = bytes.Clone(w.writes[i])
	}
	return writes, w.flushes
}

func newAggregationTestConn(interval time.Duration) (*httpServerConn, *recordingResponseWriter) {
	writer := &recordingResponseWriter{header: make(http.Header)}
	return &httpServerConn{
		Instance:       done.New(),
		Reader:         bytes.NewReader(nil),
		ResponseWriter: writer,
		flushInterval:  interval,
	}, writer
}

func TestDownlinkAggregationDefaultsMatchHTTP2Frame(t *testing.T) {
	if downlinkFlushThreshold != 16*1024 {
		t.Fatalf("threshold = %d, want 16384", downlinkFlushThreshold)
	}
	if downlinkFlushInterval != time.Millisecond {
		t.Fatalf("interval = %s, want 1ms", downlinkFlushInterval)
	}
}

func TestDownlinkAggregationDisabledFlushesEachWrite(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	if _, err := conn.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	writes, flushes := writer.snapshot()
	if len(writes) != 2 || string(writes[0]) != "one" || string(writes[1]) != "two" {
		t.Fatalf("writes = %q, want two immediate writes", writes)
	}
	if flushes != 2 {
		t.Fatalf("flushes = %d, want 2", flushes)
	}
}

func TestDownlinkAggregationRollsOverflowIntoNextWindow(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	conn.SetDownlinkWriteAggregation(true)

	payload := make([]byte, 2*downlinkFlushThreshold+37)
	for i := range payload {
		payload[i] = byte(i)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(payload))
	}

	writes, flushes := writer.snapshot()
	if len(writes) != 2 {
		t.Fatalf("writes before close = %d, want 2 full windows", len(writes))
	}
	for i, write := range writes {
		if len(write) != downlinkFlushThreshold {
			t.Fatalf("write[%d] length = %d, want %d", i, len(write), downlinkFlushThreshold)
		}
	}
	if flushes != 2 {
		t.Fatalf("flushes before close = %d, want 2", flushes)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	writes, flushes = writer.snapshot()
	if len(writes) != 3 || len(writes[2]) != 37 {
		t.Fatalf("write lengths after close = %v, want [16384 16384 37]", writeLengths(writes))
	}
	if flushes != 3 {
		t.Fatalf("flushes after close = %d, want 3", flushes)
	}
	if got := bytes.Join(writes, nil); !bytes.Equal(got, payload) {
		t.Fatal("windowed writes changed payload bytes or ordering")
	}
}

func TestDownlinkAggregationTimerFlushesPartialWindow(t *testing.T) {
	conn, writer := newAggregationTestConn(0)
	conn.SetDownlinkWriteAggregation(true)
	if _, err := conn.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		writes, flushes := writer.snapshot()
		if len(writes) == 1 {
			if string(writes[0]) != "partial" || flushes != 1 {
				t.Fatalf("writes = %q, flushes = %d", writes, flushes)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("partial window was not flushed by its timer")
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDownlinkAggregationDisableFlushesPendingBytes(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	conn.SetDownlinkWriteAggregation(true)
	if _, err := conn.Write([]byte("pending")); err != nil {
		t.Fatal(err)
	}
	conn.SetDownlinkWriteAggregation(false)

	writes, flushes := writer.snapshot()
	if len(writes) != 1 || string(writes[0]) != "pending" || flushes != 1 {
		t.Fatalf("writes = %q, flushes = %d", writes, flushes)
	}
}

func TestDownlinkAggregationAsyncErrorIsSticky(t *testing.T) {
	wantErr := errors.New("write failed")
	conn, writer := newAggregationTestConn(time.Hour)
	conn.SetDownlinkWriteAggregation(true)
	if _, err := conn.Write([]byte("pending")); err != nil {
		t.Fatal(err)
	}
	writer.mu.Lock()
	writer.writeErr = wantErr
	writer.mu.Unlock()

	conn.Lock()
	conn.flushDeadline = time.Now()
	conn.Unlock()
	conn.flushPending()

	if _, err := conn.Write([]byte("later")); !errors.Is(err, wantErr) {
		t.Fatalf("subsequent Write error = %v, want %v", err, wantErr)
	}
	if err := conn.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close error = %v, want %v", err, wantErr)
	}
}

func TestDownlinkAggregationConcurrentWrites(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	conn.SetDownlinkWriteAggregation(true)

	const (
		writers       = 64
		bytesPerWrite = 257
	)
	errCh := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(value byte) {
			defer wg.Done()
			_, err := conn.Write(bytes.Repeat([]byte{value}, bytesPerWrite))
			errCh <- err
		}(byte(i))
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	writes, _ := writer.snapshot()
	got := bytes.Join(writes, nil)
	if len(got) != writers*bytesPerWrite {
		t.Fatalf("combined length = %d, want %d", len(got), writers*bytesPerWrite)
	}
	for i := 0; i < writers; i++ {
		if count := bytes.Count(got, []byte{byte(i)}); count != bytesPerWrite {
			t.Fatalf("byte %d count = %d, want %d", i, count, bytesPerWrite)
		}
	}
}

func TestFramedDownlinkAggregationPreservesStream(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	conn.framedDownlink = true
	conn.SetDownlinkWriteAggregation(true)

	payload := bytes.Repeat([]byte("framed-payload-"), 3000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.writeDownlinkHeartbeat(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	writes, _ := writer.snapshot()
	stream := bytes.Join(writes, nil)
	var decoded []byte
	for len(stream) > 0 {
		if len(stream) < downlinkFrameHeaderSize {
			t.Fatalf("truncated frame header: %d bytes", len(stream))
		}
		frameType := stream[0]
		length := int(stream[1])<<24 | int(stream[2])<<16 | int(stream[3])<<8 | int(stream[4])
		stream = stream[downlinkFrameHeaderSize:]
		if length > len(stream) {
			t.Fatalf("frame length %d exceeds remaining %d", length, len(stream))
		}
		switch frameType {
		case downlinkDataFrame:
			if length > downlinkFlushThreshold {
				t.Fatalf("data frame length = %d, want <= %d", length, downlinkFlushThreshold)
			}
			decoded = append(decoded, stream[:length]...)
		case downlinkHeartbeatFrame:
			if length != 0 {
				t.Fatalf("heartbeat length = %d, want 0", length)
			}
		default:
			t.Fatalf("unexpected frame type %d", frameType)
		}
		stream = stream[length:]
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("framed aggregation changed payload bytes or ordering")
	}
}

func TestSplitConnDelegatesDownlinkAggregation(t *testing.T) {
	httpConn, _ := newAggregationTestConn(time.Hour)
	conn := &splitConn{writer: httpConn, reader: io.NopCloser(bytes.NewReader(nil))}
	conn.SetDownlinkWriteAggregation(true)

	httpConn.Lock()
	enabled := httpConn.aggregateDownlink
	httpConn.Unlock()
	if !enabled {
		t.Fatal("splitConn did not enable its HTTP writer")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeLengths(writes [][]byte) []int {
	lengths := make([]int, len(writes))
	for i := range writes {
		lengths[i] = len(writes[i])
	}
	return lengths
}
