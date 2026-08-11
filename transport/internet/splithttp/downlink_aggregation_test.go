package splithttp

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet/stat"
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

func TestDownlinkAggregationDefaultsUseHTTP2SizedSoftTarget(t *testing.T) {
	if downlinkFlushThreshold != 16*1024 {
		t.Fatalf("threshold = %d, want 16384", downlinkFlushThreshold)
	}
	if downlinkFlushInterval != time.Millisecond {
		t.Fatalf("interval = %s, want 1ms", downlinkFlushInterval)
	}
	if downlinkPrewarmedBuffers != 8 {
		t.Fatalf("prewarmed buffers = %d, want 8", downlinkPrewarmedBuffers)
	}
}

func TestDownlinkWriteBufferPoolPrewarmsEightWindows(t *testing.T) {
	pool := newDownlinkWriteBufferPool()
	if len(pool) != downlinkPrewarmedBuffers || cap(pool) != downlinkPrewarmedBuffers {
		t.Fatalf("pool = len %d cap %d, want %d", len(pool), cap(pool), downlinkPrewarmedBuffers)
	}
	for i := 0; i < downlinkPrewarmedBuffers; i++ {
		buffer := <-pool
		if len(buffer) != 0 || cap(buffer) != downlinkFlushThreshold {
			t.Fatalf("buffer[%d] = len %d cap %d, want len 0 cap %d", i, len(buffer), cap(buffer), downlinkFlushThreshold)
		}
	}
}

func TestDownlinkWriteBufferPoolUsesNonblockingBoundedFallback(t *testing.T) {
	pool := newDownlinkWriteBufferPool()
	buffers := make([][]byte, downlinkPrewarmedBuffers+1)
	for i := range buffers {
		buffers[i] = acquireDownlinkWriteBuffer(pool)
		if len(buffers[i]) != 0 || cap(buffers[i]) != downlinkFlushThreshold {
			t.Fatalf("buffer[%d] = len %d cap %d, want len 0 cap %d", i, len(buffers[i]), cap(buffers[i]), downlinkFlushThreshold)
		}
	}
	if len(pool) != 0 {
		t.Fatalf("pool length after %d acquisitions = %d, want 0", len(buffers), len(pool))
	}

	for _, buffer := range buffers {
		releaseDownlinkWriteBuffer(pool, buffer)
	}
	if len(pool) != downlinkPrewarmedBuffers {
		t.Fatalf("pool length after %d releases = %d, want bounded length %d", len(buffers), len(pool), downlinkPrewarmedBuffers)
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

func TestDownlinkMultiBufferUsesOneApplicationWrite(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	split := &splitConn{writer: conn, reader: io.NopCloser(bytes.NewReader(nil))}
	batchWriter := buf.NewWriter(split)

	first := buf.New()
	second := buf.New()
	_, _ = first.Write([]byte("first-"))
	_, _ = second.Write([]byte("second"))
	if err := batchWriter.WriteMultiBuffer(buf.MultiBuffer{
		first,
		second,
	}); err != nil {
		t.Fatal(err)
	}

	writes, flushes := writer.snapshot()
	if len(writes) != 1 || flushes != 1 {
		t.Fatalf("writes = %v, flushes = %d, want one application write and flush", writeLengths(writes), flushes)
	}
	if got, want := writes[0], []byte("first-second"); !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("buffer ownership was not released: caps = %d, %d", first.Cap(), second.Cap())
	}
}

func TestDownlinkMultiBufferSurvivesStatsConnection(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	split := &splitConn{writer: conn, reader: io.NopCloser(bytes.NewReader(nil))}
	counter := new(testCounter)
	wrapped := &stat.CounterConnection{Connection: split, WriteCounter: counter}

	if err := buf.NewWriter(wrapped).WriteMultiBuffer(buf.MultiBuffer{
		buf.FromBytes([]byte("first-")),
		buf.FromBytes([]byte("second")),
	}); err != nil {
		t.Fatal(err)
	}

	writes, _ := writer.snapshot()
	if len(writes) != 1 || string(writes[0]) != "first-second" {
		t.Fatalf("writes through stats connection = %q, want one ordered write", writes)
	}
	if got, want := counter.Value(), int64(len("first-second")); got != want {
		t.Fatalf("write counter = %d, want %d", got, want)
	}
}

type testCounter struct {
	value atomic.Int64
}

func (c *testCounter) Value() int64 { return c.value.Load() }

func (c *testCounter) Set(value int64) int64 { return c.value.Swap(value) }

func (c *testCounter) Add(value int64) int64 { return c.value.Add(value) }

func TestDownlinkMultiBufferFallbackUsesOneApplicationWrite(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	first := buf.New()
	second := buf.New()
	_, _ = first.Write(bytes.Repeat([]byte{'a'}, buf.Size))
	_, _ = second.Write(bytes.Repeat([]byte{'b'}, buf.Size))

	if err := conn.WriteMultiBuffer(buf.MultiBuffer{first, second}); err != nil {
		t.Fatal(err)
	}

	writes, flushes := writer.snapshot()
	if len(writes) != 1 || flushes != 1 || len(writes[0]) != 2*buf.Size {
		t.Fatalf("writes = %v, flushes = %d, want one %d-byte fallback write", writeLengths(writes), flushes, 2*buf.Size)
	}
	if !bytes.Equal(writes[0][:buf.Size], bytes.Repeat([]byte{'a'}, buf.Size)) ||
		!bytes.Equal(writes[0][buf.Size:], bytes.Repeat([]byte{'b'}, buf.Size)) {
		t.Fatal("fallback write changed payload bytes or ordering")
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("fallback buffer ownership was not released: caps = %d, %d", first.Cap(), second.Cap())
	}
}

func TestDownlinkSingleBufferStillUsesOneApplicationWrite(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	split := &splitConn{writer: conn, reader: io.NopCloser(bytes.NewReader(nil))}
	payload := []byte("single")

	if err := buf.NewWriter(split).WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		t.Fatal(err)
	}

	writes, flushes := writer.snapshot()
	if len(writes) != 1 || flushes != 1 || !bytes.Equal(writes[0], payload) {
		t.Fatalf("writes = %q, flushes = %d, want one unchanged write", writes, flushes)
	}
}

func TestDownlinkMultiBufferAggregationPreservesBatch(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	conn.SetDownlinkWriteAggregation(true)
	first := []byte("aggregated-")
	second := []byte("batch")

	if err := conn.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(first), buf.FromBytes(second)}); err != nil {
		t.Fatal(err)
	}
	if writes, flushes := writer.snapshot(); len(writes) != 0 || flushes != 0 {
		t.Fatalf("batch flushed before aggregation boundary: writes=%v flushes=%d", writeLengths(writes), flushes)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	writes, flushes := writer.snapshot()
	want := append(bytes.Clone(first), second...)
	if len(writes) != 1 || flushes != 1 || !bytes.Equal(writes[0], want) {
		t.Fatalf("writes = %q, flushes = %d, want one ordered aggregated batch %q", writes, flushes, want)
	}
}

func TestDownlinkMultiBufferReportsPartialWrite(t *testing.T) {
	wantErr := io.ErrShortWrite
	writer := &partialResponseWriter{
		header: make(http.Header),
		limit:  4,
	}
	conn := &httpServerConn{
		Instance:       done.New(),
		Reader:         bytes.NewReader(nil),
		ResponseWriter: writer,
	}

	first := buf.New()
	second := buf.New()
	_, _ = first.Write([]byte("hello"))
	_, _ = second.Write([]byte("world"))
	err := conn.WriteMultiBuffer(buf.MultiBuffer{first, second})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WriteMultiBuffer error = %v, want %v", err, wantErr)
	}
	if writer.calls != 1 {
		t.Fatalf("ResponseWriter.Write calls = %d, want 1", writer.calls)
	}
	if got, want := writer.payload, []byte("hell"); !bytes.Equal(got, want) {
		t.Fatalf("partial payload = %q, want %q", got, want)
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("buffers were not released after partial write: caps = %d, %d", first.Cap(), second.Cap())
	}
}

func TestDownlinkMultiBufferPropagatesWriteError(t *testing.T) {
	wantErr := errors.New("write failed")
	conn, writer := newAggregationTestConn(time.Hour)
	writer.writeErr = wantErr
	first := buf.New()
	second := buf.New()
	_, _ = first.Write([]byte("first"))
	_, _ = second.Write([]byte("second"))

	if err := conn.WriteMultiBuffer(buf.MultiBuffer{first, second}); !errors.Is(err, wantErr) {
		t.Fatalf("WriteMultiBuffer error = %v, want %v", err, wantErr)
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("buffers were not released after write error: caps = %d, %d", first.Cap(), second.Cap())
	}
}

type partialResponseWriter struct {
	header  http.Header
	limit   int
	calls   int
	payload []byte
}

func (w *partialResponseWriter) Header() http.Header { return w.header }

func (*partialResponseWriter) WriteHeader(int) {}

func (w *partialResponseWriter) Write(p []byte) (int, error) {
	w.calls++
	n := min(w.limit, len(p))
	w.payload = append(w.payload, p[:n]...)
	return n, nil
}

func TestDownlinkAggregationDoesNotSplitLargeWrite(t *testing.T) {
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
	if len(writes) != 1 || len(writes[0]) != len(payload) {
		t.Fatalf("write lengths = %v, want [%d]", writeLengths(writes), len(payload))
	}
	if flushes != 1 {
		t.Fatalf("flushes = %d, want 1", flushes)
	}
	if got := bytes.Join(writes, nil); !bytes.Equal(got, payload) {
		t.Fatal("large write changed payload bytes or ordering")
	}
	if cap(conn.writeBuf) != 0 {
		t.Fatalf("large-write fast path retained %d bytes of buffer capacity", cap(conn.writeBuf))
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if cap(conn.writeBuf) != 0 {
		t.Fatalf("closed connection retained %d bytes of buffer capacity", cap(conn.writeBuf))
	}
}

func TestDownlinkAggregationLazilyPreallocatesAndReusesSoftTarget(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	if cap(conn.writeBuf) != 0 {
		t.Fatalf("initial buffer capacity = %d, want 0", cap(conn.writeBuf))
	}
	conn.SetDownlinkWriteAggregation(true)
	if cap(conn.writeBuf) != 0 {
		t.Fatalf("enabling aggregation allocated %d bytes, want 0", cap(conn.writeBuf))
	}

	const firstSize = 2 * 1024
	if _, err := conn.Write(bytes.Repeat([]byte{1}, firstSize)); err != nil {
		t.Fatal(err)
	}
	if len(conn.writeBuf) != firstSize || cap(conn.writeBuf) != downlinkFlushThreshold {
		t.Fatalf("buffer after first small write = len %d cap %d, want len %d cap %d", len(conn.writeBuf), cap(conn.writeBuf), firstSize, downlinkFlushThreshold)
	}

	if _, err := conn.Write(bytes.Repeat([]byte{2}, downlinkFlushThreshold-firstSize)); err != nil {
		t.Fatal(err)
	}
	if len(conn.writeBuf) != 0 || cap(conn.writeBuf) != downlinkFlushThreshold {
		t.Fatalf("buffer after threshold flush = len %d cap %d, want len 0 cap %d", len(conn.writeBuf), cap(conn.writeBuf), downlinkFlushThreshold)
	}
	writes, flushes := writer.snapshot()
	if len(writes) != 1 || len(writes[0]) != downlinkFlushThreshold || flushes != 1 {
		t.Fatalf("writes = %v, flushes = %d, want one %d-byte write and flush", writeLengths(writes), flushes, downlinkFlushThreshold)
	}

	if _, err := conn.Write([]byte("reused")); err != nil {
		t.Fatal(err)
	}
	if cap(conn.writeBuf) != downlinkFlushThreshold {
		t.Fatalf("reused buffer capacity = %d, want %d", cap(conn.writeBuf), downlinkFlushThreshold)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if cap(conn.writeBuf) != 0 {
		t.Fatalf("closed connection retained %d bytes of buffer capacity", cap(conn.writeBuf))
	}
}

func TestDownlinkAggregationFlushesWholeBatchPastSoftTarget(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	conn.SetDownlinkWriteAggregation(true)

	first := bytes.Repeat([]byte{1}, downlinkFlushThreshold/2)
	second := bytes.Repeat([]byte{2}, downlinkFlushThreshold/2+37)
	if _, err := conn.Write(first); err != nil {
		t.Fatal(err)
	}
	if writes, flushes := writer.snapshot(); len(writes) != 0 || flushes != 0 {
		t.Fatalf("first partial write flushed early: writes=%v flushes=%d", writeLengths(writes), flushes)
	}
	if _, err := conn.Write(second); err != nil {
		t.Fatal(err)
	}

	writes, flushes := writer.snapshot()
	wantLength := len(first) + len(second)
	if len(writes) != 1 || len(writes[0]) != wantLength {
		t.Fatalf("write lengths = %v, want [%d]", writeLengths(writes), wantLength)
	}
	if flushes != 1 {
		t.Fatalf("flushes = %d, want 1", flushes)
	}
	if len(conn.writeBuf) != 0 || cap(conn.writeBuf) != downlinkFlushThreshold {
		t.Fatalf("buffer after soft-target overshoot = len %d cap %d, want len 0 cap %d", len(conn.writeBuf), cap(conn.writeBuf), downlinkFlushThreshold)
	}
	want := append(bytes.Clone(first), second...)
	if !bytes.Equal(writes[0], want) {
		t.Fatal("soft-target batch changed payload bytes or ordering")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDownlinkAggregationDoesNotGrowWindowForLargeWriteAfterPartialBatch(t *testing.T) {
	conn, writer := newAggregationTestConn(time.Hour)
	conn.SetDownlinkWriteAggregation(true)

	first := bytes.Repeat([]byte{1}, 2*1024)
	second := bytes.Repeat([]byte{2}, 4*downlinkFlushThreshold)
	if _, err := conn.Write(first); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(second); err != nil {
		t.Fatal(err)
	}

	writes, flushes := writer.snapshot()
	wantLength := len(first) + len(second)
	if len(writes) != 1 || len(writes[0]) != wantLength || flushes != 1 {
		t.Fatalf("write lengths = %v, flushes = %d, want one %d-byte write and flush", writeLengths(writes), flushes, wantLength)
	}
	if len(conn.writeBuf) != 0 || cap(conn.writeBuf) != downlinkFlushThreshold {
		t.Fatalf("buffer after large following write = len %d cap %d, want len 0 cap %d", len(conn.writeBuf), cap(conn.writeBuf), downlinkFlushThreshold)
	}
	want := append(bytes.Clone(first), second...)
	if !bytes.Equal(writes[0], want) {
		t.Fatal("large following write changed payload bytes or ordering")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
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
		if len(writes) == 1 && flushes == 1 {
			if string(writes[0]) != "partial" {
				t.Fatalf("writes = %q, want partial", writes)
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
	dataFrames := 0
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
			dataFrames++
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
	if dataFrames != 1 {
		t.Fatalf("framed large write used %d data frames, want 1 application frame", dataFrames)
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
