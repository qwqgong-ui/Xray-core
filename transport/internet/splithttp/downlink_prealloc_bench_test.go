package splithttp

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

type discardFlushingResponseWriter struct {
	header http.Header
}

func (w *discardFlushingResponseWriter) Header() http.Header {
	return w.header
}

func (*discardFlushingResponseWriter) WriteHeader(int) {}

func (*discardFlushingResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (*discardFlushingResponseWriter) Flush() {}

func runDownlinkAggregationSmallWriteLifecycle(payload []byte, writer http.ResponseWriter) error {
	conn := &httpServerConn{
		Instance:       done.New(),
		Reader:         bytes.NewReader(nil),
		ResponseWriter: writer,
		flushInterval:  time.Hour,
	}
	conn.SetDownlinkWriteAggregation(true)
	for written := 0; written < downlinkFlushThreshold; written += len(payload) {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	return conn.Close()
}

func BenchmarkDownlinkAggregationSmallWriteLifecycle(b *testing.B) {
	payload := bytes.Repeat([]byte{1}, 2*1024)
	writer := &discardFlushingResponseWriter{header: make(http.Header)}

	b.ReportAllocs()
	b.SetBytes(downlinkFlushThreshold)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := runDownlinkAggregationSmallWriteLifecycle(payload, writer); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDownlinkAggregationSmallWriteLifecycleParallel(b *testing.B) {
	payload := bytes.Repeat([]byte{1}, 2*1024)

	// Eight workers per P deliberately creates more simultaneous lifecycles
	// than the bounded prewarmed pool on ordinary 2-vCPU servers. This covers
	// both pooled acquisition and the non-blocking allocation fallback.
	b.SetParallelism(8)
	b.ReportAllocs()
	b.SetBytes(downlinkFlushThreshold)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		writer := &discardFlushingResponseWriter{header: make(http.Header)}
		for pb.Next() {
			if err := runDownlinkAggregationSmallWriteLifecycle(payload, writer); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
