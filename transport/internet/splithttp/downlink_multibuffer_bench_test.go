package splithttp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal/done"
)

type countingResponseWriter struct {
	writes int64
}

func (*countingResponseWriter) Header() http.Header { return nil }

func (*countingResponseWriter) WriteHeader(int) {}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	w.writes++
	return len(p), nil
}

func (*countingResponseWriter) Flush() {}

func BenchmarkDownlinkTwoBufferWrite(b *testing.B) {
	firstPayload := bytes.Repeat([]byte{'a'}, 128)
	secondPayload := bytes.Repeat([]byte{'b'}, 1152)
	bytesPerIteration := len(firstPayload) + len(secondPayload)

	b.Run("sequential-scalar", func(b *testing.B) {
		writer := new(countingResponseWriter)
		conn := &httpServerConn{Instance: done.New(), ResponseWriter: writer}
		b.SetBytes(int64(bytesPerIteration))
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			first, second := benchmarkBuffers(firstPayload, secondPayload)
			_, _ = conn.Write(first.Bytes())
			_, _ = conn.Write(second.Bytes())
			first.Release()
			second.Release()
		}
		b.ReportMetric(writesPerMiB(writer.writes, b.N, bytesPerIteration), "writes/MiB")
	})

	b.Run("multibuffer", func(b *testing.B) {
		writer := new(countingResponseWriter)
		conn := &httpServerConn{Instance: done.New(), ResponseWriter: writer}
		b.SetBytes(int64(bytesPerIteration))
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			first, second := benchmarkBuffers(firstPayload, secondPayload)
			_ = conn.WriteMultiBuffer(buf.MultiBuffer{first, second})
		}
		b.ReportMetric(writesPerMiB(writer.writes, b.N, bytesPerIteration), "writes/MiB")
	})
}

func BenchmarkDownlinkTwoBufferHTTP2(b *testing.B) {
	const batchesPerResponse = 128
	firstPayload := bytes.Repeat([]byte{'a'}, 128)
	secondPayload := bytes.Repeat([]byte{'b'}, 1152)
	bytesPerResponse := batchesPerResponse * (len(firstPayload) + len(secondPayload))
	contentLength := strconv.Itoa(bytesPerResponse)

	for _, benchmark := range []struct {
		name        string
		multibuffer bool
		writes      int
	}{
		{name: "sequential-scalar", writes: 2 * batchesPerResponse},
		{name: "multibuffer", multibuffer: true, writes: batchesPerResponse},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Length", contentLength)
				conn := &httpServerConn{Instance: done.New(), ResponseWriter: writer}
				for range batchesPerResponse {
					first, second := benchmarkBuffers(firstPayload, secondPayload)
					if benchmark.multibuffer {
						_ = conn.WriteMultiBuffer(buf.MultiBuffer{first, second})
						continue
					}
					_, _ = conn.Write(first.Bytes())
					_, _ = conn.Write(second.Bytes())
					first.Release()
					second.Release()
				}
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()

			client := server.Client()
			b.SetBytes(int64(bytesPerResponse))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				response, err := client.Get(server.URL)
				if err != nil {
					b.Fatal(err)
				}
				if response.ProtoMajor != 2 {
					response.Body.Close()
					b.Fatalf("HTTP major version = %d, want 2", response.ProtoMajor)
				}
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					response.Body.Close()
					b.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(benchmark.writes)*float64(b.N)/(float64(bytesPerResponse*b.N)/(1<<20)), "writes/MiB")
		})
	}
}

func benchmarkBuffers(firstPayload, secondPayload []byte) (*buf.Buffer, *buf.Buffer) {
	first := buf.New()
	second := buf.New()
	_, _ = first.Write(firstPayload)
	_, _ = second.Write(secondPayload)
	return first, second
}

func writesPerMiB(writes int64, iterations, bytesPerIteration int) float64 {
	mebibytes := float64(iterations*bytesPerIteration) / (1 << 20)
	return float64(writes) / mebibytes
}
