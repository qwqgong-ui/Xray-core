package encryption

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type recordingConn struct {
	mu       sync.Mutex
	calls    int
	writes   [][]byte
	failAt   int
	writeErr error
	shortAt  int
	shortN   int
}

func (c *recordingConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.failAt == c.calls {
		return 0, c.writeErr
	}
	if c.shortAt == c.calls {
		n := min(c.shortN, len(p))
		c.writes = append(c.writes, bytes.Clone(p[:n]))
		return n, nil
	}
	c.writes = append(c.writes, bytes.Clone(p))
	return len(p), nil
}

func (*recordingConn) Close() error                     { return nil }
func (*recordingConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*recordingConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingConn) snapshot() (int, [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, append([][]byte(nil), c.writes...)
}

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func newTestCommonConn(raw net.Conn) (*CommonConn, *AEAD) {
	contextBytes := []byte("common-conn-multibuffer-test")
	key := bytes.Repeat([]byte{0x5a}, 32)
	conn := NewCommonConn(raw, true)
	conn.UnitedKey = bytes.Clone(key)
	conn.AEAD = NewAEAD(contextBytes, key, true)
	return conn, NewAEAD(contextBytes, key, true)
}

func managedBuffer(t *testing.T, payload []byte) *buf.Buffer {
	t.Helper()
	buffer := buf.New()
	if n, err := buffer.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("buffer.Write() = %d, %v, want %d, nil", n, err, len(payload))
	}
	return buffer
}

func decryptRecords(t *testing.T, peer *AEAD, writes [][]byte) []byte {
	t.Helper()
	var plaintext []byte
	for i, record := range writes {
		if len(record) < 5 {
			t.Fatalf("record %d length = %d, want at least 5", i, len(record))
		}
		ciphertextLength, err := DecodeHeader(record[:5])
		if err != nil {
			t.Fatalf("DecodeHeader(record %d): %v", i, err)
		}
		if got, want := len(record), 5+ciphertextLength; got != want {
			t.Fatalf("record %d length = %d, want %d", i, got, want)
		}
		chunk, err := peer.Open(nil, nil, record[5:], record[:5])
		if err != nil {
			t.Fatalf("decrypt record %d: %v", i, err)
		}
		plaintext = append(plaintext, chunk...)
	}
	return plaintext
}

func TestCommonConnWriteMultiBufferCoalescesTwoBuffers(t *testing.T) {
	raw := new(recordingConn)
	conn, peer := newTestCommonConn(raw)
	first := managedBuffer(t, []byte("first-"))
	second := managedBuffer(t, []byte("second"))

	if err := buf.NewWriter(conn).WriteMultiBuffer(buf.MultiBuffer{first, second}); err != nil {
		t.Fatal(err)
	}

	calls, writes := raw.snapshot()
	if calls != 1 {
		t.Fatalf("underlying Write calls = %d, want 1", calls)
	}
	if got, want := decryptRecords(t, peer, writes), []byte("first-second"); !bytes.Equal(got, want) {
		t.Fatalf("plaintext = %q, want %q", got, want)
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("buffer ownership was not released: caps = %d, %d", first.Cap(), second.Cap())
	}
}

func TestCommonConnWriteMultiBufferPreservesPreWrite(t *testing.T) {
	raw := new(recordingConn)
	conn, peer := newTestCommonConn(raw)
	prefix := bytes.Repeat([]byte{0x42}, 16)
	conn.PreWrite = bytes.Clone(prefix)
	first := managedBuffer(t, []byte("first-"))
	second := managedBuffer(t, []byte("second"))

	if err := conn.WriteMultiBuffer(buf.MultiBuffer{first, second}); err != nil {
		t.Fatal(err)
	}

	calls, writes := raw.snapshot()
	if calls != 1 || len(writes) != 1 {
		t.Fatalf("underlying writes = %d/%d, want 1/1", calls, len(writes))
	}
	if !bytes.HasPrefix(writes[0], prefix) {
		t.Fatal("first encrypted record lost PreWrite prefix")
	}
	if conn.PreWrite != nil {
		t.Fatal("PreWrite was not consumed")
	}
	if got, want := decryptRecords(t, peer, [][]byte{writes[0][len(prefix):]}), []byte("first-second"); !bytes.Equal(got, want) {
		t.Fatalf("plaintext = %q, want %q", got, want)
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("buffer ownership was not released: caps = %d, %d", first.Cap(), second.Cap())
	}
}

func TestCommonConnWriteMultiBufferPacksAcrossRecordBoundary(t *testing.T) {
	raw := new(recordingConn)
	conn, peer := newTestCommonConn(raw)
	firstPayload := bytes.Repeat([]byte{'a'}, 4000)
	secondPayload := bytes.Repeat([]byte{'b'}, 4000)
	thirdPayload := bytes.Repeat([]byte{'c'}, 4000)
	first := managedBuffer(t, firstPayload)
	second := managedBuffer(t, secondPayload)
	third := managedBuffer(t, thirdPayload)

	if err := conn.WriteMultiBuffer(buf.MultiBuffer{first, second, third}); err != nil {
		t.Fatal(err)
	}

	calls, writes := raw.snapshot()
	if calls != 2 {
		t.Fatalf("underlying Write calls = %d, want 2", calls)
	}
	if got, want := len(writes[0]), 5+buf.Size+16; got != want {
		t.Fatalf("first encrypted record length = %d, want %d", got, want)
	}
	want := append(bytes.Clone(firstPayload), secondPayload...)
	want = append(want, thirdPayload...)
	if got := decryptRecords(t, peer, writes); !bytes.Equal(got, want) {
		t.Fatalf("decrypted payload mismatch: got %d bytes, want %d", len(got), len(want))
	}
	if first.Cap() != 0 || second.Cap() != 0 || third.Cap() != 0 {
		t.Fatalf("buffer ownership was not released: caps = %d, %d, %d", first.Cap(), second.Cap(), third.Cap())
	}
}

func TestCommonConnWriteMultiBufferReleasesBuffersOnError(t *testing.T) {
	wantErr := errors.New("write failed")
	raw := &recordingConn{failAt: 1, writeErr: wantErr}
	conn, _ := newTestCommonConn(raw)
	first := managedBuffer(t, []byte("first"))
	second := managedBuffer(t, []byte("second"))

	if err := conn.WriteMultiBuffer(buf.MultiBuffer{first, second}); !errors.Is(err, wantErr) {
		t.Fatalf("WriteMultiBuffer() error = %v, want %v", err, wantErr)
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("buffers were not released after error: caps = %d, %d", first.Cap(), second.Cap())
	}
}

func TestCommonConnWriteMultiBufferReportsShortWrite(t *testing.T) {
	raw := &recordingConn{shortAt: 1, shortN: 4}
	conn, _ := newTestCommonConn(raw)
	first := managedBuffer(t, []byte("first"))
	second := managedBuffer(t, []byte("second"))

	if err := conn.WriteMultiBuffer(buf.MultiBuffer{first, second}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteMultiBuffer() error = %v, want %v", err, io.ErrShortWrite)
	}
	if first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("buffers were not released after short write: caps = %d, %d", first.Cap(), second.Cap())
	}
}
