package buf

import (
	"io"
	"testing"
	"time"
)

type stagedReader struct {
	chunks chan []byte
}

func (r *stagedReader) Read(p []byte) (int, error) {
	chunk, ok := <-r.chunks
	if !ok {
		return 0, io.EOF
	}
	return copy(p, chunk), nil
}

func TestReadyReaderDrainsOnlyQueuedBuffers(t *testing.T) {
	source := &stagedReader{chunks: make(chan []byte, 4)}
	reader := NewReadyReader(source)
	defer close(source.chunks)
	defer reader.Interrupt()

	source.chunks <- make([]byte, Size)
	source.chunks <- make([]byte, Size)
	source.chunks <- make([]byte, 6<<10)

	deadline := time.Now().Add(time.Second)
	for len(reader.results) < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(reader.results); got != 3 {
		t.Fatalf("queued buffers = %d, want 3", got)
	}

	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer ReleaseMulti(mb)
	if got := len(mb); got != 3 {
		t.Fatalf("buffers = %d, want 3", got)
	}
	if got := mb.Len(); got != 22<<10 {
		t.Fatalf("bytes = %d, want %d", got, 22<<10)
	}

	result := make(chan MultiBuffer, 1)
	go func() {
		mb, _ := reader.ReadMultiBuffer()
		result <- mb
	}()
	select {
	case mb := <-result:
		ReleaseMulti(mb)
		t.Fatal("ReadMultiBuffer returned before future data arrived")
	case <-time.After(10 * time.Millisecond):
	}

	source.chunks <- []byte("next")
	select {
	case mb := <-result:
		defer ReleaseMulti(mb)
		if got := mb.String(); got != "next" {
			t.Fatalf("payload = %q, want next", got)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadMultiBuffer did not return after data arrived")
	}
}
