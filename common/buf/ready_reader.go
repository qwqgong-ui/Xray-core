package buf

import (
	"io"
	"sync"
	"sync/atomic"
)

const readyReaderMaxBuffers = 8

type readyReadResult struct {
	buffer *Buffer
	err    error
}

// ReadyReader turns a plain io.Reader into a MultiBuffer reader without
// waiting for future data. A single producer performs blocking reads; each
// ReadMultiBuffer blocks for the first result and then drains only results
// already queued by the producer.
type ReadyReader struct {
	reader  io.Reader
	results chan readyReadResult
	done    chan struct{}
	stop    sync.Once
	stopped atomic.Bool

	pendingErr error
}

func NewReadyReader(reader io.Reader) *ReadyReader {
	r := &ReadyReader{
		reader:  reader,
		results: make(chan readyReadResult, readyReaderMaxBuffers),
		done:    make(chan struct{}),
	}
	go r.readLoop()
	return r
}

func (r *ReadyReader) readLoop() {
	defer func() {
		if r.stopped.Load() {
			for {
				select {
				case result := <-r.results:
					if result.buffer != nil {
						result.buffer.Release()
					}
				default:
					close(r.results)
					return
				}
			}
		}
		close(r.results)
	}()

	for {
		select {
		case <-r.done:
			return
		default:
		}
		buffer, err := ReadBuffer(r.reader)
		result := readyReadResult{buffer: buffer, err: err}
		select {
		case r.results <- result:
		case <-r.done:
			if buffer != nil {
				buffer.Release()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

// ReadMultiBuffer blocks for one buffer, then batches only data which is
// already available from the read-ahead queue.
func (r *ReadyReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.pendingErr != nil {
		err := r.pendingErr
		r.pendingErr = nil
		return nil, err
	}

	first, ok := <-r.results
	if !ok {
		return nil, io.EOF
	}

	mb := make(MultiBuffer, 0, readyReaderMaxBuffers)
	if first.buffer != nil {
		mb = append(mb, first.buffer)
	}
	if first.err != nil {
		if len(mb) == 0 {
			return nil, first.err
		}
		r.pendingErr = first.err
		return mb, nil
	}

	for len(mb) < readyReaderMaxBuffers {
		select {
		case result, open := <-r.results:
			if !open {
				return mb, io.EOF
			}
			if result.buffer != nil {
				mb = append(mb, result.buffer)
			}
			if result.err != nil {
				if len(mb) == 0 {
					return nil, result.err
				}
				r.pendingErr = result.err
				return mb, nil
			}
		default:
			return mb, nil
		}
	}
	return mb, nil
}

// Interrupt stops delivery and releases queued buffers. Closing the
// underlying reader remains the owner's responsibility and unblocks any read
// currently in progress.
func (r *ReadyReader) Interrupt() {
	r.stop.Do(func() {
		r.stopped.Store(true)
		close(r.done)
	})
}
