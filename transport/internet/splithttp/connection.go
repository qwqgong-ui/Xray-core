package splithttp

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()

	readyEnabled bool
	readOnce     sync.Once
	readMutex    sync.Mutex
	buffered     *buf.BufferedReader
	readyInput   atomic.Pointer[buf.ReadyReader]
}

type downlinkWriteAggregator interface {
	SetDownlinkWriteAggregation(bool)
}

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

// WriteMultiBuffer preserves batch boundaries for writers which understand
// them. Client-side upload writers (notably io.Pipe) still use the same
// sequential fallback as buf.SequentialWriter.
func (c *splitConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if writer, ok := c.writer.(buf.Writer); ok {
		return writer.WriteMultiBuffer(mb)
	}

	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *splitConn) Read(b []byte) (int, error) {
	if !c.readyEnabled {
		return c.reader.Read(b)
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	c.initReadyInput()
	return c.buffered.Read(b)
}

func (c *splitConn) initReadyInput() {
	c.readOnce.Do(func() {
		ready := buf.NewReadyReader(c.reader)
		c.readyInput.Store(ready)
		c.buffered = &buf.BufferedReader{Reader: ready}
	})
}

func (c *splitConn) enableReadyInput() {
	c.readyEnabled = true
	c.initReadyInput()
}

// ReadMultiBuffer lets XHTTP uplinks retain the 8 KiB chunks which are
// already available instead of collapsing the stream into one Buffer per
// copy iteration.
func (c *splitConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if !c.readyEnabled {
		buffer, err := buf.ReadBuffer(c.reader)
		if buffer == nil {
			return nil, err
		}
		return buf.MultiBuffer{buffer}, err
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	c.initReadyInput()
	return c.buffered.ReadMultiBuffer()
}

// SetDownlinkWriteAggregation toggles transport-level response batching when
// the upper-layer proxy has enough metadata to opt this connection in.
func (c *splitConn) SetDownlinkWriteAggregation(enabled bool) {
	if writer, ok := c.writer.(downlinkWriteAggregator); ok {
		writer.SetDownlinkWriteAggregation(enabled)
	}
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	if ready := c.readyInput.Load(); ready != nil {
		ready.Interrupt()
	}

	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}

	if err2 != nil {
		return err
	}

	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}
