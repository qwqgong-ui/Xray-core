package hybrid

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
)

var shared = struct {
	sync.Mutex
	servers map[netip.AddrPort]*Server
}{servers: make(map[netip.AddrPort]*Server)}

func RegisterShared(address netip.AddrPort, s *Server) error {
	shared.Lock()
	defer shared.Unlock()
	if shared.servers[address] != nil {
		return errors.New("hybrid: duplicate shared listener")
	}
	shared.servers[address] = s
	return nil
}
func UnregisterShared(address netip.AddrPort, s *Server) {
	shared.Lock()
	defer shared.Unlock()
	if shared.servers[address] == s {
		delete(shared.servers, address)
	}
}

// WrapShared is the only HY2 integration. Unclaimed packets are always passed
// through; raw demultiplexing takes place before any transport UDP mask.
//
// A socket that can carry out-of-band data is wrapped so that it still can.
// Hiding SyscallConn/ReadMsgUDP/WriteMsgUDP behind a plain net.PacketConn
// costs this listener UDP GSO, ECN and the don't-fragment bit, because quic-go
// decides what a connection can do from its method set alone.
//
// Exposing them is only half of it. quic-go reads an OOB-capable connection in
// batches, and builds that batch reader from the file descriptor unless the
// connection already provides one, in which case neither ReadFrom nor
// ReadMsgUDP is ever called and raw packets stop reaching HandleRaw. So the
// wrapper provides the batch reader itself and demultiplexes inside it.
func WrapShared(c net.PacketConn) (net.PacketConn, error) {
	a, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return c, nil
	}
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	shared.Lock()
	s := shared.servers[a]
	shared.Unlock()
	if s == nil {
		return c, nil
	}
	if err = s.Attach(c); err != nil {
		return nil, err
	}
	shared := &sharedConn{PacketConn: c, server: s}
	if oob, ok := c.(oobPacketConn); ok {
		return &sharedOOBConn{sharedConn: shared, inner: oob, batch: ipv4.NewPacketConn(oob)}, nil
	}
	return shared, nil
}

// oobPacketConn is what quic-go requires before it will use UDP GSO, read ECN,
// or set the don't-fragment bit. *net.UDPConn satisfies it; a wrapper that
// embeds net.PacketConn does not.
type oobPacketConn interface {
	net.PacketConn
	// net.Conn as well, because x/net builds its batch reader from one.
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	RemoteAddr() net.Addr

	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

type sharedConn struct {
	net.PacketConn
	server *Server
	readMu sync.Mutex
	buffer [65536]byte
}

// sharedOOBConn demultiplexes raw packets exactly as sharedConn does, on every
// path a reader might take, while leaving the socket's own capabilities
// visible.
type sharedOOBConn struct {
	*sharedConn
	inner oobPacketConn
	batch *ipv4.PacketConn // recvmmsg over the same socket; ipv6 shares the type
}

func (c *sharedOOBConn) SyscallConn() (syscall.RawConn, error) { return c.inner.SyscallConn() }
func (c *sharedOOBConn) SetReadBuffer(size int) error          { return c.inner.SetReadBuffer(size) }
func (c *sharedOOBConn) SetWriteBuffer(size int) error         { return c.inner.SetWriteBuffer(size) }
func (c *sharedOOBConn) Write(b []byte) (int, error)           { return c.inner.Write(b) }
func (c *sharedOOBConn) RemoteAddr() net.Addr                  { return c.inner.RemoteAddr() }

func (c *sharedOOBConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	return c.inner.WriteMsgUDP(b, oob, addr)
}

// Read takes the demultiplexing path so a raw packet cannot reach a reader by
// this route either.
func (c *sharedOOBConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// ReadMsgUDP consumes the packets a hybrid flow claims and returns the rest
// with the out-of-band data that came with them.
func (c *sharedOOBConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, oobn, flags, addr, err := c.inner.ReadMsgUDP(c.buffer[:], oob)
		if err != nil {
			c.server.rawFailed()
			return n, oobn, flags, addr, err
		}
		if !c.server.HandleRaw(c.buffer[:n], addr) {
			return copy(b, c.buffer[:n]), oobn, flags, addr, nil
		}
	}
}

// ReadBatch is the path quic-go actually reads through. Messages a hybrid flow
// claims are taken out and the rest are moved down to close the gap, so the
// caller keeps every buffer it handed in and each message still owns the one
// it was given. A batch holding nothing but raw packets reads again rather
// than reporting zero, which the caller would treat as an error.
func (c *sharedOOBConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	for {
		n, err := c.batch.ReadBatch(ms, flags)
		if err != nil {
			c.server.rawFailed()
			return n, err
		}
		kept := 0
		for i := range n {
			m := &ms[i]
			if len(m.Buffers) > 0 && c.server.HandleRaw(m.Buffers[0][:m.N], m.Addr) {
				continue
			}
			if kept != i {
				// Copy into the slot's own buffer; never move the buffers
				// themselves, which the caller tracks by position.
				dst := &ms[kept]
				dst.N = copy(dst.Buffers[0], m.Buffers[0][:m.N])
				dst.NN = copy(dst.OOB, m.OOB[:m.NN])
				dst.Flags, dst.Addr = m.Flags, m.Addr
			}
			kept++
		}
		if kept > 0 {
			return kept, nil
		}
	}
}

func (c *sharedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, a, e := c.PacketConn.ReadFrom(c.buffer[:])
		if e != nil {
			c.server.rawFailed()
			return n, a, e
		}
		if !c.server.HandleRaw(c.buffer[:n], a) {
			return copy(p, c.buffer[:n]), a, nil
		}
	}
}
