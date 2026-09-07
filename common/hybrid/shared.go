package hybrid

import (
	"errors"
	"net"
	"net/netip"
	"sync"
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
	return &sharedConn{PacketConn: c, server: s}, nil
}

type sharedConn struct {
	net.PacketConn
	server *Server
	readMu sync.Mutex
	buffer [65536]byte
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
