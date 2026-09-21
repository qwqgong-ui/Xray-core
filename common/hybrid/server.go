package hybrid

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// rawStale is how long a binding survives without a raw packet from the
// client. Past it the flow answers on the stream and a NAT that remapped the
// client may bind a new tuple. It is well past the client's own silence
// timeout, so it never races the client's own fallback.
const rawStale = 60 * time.Second

type Target interface {
	WritePacket([]byte) error
	// ReadPackets waits for the target's next datagram and returns it with
	// every other one already queued, in order. The slices stay valid until
	// the next call.
	ReadPackets() ([][]byte, error)
	Close() error
}
type Dial func(context.Context, string) (Target, netip.AddrPort, error)

// Server belongs to one dispatcher. Its flows belong to streams, never a HY2
// session. The lock also serializes CID claims, binding and permanent disable.
type Server struct {
	mu         sync.Mutex
	conn       net.PacketConn
	advertised netip.AddrPort
	flows      map[*flow]struct{}
	cids       map[string]*flow
	tuples     map[netip.AddrPort]*flow
	closed     bool
	gso        atomic.Bool // the raw socket takes UDP_SEGMENT
}
type flow struct {
	server    *Server
	stream    io.ReadWriteCloser
	target    Target
	peer      netip.Addr
	tuple     netip.AddrPort
	lastRaw   time.Time
	disabled  bool
	paused    bool
	cids      []string
	writeMu   sync.Mutex
	closeOnce sync.Once
	cancel    context.CancelFunc
}

func NewServer(advertised netip.AddrPort) *Server {
	return &Server{advertised: advertised, flows: make(map[*flow]struct{}), cids: make(map[string]*flow), tuples: make(map[netip.AddrPort]*flow)}
}
func (s *Server) Attach(conn net.PacketConn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.conn != nil && s.conn != conn {
		return errors.New("hybrid: raw socket already attached")
	}
	s.conn = conn
	s.gso.Store(gsoSupported(conn))
	return nil
}
func (s *Server) ReadRaw(conn net.PacketConn) {
	p := make([]byte, 65536)
	for {
		n, a, err := conn.ReadFrom(p)
		if err != nil {
			s.rawFailed()
			return
		}
		s.HandleRaw(p[:n], a)
	}
}

// HandleRaw consumes only packets claimed by an active hybrid flow. All other
// packets pass untouched to a shared QUIC listener, including NAT rebinding.
func (s *Server) HandleRaw(p []byte, addr net.Addr) bool {
	if !Short(p) {
		return false
	}
	var a netip.AddrPort
	if u, ok := addr.(*net.UDPAddr); ok {
		a = u.AddrPort()
	} else {
		var err error
		if a, err = netip.ParseAddrPort(addr.String()); err != nil {
			return false
		}
	}
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	now := time.Now()
	s.mu.Lock()
	f := s.tuples[a]
	if f == nil {
		for cid, candidate := range s.cids {
			if len(p) > len(cid) && string(p[1:1+len(cid)]) == cid {
				// Different-length prefix collisions must never select an arbitrary flow.
				if f != nil && f != candidate {
					s.mu.Unlock()
					return false
				}
				f = candidate
			}
		}
		// A bound tuple only gives way once it has gone quiet for rawStale:
		// that is a NAT that remapped the client, not a second live path
		// claiming the same flow.
		if f == nil || f.disabled || f.peer != a.Addr() || (f.tuple.IsValid() && f.tuple != a && now.Sub(f.lastRaw) < rawStale) {
			s.mu.Unlock()
			return false
		}
		if s.tuples[f.tuple] == f {
			delete(s.tuples, f.tuple)
		}
		f.tuple = a
		s.tuples[a] = f
	}
	if f.disabled {
		s.mu.Unlock()
		return false
	}
	// Raw from the client proves the path and lifts a pause: a client that
	// fell back to the stream resumes raw by sending on it again.
	f.paused = false
	f.lastRaw = now
	target := f.target
	s.mu.Unlock()
	// A blocked destination must not stall the shared listener. The target
	// adapter supplies bounded, nonblocking enqueueing and one writer goroutine.
	if err := target.WritePacket(p); err != nil {
		f.close()
	}
	return true
}
func (s *Server) claim(f *flow, cid string) {
	// A zero-length CID cannot identify an independent raw flow.
	if len(cid) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.disabled || len(f.cids) >= 8 {
		return
	}
	if _, ok := s.flows[f]; !ok {
		return
	}
	for existing, owner := range s.cids {
		if existing == cid && owner == f {
			return
		}
		n := min(len(existing), len(cid))
		if existing[:n] == cid[:n] && owner != f {
			return
		}
	}
	s.cids[cid] = f
	f.cids = append(f.cids, cid)
}

// pause stops sending raw downstream without giving the flow up. The binding
// and the claimed CIDs stay, so the client's next raw packet resumes it; a
// client that never sends raw again leaves the flow on the stream for good.
func (f *flow) pause() {
	s := f.server
	s.mu.Lock()
	defer s.mu.Unlock()
	f.paused = true
}
func (f *flow) disable() {
	s := f.server
	s.mu.Lock()
	defer s.mu.Unlock()
	f.disabled = true
	if s.tuples[f.tuple] == f {
		delete(s.tuples, f.tuple)
	}
	for _, cid := range f.cids {
		if s.cids[cid] == f {
			delete(s.cids, cid)
		}
	}
	f.cids = nil
}
func (f *flow) send(p []byte) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	return WriteFrame(f.stream, p)
}
func (f *flow) close() {
	f.closeOnce.Do(func() {
		f.disable()
		f.cancel()
		f.stream.Close()
		f.server.mu.Lock()
		target := f.target
		delete(f.server.flows, f)
		f.server.mu.Unlock()
		if target != nil {
			target.Close()
		}
	})
}
func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser, peer netip.Addr, address string, dial Dial) error {
	ctx, cancel := context.WithCancel(ctx)
	f := &flow{server: s, stream: stream, peer: peer.Unmap(), cancel: cancel}
	s.mu.Lock()
	if s.closed || len(s.flows) >= 1024 {
		s.mu.Unlock()
		cancel()
		stream.Close()
		return errors.New("hybrid: unavailable or flow limit reached")
	}
	s.flows[f] = struct{}{}
	s.mu.Unlock()
	defer f.close()
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	t, resolved, err := dial(ctx, address)
	if err != nil {
		return err
	}
	// Install the target under the same lock as Close/HandleRaw. Before this
	// point there are no CIDs, so raw cannot reach a partially initialized flow.
	s.mu.Lock()
	if s.closed || ctx.Err() != nil {
		s.mu.Unlock()
		t.Close()
		return net.ErrClosed
	}
	f.target = t
	conn := s.conn
	s.mu.Unlock()
	if err = WriteAll(stream, []byte{0}); err != nil {
		return err
	}
	if err = WriteAddress(stream, resolved.String()); err != nil {
		return err
	}
	relay := s.advertised
	if conn == nil || !peer.IsValid() {
		relay = netip.MustParseAddrPort("0.0.0.0:443")
		f.disable()
	}
	if err = WriteAddress(stream, relay.String()); err != nil {
		return err
	}
	go f.readTarget()
	go f.keepAlive(ctx)
	for {
		p, err := ReadFrame(stream)
		if err != nil {
			return err
		}
		if p == nil {
			continue
		}
		if len(p) == 0 {
			f.pause()
			continue
		}
		if dcid, _, ok := LongCIDs(p); ok {
			s.claim(f, dcid)
		}
		if err = t.WritePacket(p); err != nil {
			return err
		}
	}
}
func (f *flow) readTarget() {
	defer f.close()
	s := f.server
	for {
		ps, err := f.target.ReadPackets()
		if err != nil {
			return
		}
		for _, p := range ps {
			if _, scid, ok := LongCIDs(p); ok {
				s.claim(f, scid)
			}
		}
		// One look at the binding serves the whole batch.
		s.mu.Lock()
		conn := s.conn
		raw := conn != nil && !f.disabled && !f.paused && f.tuple.IsValid() && time.Since(f.lastRaw) < rawStale
		tuple := f.tuple
		s.mu.Unlock()
		for len(ps) > 0 {
			// The short-header packets at the front go out raw together.
			n := 0
			for raw && n < len(ps) && Short(ps[n]) {
				n++
			}
			if n > 0 {
				sent, err := s.writeRaw(conn, tuple, ps[:n])
				ps = ps[sent:]
				if err == nil {
					continue
				}
				raw = false
				f.disable()
				if f.send(nil) != nil {
					return
				}
			}
			if f.send(ps[0]) != nil {
				return
			}
			ps = ps[1:]
		}
	}
}
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	flows := make([]*flow, 0, len(s.flows))
	for f := range s.flows {
		flows = append(flows, f)
	}
	s.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
	return nil
}

func (f *flow) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.writeMu.Lock()
			err := WriteKeepAlive(f.stream)
			f.writeMu.Unlock()
			if err != nil {
				f.close()
				return
			}
		}
	}
}
func (s *Server) rawFailed() {
	s.mu.Lock()
	s.conn = nil
	flows := make([]*flow, 0, len(s.flows))
	for f := range s.flows {
		flows = append(flows, f)
	}
	s.mu.Unlock()
	for _, f := range flows {
		f.disable()
		go func() {
			if f.send(nil) != nil {
				f.close()
			}
		}()
	}
}
