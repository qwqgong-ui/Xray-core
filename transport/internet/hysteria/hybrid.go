package hysteria

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	hybridControlHost = "hybrid-quic.invalid:443"
	hybridMagic       = "HQV1"
	hybridOpInitial   = byte(1)
	hybridFlowTTL     = 2 * time.Minute
)

// hybridManager owns the raw half of authenticated hybrid QUIC flows. Until an
// authenticated Hysteria session registers an exact IPv6 address and UDP port,
// packets simply continue to quic-go and can never reach a target socket.
type hybridManager struct {
	conn net.PacketConn

	mu          sync.RWMutex
	flows       map[netip.AddrPort]*hybridFlow
	sessions    map[*hybridSession]struct{}
	hy2         map[netip.AddrPort]int
	candidates  map[netip.AddrPort]time.Time
	passUnknown bool
	closed      chan struct{}
}

type hybridSession struct {
	manager *hybridManager
	remote  netip.Addr

	mu     sync.Mutex
	flows  map[[16]byte]*hybridFlow
	closed bool
}

type hybridFlow struct {
	session *hybridSession
	id      [16]byte
	client  netip.AddrPort
	target  netip.AddrPort
	conn    *net.UDPConn

	mu       sync.Mutex
	lastSeen time.Time
	closed   bool
}

type hybridPacketConn struct {
	net.PacketConn
	manager *hybridManager
}

func newHybridManager(conn net.PacketConn) *hybridManager {
	m := &hybridManager{
		conn:       conn,
		flows:      make(map[netip.AddrPort]*hybridFlow),
		sessions:   make(map[*hybridSession]struct{}),
		hy2:        make(map[netip.AddrPort]int),
		candidates: make(map[netip.AddrPort]time.Time),
		closed:     make(chan struct{}),
	}
	go m.clean()
	return m
}

func (m *hybridManager) wrap() net.PacketConn {
	return &hybridPacketConn{PacketConn: m.conn, manager: m}
}

func (c *hybridPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, source, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}
		client, ok := udpAddrPort(source)
		if !ok {
			return n, source, nil
		}
		c.manager.mu.RLock()
		flow := c.manager.flows[client]
		c.manager.mu.RUnlock()
		if flow == nil {
			if c.manager.allowQUIC(client, p[:n]) {
				return n, source, nil
			}
			// Unknown non-Initial traffic is dropped before quic-go. It never
			// reaches the authenticated raw relay table.
			continue
		}
		if err := flow.writeTarget(p[:n]); err != nil {
			flow.close()
		}
	}
}

func (m *hybridManager) allowQUIC(client netip.AddrPort, packet []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.passUnknown || m.hy2[client] > 0 {
		return true
	}
	now := time.Now()
	if expiry := m.candidates[client]; expiry.After(now) {
		return true
	}
	if !isServerQUICInitial(packet) {
		delete(m.candidates, client)
		return false
	}
	m.candidates[client] = now.Add(10 * time.Second)
	return true
}

func (m *hybridManager) establishHY2(remote net.Addr) func() {
	client, ok := udpAddrPort(remote)
	if !ok {
		return func() {}
	}
	m.mu.Lock()
	m.hy2[client]++
	delete(m.candidates, client)
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		if m.hy2[client] <= 1 {
			delete(m.hy2, client)
		} else {
			m.hy2[client]--
		}
		m.mu.Unlock()
	}
}

func isServerQUICInitial(packet []byte) bool {
	if len(packet) < 5 || packet[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	packetType := (packet[0] >> 4) & 0x3
	switch version {
	case 1:
		return packetType == 0
	case 0x6b3343cf:
		return packetType == 1
	default:
		return false
	}
}

func (m *hybridManager) newSession(remote net.Addr) *hybridSession {
	addrPort, ok := udpAddrPort(remote)
	if !ok || !isPublicIPv6(addrPort.Addr()) {
		return nil
	}
	s := &hybridSession{manager: m, remote: addrPort.Addr(), flows: make(map[[16]byte]*hybridFlow)}
	m.mu.Lock()
	m.sessions[s] = struct{}{}
	m.mu.Unlock()
	return s
}

func (s *hybridSession) handle(data []byte) error {
	if s == nil {
		return errors.New("hybrid QUIC requires public IPv6")
	}
	if len(data) < 42 || string(data[:4]) != hybridMagic || data[4] != hybridOpInitial {
		return errors.New("invalid hybrid QUIC control message")
	}
	var id [16]byte
	copy(id[:], data[5:21])
	rawPort := binary.BigEndian.Uint16(data[21:23])
	family := data[23]
	targetBytes := data[24:40]
	targetPort := binary.BigEndian.Uint16(data[40:42])
	payload := data[42:]
	if rawPort == 0 || targetPort != 443 || len(payload) == 0 {
		return errors.New("invalid hybrid QUIC endpoint")
	}
	var targetAddr netip.Addr
	switch family {
	case 4:
		targetAddr = netip.AddrFrom4([4]byte(targetBytes[12:16]))
	case 6:
		targetAddr = netip.AddrFrom16([16]byte(targetBytes))
	default:
		return errors.New("invalid hybrid QUIC address family")
	}
	if !isPublicTarget(targetAddr) {
		return errors.New("hybrid QUIC target is not public")
	}
	client := netip.AddrPortFrom(s.remote, rawPort)
	target := netip.AddrPortFrom(targetAddr, targetPort)
	flow, err := s.register(id, client, target)
	if err != nil {
		return err
	}
	return flow.writeTarget(payload)
}

func (s *hybridSession) register(id [16]byte, client, target netip.AddrPort) (*hybridFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, net.ErrClosed
	}
	if existing := s.flows[id]; existing != nil {
		if existing.client != client || existing.target != target {
			return nil, errors.New("hybrid QUIC flow id collision")
		}
		return existing, nil
	}

	network := "udp4"
	if target.Addr().Is6() {
		network = "udp6"
	}
	targetConn, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return nil, err
	}
	flow := &hybridFlow{session: s, id: id, client: client, target: target, conn: targetConn, lastSeen: time.Now()}
	s.manager.mu.Lock()
	if s.manager.hy2[client] > 0 {
		s.manager.mu.Unlock()
		_ = targetConn.Close()
		return nil, errors.New("hybrid QUIC raw tuple collides with HY2")
	}
	if other := s.manager.flows[client]; other != nil {
		s.manager.mu.Unlock()
		_ = targetConn.Close()
		return nil, errors.New("hybrid QUIC raw tuple already registered")
	}
	s.manager.flows[client] = flow
	s.manager.mu.Unlock()
	s.flows[id] = flow
	go flow.readTarget()
	return flow, nil
}

func (f *hybridFlow) writeTarget(payload []byte) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	f.lastSeen = time.Now()
	f.mu.Unlock()
	_, err := f.conn.Write(payload)
	return err
}

func (f *hybridFlow) readTarget() {
	buffer := make([]byte, 64*1024)
	for {
		n, err := f.conn.Read(buffer)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.lastSeen = time.Now()
		closed := f.closed
		f.mu.Unlock()
		if closed {
			return
		}
		if _, err = f.session.manager.conn.WriteTo(buffer[:n], net.UDPAddrFromAddrPort(f.client)); err != nil {
			f.close()
			return
		}
	}
}

func (f *hybridFlow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.mu.Unlock()
	_ = f.conn.Close()
	m := f.session.manager
	m.mu.Lock()
	if m.flows[f.client] == f {
		delete(m.flows, f.client)
	}
	m.mu.Unlock()
	f.session.mu.Lock()
	if f.session.flows[f.id] == f {
		delete(f.session.flows, f.id)
	}
	f.session.mu.Unlock()
}

func (s *hybridSession) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	flows := make([]*hybridFlow, 0, len(s.flows))
	for _, flow := range s.flows {
		flows = append(flows, flow)
	}
	s.mu.Unlock()
	for _, flow := range flows {
		flow.close()
	}
	s.manager.mu.Lock()
	delete(s.manager.sessions, s)
	s.manager.mu.Unlock()
}

func (m *hybridManager) clean() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mu.RLock()
			flows := make([]*hybridFlow, 0, len(m.flows))
			for _, flow := range m.flows {
				flows = append(flows, flow)
			}
			m.mu.RUnlock()
			now := time.Now()
			m.mu.Lock()
			for client, expiry := range m.candidates {
				if !expiry.After(now) {
					delete(m.candidates, client)
				}
			}
			m.mu.Unlock()
			for _, flow := range flows {
				flow.mu.Lock()
				expired := now.Sub(flow.lastSeen) > hybridFlowTTL
				flow.mu.Unlock()
				if expired {
					flow.close()
				}
			}
		case <-m.closed:
			return
		}
	}
}

func (m *hybridManager) close() {
	select {
	case <-m.closed:
		return
	default:
		close(m.closed)
	}
	m.mu.RLock()
	sessions := make([]*hybridSession, 0, len(m.sessions))
	for session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()
	for _, session := range sessions {
		session.close()
	}
}

func udpAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return netip.AddrPort{}, false
	}
	addrPort := udpAddr.AddrPort()
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), addrPort.IsValid()
}

func isPublicIPv6(addr netip.Addr) bool {
	return addr.Is6() && isPublicTarget(addr)
}

func isPublicTarget(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsUnspecified()
}

// HandleHybridQUIC is exposed through a tiny interface so the proxy layer can
// consume the reserved authenticated destination without a package cycle.
func (c *InterConn) HandleHybridQUIC(destination string, data []byte) (bool, error) {
	if destination != hybridControlHost {
		return false, nil
	}
	if c.hybridSession == nil {
		return true, errors.New("hybrid QUIC is unavailable for this session")
	}
	return true, c.hybridSession.handle(data)
}
