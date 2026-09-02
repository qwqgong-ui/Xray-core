package hysteria

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	hybridControlHost = "hybrid-quic.invalid:443"
	// The wire format changed incompatibly with HQV1: the client no longer
	// reports its own raw port (the server observes it instead) and the target
	// may now be a domain the server resolves itself. Bumping the magic makes
	// an old peer fail cleanly rather than misparse a shifted header.
	hybridMagic     = "HQV2"
	hybridOpInitial = byte(1)
	hybridOpAck     = byte(2)

	hybridTargetDomain = byte(0)
	hybridTargetIPv4   = byte(4)
	hybridTargetIPv6   = byte(6)

	hybridAckOK     = byte(0)
	hybridAckFailed = byte(1)

	hybridFlowTTL = 2 * time.Minute

	// hybridMaxFlowCIDs bounds the connection IDs one flow may claim. A flow
	// needs two in the normal case (the client's original Initial DCID and the
	// server's first SCID); the rest of the budget absorbs Retry and early
	// rotation.
	hybridMaxFlowCIDs = 8
)

// hybridManager owns the raw half of authenticated hybrid QUIC flows. Until an
// authenticated Hysteria session registers an exact IPv6 address and UDP port,
// packets simply continue to quic-go and can never reach a target socket.
type hybridManager struct {
	conn net.PacketConn

	mu       sync.RWMutex
	flows    map[netip.AddrPort]*hybridFlow
	sessions map[*hybridSession]struct{}
	hy2      map[netip.AddrPort]int
	// byCID bootstraps a flow before its raw tuple is known. It holds the
	// connection IDs a flow may be addressed by: the DCID of the client's own
	// Initial (which also covers 0-RTT) and the SCID the target chose in its
	// first reply. The client learns the latter only from that reply, which the
	// server sends back through the tunnel, so a raw packet carrying it cannot
	// arrive before the entry exists.
	byCID       map[string]*hybridFlow
	candidates  map[netip.AddrPort]time.Time
	passUnknown bool
	closed      chan struct{}
}

type hybridSession struct {
	manager *hybridManager
	remote  netip.Addr
	// send delivers a datagram back over this client's authenticated tunnel,
	// attributed to the given source. It carries the target's replies until the
	// flow's raw tuple is bound, and the registration acknowledgements.
	send func(payload []byte, from xnet.Destination) error

	mu     sync.Mutex
	flows  map[[16]byte]*hybridFlow
	closed bool
}

type hybridFlow struct {
	session *hybridSession
	id      [16]byte
	target  netip.AddrPort
	conn    *net.UDPConn

	mu sync.Mutex
	// client is the raw tuple as this server observed it, zero until a raw
	// packet has been matched to this flow by connection ID. Until then the
	// target's replies go back through the tunnel, which is also what keeps the
	// server from sending to an unbound tuple.
	client   netip.AddrPort
	bound    bool
	cids     []string
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
		byCID:      make(map[string]*hybridFlow),
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
			flow = c.manager.bind(client, p[:n])
		}
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

// bind attaches an as-yet-unseen raw tuple to the flow the packet's connection
// ID belongs to, and reports that flow.
//
// Only long-header packets can bootstrap. A short header does not encode its
// DCID length, so it cannot be parsed without already knowing the connection --
// and it does not need to: the first packet a client sends on the raw path is
// its Handshake (or 0-RTT), both of which are long-header. Anything short-header
// from an unknown tuple is therefore not a flow of ours.
//
// The observed address must belong to the session that registered the flow.
// Connection IDs travel in cleartext on the raw path, so an on-path observer can
// read one and replay it from its own tuple; without this check that would hand
// the target's traffic to whoever sent the packet. NAT rewrites the port rather
// than the address, so requiring the address still leaves IPv4 clients working.
func (m *hybridManager) bind(client netip.AddrPort, packet []byte) *hybridFlow {
	dcid, _, ok := longHeaderConnectionIDs(packet)
	if !ok || dcid == "" {
		return nil
	}

	m.mu.Lock()
	flow := m.byCID[dcid]
	if flow == nil || m.hy2[client] > 0 || m.flows[client] != nil {
		m.mu.Unlock()
		return nil
	}
	if flow.session.remote != client.Addr() {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	flow.mu.Lock()
	if flow.closed {
		flow.mu.Unlock()
		return nil
	}
	if flow.bound {
		bound := flow.client
		flow.mu.Unlock()
		if bound == client {
			return flow
		}
		// The flow already migrated to another tuple; this one is stale.
		return nil
	}
	flow.client = client
	flow.bound = true
	flow.mu.Unlock()

	m.mu.Lock()
	if m.flows[client] == nil {
		m.flows[client] = flow
	}
	m.mu.Unlock()
	return flow
}

// claimCID lets a flow be addressed by one more connection ID. A CID already
// claimed by a different flow is left alone rather than stolen: two flows
// answering to the same ID cannot both be right, and dropping the packet is
// better than relaying it to the wrong target.
func (m *hybridManager) claimCID(flow *hybridFlow, cid string) {
	if cid == "" {
		return
	}
	flow.mu.Lock()
	if flow.closed || len(flow.cids) >= hybridMaxFlowCIDs {
		flow.mu.Unlock()
		return
	}
	for _, existing := range flow.cids {
		if existing == cid {
			flow.mu.Unlock()
			return
		}
	}
	flow.cids = append(flow.cids, cid)
	flow.mu.Unlock()

	m.mu.Lock()
	if m.byCID[cid] == nil {
		m.byCID[cid] = flow
	}
	m.mu.Unlock()
}

// longHeaderConnectionIDs reads the two connection IDs out of a QUIC long
// header. Version and both IDs sit outside header protection, so this needs no
// key material and interprets nothing else about the packet.
func longHeaderConnectionIDs(packet []byte) (destination, source string, ok bool) {
	if len(packet) < 7 || packet[0]&0xc0 != 0xc0 || packet[1]|packet[2]|packet[3]|packet[4] == 0 {
		return "", "", false
	}
	destinationLength := int(packet[5])
	if destinationLength > 20 || 6+destinationLength >= len(packet) {
		return "", "", false
	}
	destinationEnd := 6 + destinationLength
	sourceLength := int(packet[destinationEnd])
	sourceStart := destinationEnd + 1
	sourceEnd := sourceStart + sourceLength
	if sourceLength > 20 || sourceEnd > len(packet) {
		return "", "", false
	}
	return string(packet[6:destinationEnd]), string(packet[sourceStart:sourceEnd]), true
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
	// Any public address will do. The raw tuple is observed rather than
	// self-reported, so a client behind IPv4 NAT is no longer a problem: NAT
	// rewrites the port, and the destination of the raw socket never changes,
	// so even a symmetric NAT keeps one stable mapping.
	if !ok || !isPublicTarget(addrPort.Addr()) {
		return nil
	}
	s := &hybridSession{manager: m, remote: addrPort.Addr(), flows: make(map[[16]byte]*hybridFlow)}
	m.mu.Lock()
	m.sessions[s] = struct{}{}
	m.mu.Unlock()
	return s
}

func (s *hybridSession) sender() func([]byte, xnet.Destination) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.send
}

func (s *hybridSession) handle(data []byte) error {
	if s == nil {
		return errors.New("hybrid QUIC is unavailable for this session")
	}
	id, target, payload, err := parseHybridInitial(data)
	if err != nil {
		return err
	}

	flow, err := s.register(id, target)
	if err != nil {
		s.ack(id, hybridAckFailed)
		return err
	}
	// The client's own Initial DCID is what its 0-RTT and Handshake packets are
	// addressed to, so claiming it here is what lets the very first raw packet
	// find this flow.
	if dcid, _, ok := longHeaderConnectionIDs(payload); ok {
		s.manager.claimCID(flow, dcid)
	}
	if err = flow.writeTarget(payload); err != nil {
		s.ack(id, hybridAckFailed)
		return err
	}
	s.ack(id, hybridAckOK)
	return nil
}

// parseHybridInitial decodes an op=1 registration. The target is either a
// literal address or a domain the server resolves itself, which is what keeps a
// fake-IP client from having to un-map its own synthetic address before it can
// register -- and what makes the destination independent of whatever the
// application put in its (possibly ECH-encrypted) ClientHello.
func parseHybridInitial(data []byte) (id [16]byte, target xnet.Destination, payload []byte, err error) {
	if len(data) < 24 || string(data[:4]) != hybridMagic || data[4] != hybridOpInitial {
		return id, target, nil, errors.New("invalid hybrid QUIC control message")
	}
	copy(id[:], data[5:21])
	rest := data[21:]

	var address xnet.Address
	switch rest[0] {
	case hybridTargetDomain:
		nameLen := int(rest[1])
		if nameLen == 0 || len(rest) < 2+nameLen+2 {
			return id, target, nil, errors.New("invalid hybrid QUIC domain")
		}
		address = xnet.DomainAddress(string(rest[2 : 2+nameLen]))
		rest = rest[2+nameLen:]
	case hybridTargetIPv4:
		if len(rest) < 1+4+2 {
			return id, target, nil, errors.New("invalid hybrid QUIC IPv4 target")
		}
		address = xnet.IPAddress(rest[1:5])
		rest = rest[5:]
	case hybridTargetIPv6:
		if len(rest) < 1+16+2 {
			return id, target, nil, errors.New("invalid hybrid QUIC IPv6 target")
		}
		address = xnet.IPAddress(rest[1:17])
		rest = rest[17:]
	default:
		return id, target, nil, errors.New("invalid hybrid QUIC address type")
	}

	port := binary.BigEndian.Uint16(rest[:2])
	payload = rest[2:]
	if port != 443 || len(payload) == 0 {
		return id, target, nil, errors.New("invalid hybrid QUIC endpoint")
	}
	return id, xnet.UDPDestination(address, xnet.Port(port)), payload, nil
}

// ack reports the outcome of a registration over the tunnel. Without it a
// rejected registration is indistinguishable to the client from a silent path
// failure, and it would keep sending on a raw socket nothing is listening for.
func (s *hybridSession) ack(id [16]byte, status byte) {
	send := s.sender()
	if send == nil {
		return
	}
	message := make([]byte, 22)
	copy(message[:4], hybridMagic)
	message[4] = hybridOpAck
	copy(message[5:21], id[:])
	message[21] = status
	_ = send(message, xnet.UDPDestination(xnet.DomainAddress("hybrid-quic.invalid"), xnet.Port(443)))
}

// resolveHybridTarget turns the registered destination into one concrete
// address. A domain is resolved with Xray's own DNS client, so the server side
// of a hybrid flow reaches the same host that an ordinary Hysteria UDP session
// to that name would.
func resolveHybridTarget(destination xnet.Destination) (netip.AddrPort, error) {
	address := destination.Address
	if address.Family().IsDomain() {
		ips, err := internet.LookupForIP(address.Domain(), internet.DomainStrategy_USE_IP, nil)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if len(ips) == 0 {
			return netip.AddrPort{}, errors.New("hybrid QUIC target did not resolve")
		}
		address = xnet.IPAddress(ips[0])
	}
	resolved, ok := netip.AddrFromSlice(address.IP())
	if !ok {
		return netip.AddrPort{}, errors.New("invalid hybrid QUIC target address")
	}
	resolved = resolved.Unmap()
	if !isPublicTarget(resolved) {
		return netip.AddrPort{}, errors.New("hybrid QUIC target is not public")
	}
	return netip.AddrPortFrom(resolved, uint16(destination.Port)), nil
}

// register creates the flow and its socket to the target. It deliberately does
// not touch the manager's tuple table: the raw tuple is not known yet and is
// filled in by bind once a raw packet has identified itself by connection ID.
func (s *hybridSession) register(id [16]byte, destination xnet.Destination) (*hybridFlow, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	if existing := s.flows[id]; existing != nil {
		s.mu.Unlock()
		if existing.target.Port() != uint16(destination.Port) {
			return nil, errors.New("hybrid QUIC flow id collision")
		}
		return existing, nil
	}
	s.mu.Unlock()

	target, err := resolveHybridTarget(destination)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if target.Addr().Is6() {
		network = "udp6"
	}
	targetConn, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = targetConn.Close()
		return nil, net.ErrClosed
	}
	if existing := s.flows[id]; existing != nil {
		s.mu.Unlock()
		_ = targetConn.Close()
		return existing, nil
	}
	flow := &hybridFlow{session: s, id: id, target: target, conn: targetConn, lastSeen: time.Now()}
	s.flows[id] = flow
	s.mu.Unlock()

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
		client := f.client
		bound := f.bound
		f.mu.Unlock()
		if closed {
			return
		}

		// The connection ID the target chose is how the client's next packet
		// will address this flow, so it has to be claimable before that packet
		// can arrive. It can only arrive after this reply reaches the client,
		// which is why claiming it here is always in time.
		if _, scid, ok := longHeaderConnectionIDs(buffer[:n]); ok {
			f.session.manager.claimCID(f, scid)
		}

		if !bound {
			// Nothing has identified a raw tuple for this flow yet. Sending to
			// a guessed one would be sending to a stranger, so the reply goes
			// back the way the registration came. This is also what removes the
			// need for the client to punch a hole first: the server never
			// speaks on the raw path before the client has.
			send := f.session.sender()
			if send == nil {
				f.close()
				return
			}
			from := xnet.UDPDestination(xnet.IPAddress(f.target.Addr().AsSlice()), xnet.Port(f.target.Port()))
			if err = send(buffer[:n], from); err != nil {
				f.close()
				return
			}
			continue
		}
		if _, err = f.session.manager.conn.WriteTo(buffer[:n], net.UDPAddrFromAddrPort(client)); err != nil {
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
	client := f.client
	cids := f.cids
	f.cids = nil
	f.mu.Unlock()
	_ = f.conn.Close()
	m := f.session.manager
	m.mu.Lock()
	if m.flows[client] == f {
		delete(m.flows, client)
	}
	for _, cid := range cids {
		if m.byCID[cid] == f {
			delete(m.byCID, cid)
		}
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

func isPublicTarget(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsUnspecified()
}

// HandleHybridQUIC is exposed through a tiny interface so the proxy layer can
// consume the reserved authenticated destination without a package cycle.
func (c *InterConn) HandleHybridQUIC(destination string, data []byte, send func([]byte, xnet.Destination) error) (bool, error) {
	if destination != hybridControlHost {
		return false, nil
	}
	if c.hybridSession == nil {
		return true, errors.New("hybrid QUIC is unavailable for this session")
	}
	c.hybridSession.attachSender(send)
	return true, c.hybridSession.handle(data)
}

// attachSender records the tunnel writer for this session. The session is
// created at authentication time, before the proxy layer has built the writer
// for its UDP link, so the first control message is what supplies it.
func (s *hybridSession) attachSender(send func([]byte, xnet.Destination) error) {
	if send == nil {
		return
	}
	s.mu.Lock()
	if s.send == nil {
		s.send = send
	}
	s.mu.Unlock()
}
