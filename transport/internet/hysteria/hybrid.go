package hysteria

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	hybridControlHost = "hybrid-quic.invalid:443"
	// The wire format changed incompatibly with HQV2: the raw path now carries
	// nothing but 1-RTT packets, so every long-header packet in either
	// direction travels over the tunnel and the client needs an op that relays
	// one without re-registering. Bumping the magic makes an HQV2 peer fail
	// cleanly rather than misread an op it has no case for.
	hybridMagic     = "HQV3"
	hybridOpInitial = byte(1)
	hybridOpAck     = byte(2)
	hybridOpRelay   = byte(3)

	hybridTargetDomain = byte(0)
	hybridTargetIPv4   = byte(4)
	hybridTargetIPv6   = byte(6)

	hybridAckOK     = byte(0)
	hybridAckFailed = byte(1)

	// A flow that is still on the tunnel is cheap to lose: the client notices
	// its registration went stale and makes a new one. A bound flow is not --
	// it is carrying a live connection on the raw path, and reclaiming it
	// black-holes that connection until QUIC gives up -- so it is held far
	// longer than an application's idle gap between requests.
	hybridFlowTTL      = 2 * time.Minute
	hybridBoundFlowTTL = 30 * time.Minute

	// hybridMaxFlowCIDs bounds the connection IDs one flow may claim. A flow
	// needs one in the normal case (the SCID the target chose, which its 1-RTT
	// packets are addressed to); the rest of the budget absorbs Retry and early
	// rotation.
	hybridMaxFlowCIDs = 8

	// hybridMaxSessionFlows bounds the flows one authenticated session may hold
	// open at a time. Each costs a socket and a goroutine, and a client with a
	// browser's worth of QUIC connections needs a fraction of this.
	hybridMaxSessionFlows = 64

	// hybridMaxPendingBytes bounds what one flow buffers while its target is
	// being resolved and dialled. Overflow is dropped rather than queued: these
	// are QUIC packets, and QUIC retransmits.
	hybridMaxPendingBytes = 64 * 1024

	// hybridHandshakeTTL is how long an unknown tuple that sent an Initial may
	// keep talking to the QUIC stack without having completed anything.
	hybridHandshakeTTL = 10 * time.Second
	// hybridMigrationTTL is how long a tuple stays authorized after a packet of
	// an authenticated connection arrived from it. It is renewed on use, so a
	// migrated connection keeps working for as long as it is live.
	hybridMigrationTTL = 60 * time.Second
	// hybridMaxPassing bounds the authorization table. Entries are cheap and
	// short-lived, but a flood of spoofed-source Initials must not be able to
	// grow it without limit.
	hybridMaxPassing = 65536

	// hybridMaxHY2CIDs bounds the connection IDs remembered for this server's
	// own QUIC connections.
	hybridMaxHY2CIDs = 65536
	// hybridHY2CIDGrace is how long those connection IDs outlive the connection
	// they belong to. A live connection keeps its own; this only reclaims the
	// ones left by a handshake that never completed.
	hybridHY2CIDGrace = 2 * time.Minute
)

// HybridTargetLink is one hybrid flow's connection to its target. The proxy
// layer supplies an implementation backed by Xray's dispatcher, so a hybrid
// flow is routed, logged and accounted exactly like an ordinary Hysteria UDP
// session; the raw path changes how the client's packets arrive, not what the
// server is allowed to do with them.
type HybridTargetLink interface {
	// WritePacket sends one datagram to the target. It may be called from
	// several goroutines at once: the control loop and the raw receive path
	// both feed the same flow.
	WritePacket(payload []byte) error
	// ReadPacket returns the next datagram from the target. It is called from
	// the flow's single reader goroutine, and the slice it returns stays valid
	// only until the next call.
	ReadPacket() ([]byte, error)
	Close() error
}

// HybridDialer opens the target side of a flow. It is an alias rather than a
// defined type so the proxy layer can satisfy the method set structurally,
// without importing anything from this package.
type HybridDialer = func(destination xnet.Destination) (HybridTargetLink, error)

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
	// connection IDs a flow may be addressed by, which the target chose and the
	// client learns only from replies the server forwards over the tunnel, so a
	// raw packet carrying one cannot arrive before the entry exists.
	//
	// A target that issues a zero-length connection ID cannot be matched this
	// way and simply never binds: its flow stays on the tunnel for its whole
	// life, which is slower but correct.
	byCID map[string]*hybridFlow
	// hy2CIDs holds the connection IDs this server's own QUIC stack handed out,
	// read off the long-header packets it writes. A 1-RTT packet from a tuple
	// nobody knows is what an ordinary NAT rebinding looks like, and matching
	// its destination ID here is the only way to tell that apart from a stray
	// datagram without keys. quic-go validates the new path itself, so the
	// packet only has to be allowed to reach it.
	hy2CIDs map[string]hybridHY2CID
	// cidLengths counts the claimed connection IDs of each length, across both
	// tables. A 1-RTT packet does not encode its DCID length, so a raw packet
	// from an unknown tuple can only be matched by trying the lengths this
	// server has actually seen -- in practice one or two.
	cidLengths map[int]int
	// passing authorizes tuples that have shown they belong to a QUIC
	// connection this server is willing to talk to, without one entry per
	// packet of bookkeeping.
	passing     map[netip.AddrPort]hybridPass
	passUnknown bool
	closed      chan struct{}
}

// hybridPass is one tuple's authorization to reach the QUIC stack: the short
// window an unknown Initial buys, or the renewed one a connection that proved
// itself by connection ID keeps.
type hybridPass struct {
	expiry time.Time
}

type hybridHY2CID struct {
	host netip.AddrPort
	seen time.Time
}

type hybridSession struct {
	manager *hybridManager
	remote  netip.Addr
	mu      sync.Mutex
	flows   map[[16]byte]*hybridFlow
	closed  bool
}

type hybridFlow struct {
	session *hybridSession
	id      [16]byte
	// request is the destination as the client asked for it, kept so a repeat
	// of the same id can be told from a new flow reusing it.
	request string

	mu sync.Mutex
	// target and link are filled once the destination has been resolved and
	// dialled, which happens off the control loop. Until then the flow buffers.
	target   netip.AddrPort
	link     HybridTargetLink
	ready    bool
	acked    bool
	pending  [][]byte
	pendingN int
	// client is the raw tuple as this server observed it, zero until a raw
	// packet has been matched to this flow by connection ID. Until then the
	// target's replies go back through the tunnel, which is also what keeps the
	// server from sending to an unbound tuple.
	client   netip.AddrPort
	bound    bool
	cids     []string
	lastSeen time.Time
	closed   bool
	// send returns a datagram over the UDP link the registration arrived on.
	// It belongs to the flow rather than the session: one authenticated tunnel
	// carries many UDP links, each with its own writer, and a session-wide
	// sender would still point at the first link long after the client closed
	// it, so every later flow's replies would go nowhere.
	send func(payload []byte, from xnet.Destination) error
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
		hy2CIDs:    make(map[string]hybridHY2CID),
		cidLengths: make(map[int]int),
		passing:    make(map[netip.AddrPort]hybridPass),
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
		// The common case -- a packet of an established flow, or of a QUIC
		// connection already known to belong here -- is answered under a read
		// lock. Only a packet neither table recognizes reaches classify, which
		// is the one place on this path that takes the write lock per packet.
		flow, pass, decided := c.manager.lookup(client, p[:n])
		if !decided {
			flow, pass = c.manager.classify(client, p[:n])
		}
		if flow == nil {
			if pass {
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

// WriteTo watches what this server's own QUIC stack sends so a connection can
// still be recognized after its tuple changes. Only long-header packets carry a
// connection ID in the clear, and they are a handful per connection, so the
// check costs a comparison on everything else.
func (c *hybridPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 0 && p[0]&0xc0 == 0xc0 {
		c.manager.observeHY2(p, addr)
	}
	return c.PacketConn.WriteTo(p, addr)
}

// lookup answers under a read lock for a packet whose tuple or connection ID is
// already known. It reports the flow the packet belongs to, whether it may go on
// to quic-go, and whether it decided at all.
func (m *hybridManager) lookup(client netip.AddrPort, packet []byte) (*hybridFlow, bool, bool) {
	now := time.Now()
	m.mu.RLock()
	if flow := m.flows[client]; flow != nil {
		m.mu.RUnlock()
		return flow, false, true
	}
	if m.passUnknown || m.hy2[client] > 0 {
		m.mu.RUnlock()
		return nil, true, true
	}
	// A 1-RTT packet naming a registered flow claims the tuple ahead of any
	// authorization window, so the match comes before passing is honoured. It
	// costs a lookup or two, and only a match goes on to take the write lock.
	migrated := false
	if isShortHeader(packet) {
		flow, hy2 := m.matchShortHeaderLocked(packet)
		if flow != nil {
			m.mu.RUnlock()
			return nil, false, false
		}
		migrated = hy2
	}
	entry, authorized := m.passing[client]
	m.mu.RUnlock()

	if migrated {
		// An authenticated connection whose tuple changed. Authorizing the
		// tuple as well as the connection ID is what keeps it working once
		// quic-go rotates to an ID issued under encryption, which this side
		// never sees. Renewing only once the window is half spent keeps the
		// write lock off the hot path.
		if !authorized || entry.expiry.Sub(now) < hybridMigrationTTL/2 {
			m.mu.Lock()
			m.allowLocked(client, now, hybridMigrationTTL)
			m.mu.Unlock()
		}
		return nil, true, true
	}
	if authorized && entry.expiry.After(now) {
		return nil, true, true
	}
	return nil, false, false
}

// classify decides what to do with a packet from a tuple lookup did not know.
// It reports the flow the packet belongs to, or whether it may continue to
// quic-go.
func (m *hybridManager) classify(client netip.AddrPort, packet []byte) (*hybridFlow, bool) {
	now := time.Now()
	m.mu.Lock()
	// Re-checked under the write lock: lookup ran without one, and an
	// authorization may have appeared since.
	if m.passUnknown || m.hy2[client] > 0 {
		m.mu.Unlock()
		return nil, true
	}

	// A registered flow claims a tuple ahead of any authorization window. The
	// raw path uses a socket of its own that never speaks QUIC to this server,
	// so the two cannot legitimately be the same tuple -- but if they ever are,
	// relaying to the target the flow named beats guessing.
	if isShortHeader(packet) {
		flow, hy2 := m.matchShortHeaderLocked(packet)
		switch {
		case hy2:
			// An authenticated connection whose tuple changed: a NAT rebinding,
			// or a client that moved networks. Dropping it here would break a
			// migration quic-go handles natively, and quic-go still has to
			// decrypt the packet and validate the path before it accepts one.
			m.allowLocked(client, now, hybridMigrationTTL)
			m.mu.Unlock()
			return nil, true
		// The observed address must belong to the session that registered the
		// flow. Connection IDs travel in cleartext on the raw path, so an
		// on-path observer can read one and replay it from its own tuple;
		// without this check that would hand the target's traffic to whoever
		// sent the packet. NAT rewrites the port rather than the address, so
		// requiring the address still leaves IPv4 clients working.
		case flow != nil && m.flows[client] == nil && flow.session.remote == client.Addr():
			m.mu.Unlock()
			return m.bind(flow, client), false
		}
	}

	if entry, ok := m.passing[client]; ok && entry.expiry.After(now) {
		m.mu.Unlock()
		return nil, true
	}
	if !isClientQUICInitial(packet) {
		delete(m.passing, client)
		m.mu.Unlock()
		return nil, false
	}
	m.allowLocked(client, now, hybridHandshakeTTL)
	m.mu.Unlock()
	return nil, true
}

// allowLocked authorizes a tuple to reach the QUIC stack. The table is swept on
// a timer, but a flood of spoofed sources can fill it between sweeps, so it is
// also swept here once it reaches its bound.
func (m *hybridManager) allowLocked(client netip.AddrPort, now time.Time, ttl time.Duration) {
	if _, exists := m.passing[client]; !exists && len(m.passing) >= hybridMaxPassing {
		for other, entry := range m.passing {
			if !entry.expiry.After(now) {
				delete(m.passing, other)
			}
		}
		if len(m.passing) >= hybridMaxPassing {
			return
		}
	}
	m.passing[client] = hybridPass{expiry: now.Add(ttl)}
}

// observeHY2 remembers a connection ID this server chose for one of its own
// QUIC connections, so a 1-RTT packet addressed to it is recognized after the
// client's tuple changes.
func (m *hybridManager) observeHY2(packet []byte, addr net.Addr) {
	_, scid, ok := longHeaderConnectionIDs(packet)
	if !ok || scid == "" {
		return
	}
	host, ok := udpAddrPort(addr)
	if !ok {
		return
	}
	now := time.Now()
	m.mu.Lock()
	if m.passUnknown {
		// A UDP mask owns recognition of new wire packets, so what reaches this
		// writer is already encoded and its bytes are not a QUIC header. The
		// table is never consulted in that mode either, so there is nothing to
		// learn and nothing to pollute it with.
		m.mu.Unlock()
		return
	}
	if entry, exists := m.hy2CIDs[scid]; exists {
		entry.seen = now
		m.hy2CIDs[scid] = entry
	} else if len(m.hy2CIDs) < hybridMaxHY2CIDs && m.byCID[scid] == nil {
		// A hybrid flow's own connection ID is never shadowed: the raw relay
		// table decides first, and an ID cannot belong to both.
		m.hy2CIDs[scid] = hybridHY2CID{host: host, seen: now}
		m.cidLengths[len(scid)]++
	}
	m.mu.Unlock()
}

// bind attaches an as-yet-unseen raw tuple to the flow the packet's connection
// ID belongs to, and reports that flow.
//
// Only a 1-RTT packet can bootstrap. Every long-header packet of a hybrid flow
// travels over the tunnel in both directions, so one arriving here is not ours.
// A short header does not encode its DCID length, so it is matched against the
// connection IDs this flow has claimed -- the target's own SCID, learned from
// the handshake reply that was relayed through the tunnel, is what the client's
// first 1-RTT packet is addressed to.
func (m *hybridManager) bind(flow *hybridFlow, client netip.AddrPort) *hybridFlow {
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
	// The only point at which the raw path starts carrying this flow. Without
	// it there is no way to tell a relay that is working from one that
	// registered and then quietly fell back to the tunnel for everything.
	xerrors.LogDebug(context.Background(), "hybrid QUIC bound ", client, " -> ", flow.targetAddr())
	return flow
}

// claimCID lets a flow be addressed by one more connection ID. A CID already
// claimed by a different flow, or by one of this server's own connections, is
// left alone rather than stolen: two owners for one ID cannot both be right,
// and dropping the packet is better than relaying it to the wrong target.
func (m *hybridManager) claimCID(flow *hybridFlow, cid string) {
	if cid == "" {
		return
	}
	m.mu.RLock()
	_, isHY2 := m.hy2CIDs[cid]
	owner := m.byCID[cid]
	m.mu.RUnlock()
	if isHY2 || (owner != nil && owner != flow) {
		// Somebody else answers to this ID. It is not recorded on the flow
		// either: the budget is for IDs the flow can actually be reached by.
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
	if _, taken := m.hy2CIDs[cid]; !taken && m.byCID[cid] == nil {
		m.byCID[cid] = flow
		m.cidLengths[len(cid)]++
	}
	m.mu.Unlock()
}

// isShortHeader reports whether this is a 1-RTT packet: the header form bit
// clear and the fixed bit set.
func isShortHeader(packet []byte) bool {
	return len(packet) > 1 && packet[0]&0xc0 == 0x40
}

// matchShortHeaderLocked finds what a 1-RTT packet belongs to by trying its
// leading bytes against the connection IDs that have been claimed, longest
// first. Only lengths some connection actually uses are tried, so this is a
// lookup or two rather than a scan, and a longer ID is preferred so a short one
// can never shadow it. It reports either a hybrid flow or that the packet
// belongs to one of this server's own QUIC connections.
func (m *hybridManager) matchShortHeaderLocked(packet []byte) (*hybridFlow, bool) {
	for length := 20; length >= 1; length-- {
		if m.cidLengths[length] == 0 || len(packet) < 1+length {
			continue
		}
		cid := string(packet[1 : 1+length])
		if flow := m.byCID[cid]; flow != nil {
			return flow, false
		}
		if _, ok := m.hy2CIDs[cid]; ok {
			return nil, true
		}
	}
	return nil, false
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

func (m *hybridManager) establishHY2(remote net.Addr) func() {
	client, ok := udpAddrPort(remote)
	if !ok {
		return func() {}
	}
	m.mu.Lock()
	m.hy2[client]++
	delete(m.passing, client)
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

// isClientQUICInitial reports whether this is the Initial a client opens a QUIC
// connection with, which is the only packet an unknown tuple may arrive with.
func isClientQUICInitial(packet []byte) bool {
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
	if !ok {
		return nil
	}
	if !isPublicTarget(addrPort.Addr()) {
		// Worth saying out loud: a server behind NAT or a load balancer sees
		// private client addresses here, and hybrid QUIC silently does nothing
		// for every one of them.
		xerrors.LogDebug(context.Background(), "hybrid QUIC is unavailable for the non-public client address ", addrPort.Addr())
		return nil
	}
	s := &hybridSession{manager: m, remote: addrPort.Addr(), flows: make(map[[16]byte]*hybridFlow)}
	m.mu.Lock()
	m.sessions[s] = struct{}{}
	m.mu.Unlock()
	return s
}

func (s *hybridSession) handle(data []byte, send func([]byte, xnet.Destination) error, dial HybridDialer) error {
	if s == nil {
		return errors.New("hybrid QUIC is unavailable for this session")
	}
	if len(data) < 5 || string(data[:4]) != hybridMagic {
		return errors.New("invalid hybrid QUIC control message")
	}
	if data[4] == hybridOpRelay {
		return s.relay(data, send)
	}
	id, target, payload, err := parseHybridInitial(data)
	if err != nil {
		return err
	}

	flow, ready, err := s.register(id, target, send, dial)
	if err != nil {
		ackHybrid(send, id, hybridAckFailed, netip.AddrPort{})
		return err
	}
	// The DCID the client picked for its own Initial is deliberately not
	// claimed. Nothing on the raw path is ever addressed to it -- the raw path
	// carries only 1-RTT packets, which are addressed to the ID the target
	// chose -- so claiming it would add nothing but a value a stray datagram
	// could match by accident.
	if err = flow.writeTarget(payload); err != nil {
		ackHybrid(send, id, hybridAckFailed, netip.AddrPort{})
		flow.close()
		return err
	}
	if ready {
		// A repeat of a registration whose flow is already up. The goroutine
		// that would have acknowledged it finished long ago, so this answers on
		// the spot; a flow still coming up is acknowledged by that goroutine.
		ackHybrid(send, id, hybridAckOK, flow.targetAddr())
	}
	return nil
}

// relay forwards one packet of an already-registered flow. The client sends
// every long-header packet this way, and its first 1-RTT packets until the raw
// path has answered, so a flow whose raw tuple never binds still completes over
// the tunnel instead of stalling.
//
// A repeat of a packet the raw path also delivered is harmless: QUIC discards a
// duplicate packet number, which is exactly what the overlap during the
// handover produces.
func (s *hybridSession) relay(data []byte, send func([]byte, xnet.Destination) error) error {
	if len(data) < 22 {
		return errors.New("invalid hybrid QUIC relay message")
	}
	var id [16]byte
	copy(id[:], data[5:21])
	payload := data[21:]

	s.mu.Lock()
	flow := s.flows[id]
	if flow != nil {
		// The link this arrived on is the live one; the flow may have been
		// created on a link that is already gone.
		flow.mu.Lock()
		flow.send = send
		flow.mu.Unlock()
	}
	s.mu.Unlock()
	if flow == nil {
		return errors.New("hybrid QUIC relay for an unregistered flow")
	}

	// The client's own connection IDs are claimed here as well as at
	// registration: a Handshake packet is addressed to the ID the target chose,
	// which is the one its later 1-RTT packets carry and the only way to match
	// them on the raw path.
	if dcid, _, ok := longHeaderConnectionIDs(payload); ok {
		s.manager.claimCID(flow, dcid)
	}
	return flow.writeTarget(payload)
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
//
// A successful ack also carries the address the name resolved to. The client
// registered a name precisely because it has none of its own -- under fake-IP
// its only address is synthetic -- so it cannot label the replies arriving on
// the raw path without being told. Only the server knows which address it
// actually opened the flow to.
func ackHybrid(send func([]byte, xnet.Destination) error, id [16]byte, status byte, target netip.AddrPort) {
	if send == nil {
		return
	}
	message := make([]byte, 0, 40)
	message = append(message, hybridMagic...)
	message = append(message, hybridOpAck)
	message = append(message, id[:]...)
	message = append(message, status)
	if status == hybridAckOK && target.IsValid() {
		if addr := target.Addr(); addr.Is4() {
			v4 := addr.As4()
			message = append(message, hybridTargetIPv4)
			message = append(message, v4[:]...)
		} else {
			v6 := addr.As16()
			message = append(message, hybridTargetIPv6)
			message = append(message, v6[:]...)
		}
		message = binary.BigEndian.AppendUint16(message, target.Port())
	}
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

// register creates the flow and hands the rest to a goroutine. Resolving a name
// and opening the target side both block, and the control loop they used to run
// on is shared by every flow of this link -- one slow lookup held up the
// handshake of every other connection. The flow buffers what arrives meanwhile.
//
// It deliberately does not touch the manager's tuple table: the raw tuple is not
// known yet and is filled in by bind once a raw packet has identified itself by
// connection ID.
func (s *hybridSession) register(id [16]byte, destination xnet.Destination, send func([]byte, xnet.Destination) error, dial HybridDialer) (*hybridFlow, bool, error) {
	// A literal target is screened here rather than in the background, so an
	// unroutable one is refused while the client is still listening for the
	// answer to this registration.
	if !destination.Address.Family().IsDomain() {
		if _, err := resolveHybridTarget(destination); err != nil {
			return nil, false, err
		}
	}
	request := destination.String()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, false, net.ErrClosed
	}
	if existing := s.flows[id]; existing != nil {
		s.mu.Unlock()
		if existing.request != request {
			return nil, false, errors.New("hybrid QUIC flow id collision")
		}
		// A re-registration arrives on whichever link is live now; the one the
		// flow was created on may already be gone.
		existing.mu.Lock()
		existing.send = send
		ready := existing.ready
		existing.mu.Unlock()
		return existing, ready, nil
	}
	if len(s.flows) >= hybridMaxSessionFlows {
		s.mu.Unlock()
		return nil, false, errors.New("hybrid QUIC flow limit reached for this session")
	}
	flow := &hybridFlow{session: s, id: id, request: request, lastSeen: time.Now(), send: send}
	s.flows[id] = flow
	s.mu.Unlock()

	go flow.start(destination, dial)
	return flow, false, nil
}

// start resolves the target, opens the link to it and releases whatever the
// flow buffered while that was happening.
func (f *hybridFlow) start(destination xnet.Destination, dial HybridDialer) {
	target, err := resolveHybridTarget(destination)
	var link HybridTargetLink
	if err == nil {
		link, err = dialHybridTarget(target, dial)
	}
	if err != nil {
		f.mu.Lock()
		send := f.send
		f.mu.Unlock()
		xerrors.LogDebugInner(context.Background(), err, "hybrid QUIC registration failed for ", destination)
		ackHybrid(send, f.id, hybridAckFailed, netip.AddrPort{})
		f.close()
		return
	}

	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = link.Close()
		return
	}
	f.target = target
	f.link = link
	f.ready = true
	pending := f.pending
	f.pending, f.pendingN = nil, 0
	send := f.send
	f.mu.Unlock()

	go f.readTarget()
	ackHybrid(send, f.id, hybridAckOK, target)
	for _, payload := range pending {
		if err = link.WritePacket(payload); err != nil {
			f.close()
			return
		}
	}
}

// dialHybridTarget opens the target side of a flow. The dispatcher-backed
// dialer is what puts hybrid traffic under the same routing, logging and
// accounting as any other UDP session; the direct socket is only what is left
// when no dialer was supplied, as in a test.
func dialHybridTarget(target netip.AddrPort, dial HybridDialer) (HybridTargetLink, error) {
	if dial != nil {
		return dial(xnet.UDPDestination(xnet.IPAddress(target.Addr().AsSlice()), xnet.Port(target.Port())))
	}
	network := "udp4"
	if target.Addr().Is6() {
		network = "udp6"
	}
	conn, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return nil, err
	}
	return newHybridUDPLink(conn), nil
}

// hybridUDPLink is a plain connected UDP socket to the target.
type hybridUDPLink struct {
	conn   *net.UDPConn
	buffer []byte
}

func newHybridUDPLink(conn *net.UDPConn) *hybridUDPLink {
	return &hybridUDPLink{conn: conn, buffer: make([]byte, 64*1024)}
}

func (l *hybridUDPLink) WritePacket(payload []byte) error {
	_, err := l.conn.Write(payload)
	return err
}

func (l *hybridUDPLink) ReadPacket() ([]byte, error) {
	n, err := l.conn.Read(l.buffer)
	if err != nil {
		return nil, err
	}
	return l.buffer[:n], nil
}

func (l *hybridUDPLink) Close() error { return l.conn.Close() }

func (l *hybridUDPLink) LocalAddr() net.Addr { return l.conn.LocalAddr() }

func (f *hybridFlow) targetAddr() netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.target
}

func (f *hybridFlow) writeTarget(payload []byte) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	f.lastSeen = time.Now()
	if !f.ready {
		// The target is still being resolved and dialled. Holding these is what
		// keeps that work off the control loop without costing the flow its
		// handshake; past the bound they are dropped, and QUIC retransmits.
		if f.pendingN+len(payload) <= hybridMaxPendingBytes {
			f.pending = append(f.pending, append([]byte(nil), payload...))
			f.pendingN += len(payload)
		}
		f.mu.Unlock()
		return nil
	}
	link := f.link
	f.mu.Unlock()
	return link.WritePacket(payload)
}

func (f *hybridFlow) readTarget() {
	f.mu.Lock()
	link := f.link
	f.mu.Unlock()
	if link == nil {
		return
	}
	for {
		payload, err := link.ReadPacket()
		if err != nil {
			f.close()
			return
		}
		f.mu.Lock()
		f.lastSeen = time.Now()
		closed := f.closed
		client := f.client
		bound := f.bound
		target := f.target
		f.mu.Unlock()
		if closed {
			return
		}

		// The connection ID the target chose is how the client's next packet
		// will address this flow, so it has to be claimable before that packet
		// can arrive. It can only arrive after this reply reaches the client,
		// which is why claiming it here is always in time.
		if _, scid, ok := longHeaderConnectionIDs(payload); ok {
			f.session.manager.claimCID(f, scid)
		}

		if !bound || !isShortHeader(payload) {
			// Two reasons to answer over the tunnel. Nothing may have
			// identified a raw tuple for this flow yet, and sending to a
			// guessed one would be sending to a stranger -- this is also what
			// removes the need for the client to punch a hole first, since the
			// server never speaks on the raw path before the client has.
			//
			// The other is that this is a long-header packet. The target's
			// Initial and Handshake belong to the tunnel however far along the
			// flow is: a raw path that carried them would show an observer a
			// QUIC connection whose handshake is half missing, while one that
			// only ever carries 1-RTT packets is shaped exactly like an
			// ordinary connection migration.
			f.mu.Lock()
			send := f.send
			f.mu.Unlock()
			if send == nil {
				f.close()
				return
			}
			from := xnet.UDPDestination(xnet.IPAddress(target.Addr().AsSlice()), xnet.Port(target.Port()))
			if err = send(payload, from); err != nil {
				f.close()
				return
			}
			continue
		}
		if _, err = f.session.manager.conn.WriteTo(payload, net.UDPAddrFromAddrPort(client)); err != nil {
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
	link := f.link
	f.cids = nil
	f.pending, f.pendingN = nil, 0
	f.mu.Unlock()
	if link != nil {
		_ = link.Close()
	}
	m := f.session.manager
	m.mu.Lock()
	if m.flows[client] == f {
		delete(m.flows, client)
	}
	for _, cid := range cids {
		if m.byCID[cid] == f {
			delete(m.byCID, cid)
			m.releaseCIDLengthLocked(len(cid))
		}
	}
	m.mu.Unlock()
	f.session.mu.Lock()
	if f.session.flows[f.id] == f {
		delete(f.session.flows, f.id)
	}
	f.session.mu.Unlock()
}

func (m *hybridManager) releaseCIDLengthLocked(length int) {
	if m.cidLengths[length] <= 1 {
		delete(m.cidLengths, length)
		return
	}
	m.cidLengths[length]--
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
			m.sweep(time.Now())
		case <-m.closed:
			return
		}
	}
}

func (m *hybridManager) sweep(now time.Time) {
	m.mu.Lock()
	for client, entry := range m.passing {
		if !entry.expiry.After(now) {
			delete(m.passing, client)
		}
	}
	for cid, entry := range m.hy2CIDs {
		// A live connection keeps its own connection IDs however long it runs;
		// this reclaims the ones a handshake that never completed left behind.
		if m.hy2[entry.host] == 0 && now.Sub(entry.seen) > hybridHY2CIDGrace {
			delete(m.hy2CIDs, cid)
			m.releaseCIDLengthLocked(len(cid))
		}
	}
	sessions := make([]*hybridSession, 0, len(m.sessions))
	for session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()

	// Every flow of every session, not just the ones a raw tuple bound. A flow
	// that never leaves the tunnel is only ever in its session's table, so
	// sweeping the manager's tuple table alone held its socket and its
	// goroutine open for the whole life of the tunnel.
	for _, session := range sessions {
		session.mu.Lock()
		flows := make([]*hybridFlow, 0, len(session.flows))
		for _, flow := range session.flows {
			flows = append(flows, flow)
		}
		session.mu.Unlock()
		for _, flow := range flows {
			flow.mu.Lock()
			ttl := hybridFlowTTL
			if flow.bound {
				ttl = hybridBoundFlowTTL
			}
			expired := now.Sub(flow.lastSeen) > ttl
			flow.mu.Unlock()
			if expired {
				flow.close()
			}
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
// consume the reserved authenticated destination without a package cycle. The
// dialer it passes is what carries a flow's target side through Xray's
// dispatcher instead of a bare socket.
func (c *InterConn) HandleHybridQUIC(destination string, data []byte, send func([]byte, xnet.Destination) error, dial HybridDialer) (bool, error) {
	if destination != hybridControlHost {
		return false, nil
	}
	if c.hybridSession == nil {
		return true, errors.New("hybrid QUIC is unavailable for this session")
	}
	return true, c.hybridSession.handle(data, send, dial)
}
