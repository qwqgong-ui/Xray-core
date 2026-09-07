package hysteria

import (
	"bytes"
	"context"
	go_tls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

// This is an ablation harness, not a regression test. It drives a real quic-go
// client to a real quic-go target through the real relay, so the connection IDs
// and their timing are whatever quic-go actually does rather than what a
// synthetic packet asserts. The question it answers is narrow: what does the
// handover -- sending each 1-RTT packet over the tunnel as well as the raw path
// until the raw one answers -- actually buy?

type ablationMode int

const (
	// ablationDual sends every 1-RTT packet over both paths until the raw one
	// answers. This is what the client used to do.
	ablationDual ablationMode = iota
	// ablationRawOnly puts 1-RTT packets on the raw path alone.
	ablationRawOnly
	// ablationTunnelOnly never uses the raw path, as a baseline.
	ablationTunnelOnly
	// ablationProbe puts 1-RTT packets on the tunnel and sends a raw copy of
	// the first one only. The raw copy is what the relay binds on; everything
	// else rides the tunnel until a raw reply says the binding took. This is
	// what the client does now, and the numbers below are why.
	ablationProbe
)

func (m ablationMode) String() string {
	switch m {
	case ablationDual:
		return "dual-send"
	case ablationRawOnly:
		return "raw-only"
	case ablationProbe:
		return "probe"
	default:
		return "tunnel-only"
	}
}

type ablationResult struct {
	handshake     time.Duration
	roundTrip     time.Duration
	bound         bool
	rawSent       int
	tunnelRelayed int
	rawReplies    int
	tunnelReplies int
	claimedCIDs   int
	firstRawMatch bool
	err           error
}

func (r ablationResult) String() string {
	status := "ok"
	if r.err != nil {
		status = "FAILED: " + r.err.Error()
	}
	return fmt.Sprintf("handshake=%-7v rtt=%-9v bound=%-5v sent[raw=%-3d tunnel=%-3d] replies[raw=%-3d tunnel=%-3d] cids=%d first-raw-matched=%-5v %s",
		r.handshake.Round(time.Millisecond), r.roundTrip.Round(time.Millisecond),
		r.bound, r.rawSent, r.tunnelRelayed, r.rawReplies, r.tunnelReplies,
		r.claimedCIDs, r.firstRawMatch, status)
}

// startAblationTarget runs a real quic-go server that echoes one stream.
func startAblationTarget(t *testing.T) *net.UDPAddr {
	t.Helper()
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	pair, err := go_tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	conn := listenLoopback(t)
	transport := &quic.Transport{Conn: conn}
	listener, err := transport.Listen(
		&go_tls.Config{Certificates: []go_tls.Certificate{pair}, NextProtos: []string{"ablation"}},
		&quic.Config{MaxIdleTimeout: 20 * time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = transport.Close() })
	go func() {
		for {
			session, acceptErr := listener.Accept(context.Background())
			if acceptErr != nil {
				return
			}
			go func() {
				stream, streamErr := session.AcceptStream(context.Background())
				if streamErr != nil {
					return
				}
				_, _ = io.Copy(stream, stream)
				_ = stream.Close()
			}()
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// ablationClient is the client half of the hybrid split, reduced to what the
// experiment needs: long headers over the tunnel, 1-RTT packets wherever the
// mode says, and every reply handed back to quic-go labelled with the target.
type ablationClient struct {
	remote  net.Addr
	front   *net.UDPAddr
	raw     *net.UDPConn
	session *hybridSession
	dial    HybridDialer
	mode    ablationMode

	mu            sync.Mutex
	id            [16]byte
	registered    bool
	rawSent       int
	tunnelRelay   int
	rawReplies    int
	tunnelReplies int
	rawAnswered   bool
	firstRawSeen  []byte

	reads  chan []byte
	closed chan struct{}
	once   sync.Once
}

func (c *ablationClient) tunnelSend(payload []byte, from xnet.Destination) error {
	if from.Address.Family().IsDomain() {
		// An acknowledgement. The experiment does not need what it carries: the
		// target is a literal address, so the client already knows how to label
		// its replies.
		return nil
	}
	c.mu.Lock()
	c.tunnelReplies++
	c.mu.Unlock()
	select {
	case c.reads <- append([]byte(nil), payload...):
	case <-c.closed:
	}
	return nil
}

func (c *ablationClient) readRaw() {
	buffer := make([]byte, 64*1024)
	for {
		n, _, err := c.raw.ReadFrom(buffer)
		if err != nil {
			return
		}
		c.mu.Lock()
		c.rawReplies++
		c.rawAnswered = true
		c.mu.Unlock()
		select {
		case c.reads <- append([]byte(nil), buffer[:n]...):
		case <-c.closed:
			return
		}
	}
}

func (c *ablationClient) WriteTo(payload []byte, _ net.Addr) (int, error) {
	if len(payload) > 0 && payload[0]&0xc0 == 0xc0 {
		return len(payload), c.overTunnel(payload)
	}

	c.mu.Lock()
	registered := c.registered
	c.mu.Unlock()
	if !registered {
		return len(payload), c.overTunnel(payload)
	}

	switch c.mode {
	case ablationTunnelOnly:
		return len(payload), c.overTunnel(payload)
	case ablationRawOnly:
		return len(payload), c.overRaw(payload)
	case ablationProbe:
		c.mu.Lock()
		answered, probed := c.rawAnswered, c.rawSent > 0
		c.mu.Unlock()
		if answered {
			return len(payload), c.overRaw(payload)
		}
		if err := c.overTunnel(payload); err != nil {
			return 0, err
		}
		if !probed {
			// One packet is enough to bind: the relay matches it by the
			// connection ID the target chose, which it already holds.
			return len(payload), c.overRaw(payload)
		}
		return len(payload), nil
	default:
		c.mu.Lock()
		answered := c.rawAnswered
		c.mu.Unlock()
		if answered {
			return len(payload), c.overRaw(payload)
		}
		if err := c.overTunnel(payload); err != nil {
			return 0, err
		}
		return len(payload), c.overRaw(payload)
	}
}

func (c *ablationClient) overRaw(payload []byte) error {
	c.mu.Lock()
	c.rawSent++
	if c.firstRawSeen == nil {
		c.firstRawSeen = append([]byte(nil), payload...)
	}
	c.mu.Unlock()
	_, err := c.raw.WriteToUDP(payload, c.front)
	return err
}

func (c *ablationClient) overTunnel(payload []byte) error {
	c.mu.Lock()
	message := make([]byte, 0, 40+len(payload))
	message = append(message, hybridMagic...)
	if c.registered {
		message = append(message, hybridOpRelay)
		message = append(message, c.id[:]...)
		c.tunnelRelay++
	} else {
		message = append(message, hybridOpInitial)
		message = append(message, c.id[:]...)
		address := netip.MustParseAddr(ablationTargetAddress).As16()
		message = append(message, hybridTargetIPv6)
		message = append(message, address[:]...)
		message = binary.BigEndian.AppendUint16(message, 443)
		c.registered = true
	}
	c.mu.Unlock()
	message = append(message, payload...)
	return c.session.handle(message, c.tunnelSend, c.dial)
}

func (c *ablationClient) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case payload := <-c.reads:
		return copy(p, payload), c.remote, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *ablationClient) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.raw.Close()
}

func (c *ablationClient) LocalAddr() net.Addr              { return c.raw.LocalAddr() }
func (c *ablationClient) SetDeadline(time.Time) error      { return nil }
func (c *ablationClient) SetReadDeadline(time.Time) error  { return nil }
func (c *ablationClient) SetWriteDeadline(time.Time) error { return nil }

// ablationTargetAddress is a documentation address, used only so registration
// screening sees a public destination. The dialer ignores it and connects to
// the loopback target the experiment actually runs.
const ablationTargetAddress = "2001:db8::1"

func runHybridAblation(t *testing.T, mode ablationMode, sameAddress bool) ablationResult {
	t.Helper()
	target := startAblationTarget(t)

	front := listenLoopback(t)
	manager := newHybridManager(front)
	defer manager.close()
	go func() { _, _, _ = manager.wrap().ReadFrom(make([]byte, 64*1024)) }()

	// The relay only binds a raw tuple whose address belongs to the session
	// that registered the flow. sameAddress=false is how a client whose raw
	// socket leaves by another address looks -- the case the handover exists
	// for.
	sessionRemote := loopbackHost
	if !sameAddress {
		sessionRemote = netip.MustParseAddr("2001:db8::ffff")
	}
	session := newTestSession(manager, sessionRemote)
	defer session.close()

	rawConn, err := net.ListenUDP(loopbackNetwork, &net.UDPAddr{IP: net.IP(loopbackHost.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}

	var delivered atomic.Int64
	dial := func(xnet.Destination) (HybridTargetLink, error) {
		conn, dialErr := net.DialUDP(loopbackNetwork, nil, target)
		if dialErr != nil {
			return nil, dialErr
		}
		return &countingLink{HybridTargetLink: newHybridUDPLink(conn), writes: &delivered}, nil
	}

	client := &ablationClient{
		remote:  net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[" + ablationTargetAddress + "]:443")),
		front:   front.LocalAddr().(*net.UDPAddr),
		raw:     rawConn,
		session: session,
		dial:    dial,
		mode:    mode,
		reads:   make(chan []byte, 512),
		closed:  make(chan struct{}),
	}
	client.id[0] = 1
	go client.readRaw()

	result := ablationResult{}
	transport := &quic.Transport{Conn: client}
	// Order matters: quic-go's Close waits for its read loop, which only
	// unblocks once the client connection is closed under it.
	defer transport.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	session2, err := transport.Dial(ctx, client.remote,
		&go_tls.Config{InsecureSkipVerify: true, NextProtos: []string{"ablation"}},
		&quic.Config{MaxIdleTimeout: 20 * time.Second},
	)
	result.handshake = time.Since(started)
	if err != nil {
		result.err = fmt.Errorf("handshake: %w", err)
		return result
	}
	defer session2.CloseWithError(0, "")

	// The stream is what exercises 1-RTT in both directions, which is the only
	// traffic the raw path ever carries.
	started = time.Now()
	stream, err := session2.OpenStreamSync(ctx)
	if err != nil {
		result.err = fmt.Errorf("open stream: %w", err)
		return result
	}
	payload := bytes.Repeat([]byte("ablation"), 64)
	if _, err = stream.Write(payload); err != nil {
		result.err = fmt.Errorf("write: %w", err)
		return result
	}
	echo := make([]byte, len(payload))
	// Short on purpose: a mode that black-holes its 1-RTT packets should show
	// up as a stall, not hold the suite up while it does.
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.ReadFull(stream, echo); err != nil {
		result.err = fmt.Errorf("read back: %w", err)
	}
	result.roundTrip = time.Since(started)

	client.mu.Lock()
	result.rawSent = client.rawSent
	result.tunnelRelayed = client.tunnelRelay
	result.rawReplies = client.rawReplies
	result.tunnelReplies = client.tunnelReplies
	firstRaw := client.firstRawSeen
	client.mu.Unlock()

	manager.mu.RLock()
	result.claimedCIDs = len(manager.byCID)
	for cid := range manager.byCID {
		if len(firstRaw) > 1 && bytes.HasPrefix(firstRaw[1:], []byte(cid)) {
			result.firstRawMatch = true
		}
	}
	manager.mu.RUnlock()

	session.mu.Lock()
	for _, flow := range session.flows {
		flow.mu.Lock()
		result.bound = result.bound || flow.bound
		flow.mu.Unlock()
	}
	session.mu.Unlock()
	return result
}

type countingLink struct {
	HybridTargetLink
	writes *atomic.Int64
}

func (l *countingLink) WritePacket(payload []byte) error {
	l.writes.Add(1)
	return l.HybridTargetLink.WritePacket(payload)
}

// TestHybridHandoverAblation is the experiment. Run it with -v to read the
// numbers; it only fails if a mode that is supposed to work does not.
func TestHybridHandoverAblation(t *testing.T) {
	cases := []struct {
		name        string
		mode        ablationMode
		sameAddress bool
		mustWork    bool
	}{
		{name: "tunnel-only/bindable", mode: ablationTunnelOnly, sameAddress: true, mustWork: true},
		{name: "dual-send/bindable", mode: ablationDual, sameAddress: true, mustWork: true},
		{name: "raw-only/bindable", mode: ablationRawOnly, sameAddress: true, mustWork: true},
		{name: "probe/bindable", mode: ablationProbe, sameAddress: true, mustWork: true},
		{name: "dual-send/unbindable", mode: ablationDual, sameAddress: false, mustWork: true},
		{name: "raw-only/unbindable", mode: ablationRawOnly, sameAddress: false, mustWork: false},
		{name: "probe/unbindable", mode: ablationProbe, sameAddress: false, mustWork: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result := runHybridAblation(t, test.mode, test.sameAddress)
			t.Logf("%-24s %s", test.name, result)
			if test.mustWork && result.err != nil {
				t.Fatalf("%s was expected to work: %v", test.name, result.err)
			}
			if !test.mustWork && result.err == nil {
				t.Logf("NOTE: %s completed after all", test.name)
			}
			// The load-bearing result. The client's very first raw packet is
			// addressed to a connection ID the relay already holds, because the
			// target's handshake reply travelled the tunnel before any 1-RTT
			// packet could exist. Binding is therefore settled on the first
			// probe, which is what makes duplicating a round trip of traffic
			// pointless -- if this ever stops being true, the client needs its
			// handover back.
			if result.rawSent > 0 && !result.firstRawMatch {
				t.Fatal("the first raw packet named a connection ID the relay had not claimed")
			}
		})
	}
}
