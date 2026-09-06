package dispatcher

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	mdns "github.com/miekg/dns"
)

func reserved(network net.Network) net.Destination {
	return net.Destination{
		Network: network,
		Address: net.DomainAddress(tunnelDNSHost),
		Port:    net.Port(tunnelDNSPort),
	}
}

// The reserved destination must be recognised on both networks -- a stream
// client frames its queries, a hybrid Hysteria2 client sends datagrams -- and
// it must never swallow anything else.
func TestIsTunnelDNSDestination(t *testing.T) {
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		if !isTunnelDNSDestination(reserved(network)) {
			t.Fatalf("the reserved destination must be recognised on %v", network)
		}
	}

	for name, destination := range map[string]net.Destination{
		"wrong port":    {Network: net.Network_TCP, Address: net.DomainAddress(tunnelDNSHost), Port: net.Port(443)},
		"unknown net":   {Network: net.Network_Unknown, Address: net.DomainAddress(tunnelDNSHost), Port: net.Port(tunnelDNSPort)},
		"real domain":   {Network: net.Network_TCP, Address: net.DomainAddress("example.com"), Port: net.Port(tunnelDNSPort)},
		"suffix attack": {Network: net.Network_TCP, Address: net.DomainAddress("evil-" + tunnelDNSHost), Port: net.Port(tunnelDNSPort)},
		"subdomain":     {Network: net.Network_TCP, Address: net.DomainAddress("x." + tunnelDNSHost), Port: net.Port(tunnelDNSPort)},
		"ip address":    {Network: net.Network_TCP, Address: net.ParseAddress("1.1.1.1"), Port: net.Port(tunnelDNSPort)},
	} {
		if isTunnelDNSDestination(destination) {
			t.Fatalf("%s must not be treated as the reserved destination", name)
		}
	}
}

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), qtype)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return wire
}

func answered(t *testing.T, wire []byte) *mdns.Msg {
	t.Helper()
	out, err := answerTunnelDNS(t.Context(), wire)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	m := new(mdns.Msg)
	if err := m.Unpack(out); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !m.Response {
		t.Fatal("a reply must have the response bit set")
	}
	return m
}

// The answered set is fixed and small. Anything outside it is refused with an
// rcode, so the client learns the destination is served here and stops asking,
// rather than this quietly becoming a general-purpose resolver.
func TestAnswerTunnelDNSRefusesUnsupportedQuestions(t *testing.T) {
	for _, qtype := range []uint16{mdns.TypeTXT, mdns.TypeMX, mdns.TypeNS, mdns.TypeANY} {
		if rcode := answered(t, query(t, "example.com", qtype)).Rcode; rcode != mdns.RcodeRefused {
			t.Fatalf("%s: expected REFUSED, got %s", mdns.TypeToString[qtype], mdns.RcodeToString[rcode])
		}
	}

	chaos := new(mdns.Msg)
	chaos.SetQuestion("example.com.", mdns.TypeA)
	chaos.Question[0].Qclass = mdns.ClassCHAOS
	wire, err := chaos.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if rcode := answered(t, wire).Rcode; rcode != mdns.RcodeRefused {
		t.Fatalf("CH class: expected REFUSED, got %s", mdns.RcodeToString[rcode])
	}
}

// Address and service-binding questions are the ones this exists for, so they
// must reach the resolver rather than be refused at the door. With no DNS
// client configured that shows up as SERVFAIL.
func TestAnswerTunnelDNSAcceptsItsOwnTypes(t *testing.T) {
	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeSVCB, mdns.TypeHTTPS} {
		response := answered(t, query(t, "example.com", qtype))
		if response.Rcode == mdns.RcodeRefused {
			t.Fatalf("%s must not be refused", mdns.TypeToString[qtype])
		}
		if len(response.Question) != 1 || response.Question[0].Qtype != qtype {
			t.Fatalf("%s: the question must be echoed", mdns.TypeToString[qtype])
		}
	}
}

func TestAnswerTunnelDNSRejectsMalformedFraming(t *testing.T) {
	multi := new(mdns.Msg)
	multi.SetQuestion("example.com.", mdns.TypeHTTPS)
	multi.Question = append(multi.Question, mdns.Question{
		Name: "example.org.", Qtype: mdns.TypeHTTPS, Qclass: mdns.ClassINET,
	})
	wire, err := multi.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if rcode := answered(t, wire).Rcode; rcode != mdns.RcodeFormatError {
		t.Fatalf("multi-question: expected FORMERR, got %s", mdns.RcodeToString[rcode])
	}

	// Unparseable wire data is the one case with no message id to reply to.
	if _, err := answerTunnelDNS(t.Context(), []byte{0x00, 0x01}); err == nil {
		t.Fatal("malformed wire data must be reported")
	}
}

func TestPrefixedMessageRoundTrip(t *testing.T) {
	message := query(t, "www.example.com", mdns.TypeHTTPS)
	framed := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(message)))
	copy(framed[2:], message)

	got, err := readPrefixedMessage(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, message) {
		t.Fatal("the message must survive framing unchanged")
	}
	if _, err := readPrefixedMessage(bytes.NewReader(framed[:len(framed)-1])); err == nil {
		t.Fatal("a truncated frame must be rejected")
	}
	if _, err := readPrefixedMessage(bytes.NewReader([]byte{0x00, 0x00})); err == nil {
		t.Fatal("a zero-length frame must be rejected")
	}
}

// A stream client must get its reply framed and the connection left open for
// the next question.
func TestServeTunnelDNSAnswersOnAStream(t *testing.T) {
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()

	message := query(t, "example.com", mdns.TypeHTTPS)
	framed := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(message)))
	copy(framed[2:], message)

	b := buf.New()
	if _, err := b.Write(framed); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("send: %v", err)
	}

	go serveTunnelDNS(t.Context(), &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, net.Network_TCP)

	reply, err := readReply(downlinkReader, true)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Id != 0 && len(reply.Question) != 1 {
		t.Fatal("the reply must answer the question that was asked")
	}
}

// A hybrid Hysteria2 client sends one bare message per datagram and expects
// one back the same way.
func TestServeTunnelDNSAnswersADatagram(t *testing.T) {
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()

	b := buf.New()
	if _, err := b.Write(query(t, "example.com", mdns.TypeAAAA)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("send: %v", err)
	}

	go serveTunnelDNS(t.Context(), &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, net.Network_UDP)

	if _, err := readReply(downlinkReader, false); err != nil {
		t.Fatalf("read reply: %v", err)
	}
}

func readReply(reader buf.Reader, framed bool) (*mdns.Msg, error) {
	type result struct {
		buffers buf.MultiBuffer
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		buffers, err := reader.ReadMultiBuffer()
		ch <- result{buffers, err}
	}()

	select {
	case got := <-ch:
		if got.err != nil {
			return nil, got.err
		}
		wire := got.buffers[0].Bytes()
		if framed {
			wire = wire[2:]
		}
		m := new(mdns.Msg)
		if err := m.Unpack(wire); err != nil {
			return nil, err
		}
		return m, nil
	case <-time.After(5 * time.Second):
		return nil, errTimeout
	}
}

var errTimeout = &timeoutError{}

type timeoutError struct{}

func (*timeoutError) Error() string { return "timed out waiting for a reply" }

// framedQuery wraps a query the way a stream client sends it.
func framedQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	message := query(t, name, qtype)
	out := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(out[:2], uint16(len(message)))
	copy(out[2:], message)
	return out
}

func writeBytes(t *testing.T, writer buf.Writer, payload []byte) {
	t.Helper()
	b := buf.New()
	if _, err := b.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// The reserved destination has to be recognised at BOTH dispatcher entry
// points. VMess, Trojan and Shadowsocks arrive at Dispatch; VLESS, SOCKS, HTTP
// CONNECT, Hysteria, dokodemo, tun and wireguard arrive at DispatchLink. A
// check in only one of them leaves the whole feature dead on the other set --
// which includes the most widely used inbound there is.
//
// Neither path touches the policy or stats managers for a session with no
// user, so a bare dispatcher is enough to drive them.
func TestDispatchAnswersTheReservedDestination(t *testing.T) {
	d := &DefaultDispatcher{}

	link, err := d.Dispatch(t.Context(), reserved(net.Network_TCP))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	writeBytes(t, link.Writer, framedQuery(t, "example.com", mdns.TypeHTTPS))

	if _, err := readReply(link.Reader, true); err != nil {
		t.Fatalf("Dispatch did not answer the reserved destination: %v", err)
	}
}

func TestDispatchLinkAnswersTheReservedDestination(t *testing.T) {
	d := &DefaultDispatcher{}

	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	writeBytes(t, uplinkWriter, framedQuery(t, "example.com", mdns.TypeHTTPS))

	done := make(chan error, 1)
	go func() {
		done <- d.DispatchLink(t.Context(), reserved(net.Network_TCP),
			&transport.Link{Reader: uplinkReader, Writer: downlinkWriter})
	}()

	if _, err := readReply(downlinkReader, true); err != nil {
		t.Fatalf("DispatchLink did not answer the reserved destination: %v", err)
	}

	// DispatchLink does not return until the link is finished.
	_ = uplinkWriter.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DispatchLink: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DispatchLink never returned")
	}
}

// A message this cannot reply to at all closes the connection. The client is
// meant to fall back to a resolver of its own and can only do that once its
// read fails; holding the connection open with no reply would make it wait out
// its whole DNS timeout for an answer that is never coming.
func TestServeTunnelDNSClosesWhenItCannotReply(t *testing.T) {
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()

	// Two bytes framed as a DNS message: too short to parse, so there is not
	// even a message id to answer with.
	writeBytes(t, uplinkWriter, []byte{0x00, 0x02, 0x00, 0x01})

	served := make(chan struct{})
	go func() {
		defer close(served)
		serveTunnelDNS(t.Context(), &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, net.Network_TCP)
	}()

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler held the connection open on a query it could not reply to")
	}

	if _, err := readReply(downlinkReader, true); err == nil {
		t.Fatal("the client's read must fail so it falls back immediately")
	}
}
