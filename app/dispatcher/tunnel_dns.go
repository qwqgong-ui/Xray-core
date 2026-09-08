package dispatcher

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"

	mdns "github.com/miekg/dns"
	dnsfeature "github.com/xtls/xray-core/features/dns"
)

const (
	// tunnelDNSHost is the reserved destination a client dials when it wants
	// this instance's own resolver to answer a question. It is a name in the
	// `.invalid` TLD (RFC 6761), so it can never resolve and can never be
	// routed to a real host: the dispatcher recognises it and answers
	// internally, whatever inbound protocol carried it there.
	//
	// It is only a destination, so it needs no protocol of its own. What
	// travels inside is an ordinary DNS message -- DNS is already the small
	// request/response protocol this needs, and reusing it means there is no
	// bespoke header, status code, name encoding or record format to agree on
	// at either end.
	tunnelDNSHost = "server-dns.invalid"
	tunnelDNSPort = 53

	// tunnelDNSMaxMessage is the largest DNS message accepted on this path.
	tunnelDNSMaxMessage = 65535
)

// tunnelDNSTypes are the question types answered here.
//
// Service bindings are the reason this exists: they carry ech keys and alpn,
// which an address lookup cannot express, so a client has no other way to
// obtain this server's view of them through the tunnel. Address types are
// answered too, for a client that wants the address this very server would
// dial rather than the one its own resolver returns -- proxy protocols resolve
// addresses remotely already, so this adds no reach they did not have.
//
// Everything else is refused. The surface is a fixed, small list on purpose:
// answering whatever was asked would make this a general-purpose resolver for
// anyone who can reach an inbound.
var tunnelDNSTypes = map[uint16]bool{
	mdns.TypeA:     true,
	mdns.TypeAAAA:  true,
	mdns.TypeSVCB:  true,
	mdns.TypeHTTPS: true,
}

// isTunnelDNSDestination reports whether a dispatch is addressed to the
// reserved resolver rather than to a real host.
func isTunnelDNSDestination(destination net.Destination) bool {
	if destination.Port != net.Port(tunnelDNSPort) {
		return false
	}
	if destination.Network != net.Network_TCP && destination.Network != net.Network_UDP {
		return false
	}
	return destination.Address != nil &&
		destination.Address.Family().IsDomain() &&
		destination.Address.Domain() == tunnelDNSHost
}

// serveTunnelDNS answers questions arriving on the reserved destination using
// this instance's own DNS. The client picked its proxy from the real domain it
// wanted, so the answer comes from the resolver of the very server its traffic
// will leave through -- which is the whole point.
func serveTunnelDNS(ctx context.Context, link *transport.Link, network net.Network) {
	defer func() {
		common.Interrupt(link.Reader)
		common.Close(link.Writer)
	}()

	if network == net.Network_UDP {
		serveTunnelDNSDatagrams(ctx, link)
		return
	}
	serveTunnelDNSStream(ctx, link)
}

// serveTunnelDNSStream speaks length-prefixed DNS (RFC 1035 4.2.2) so a client
// may reuse one connection for several questions.
func serveTunnelDNSStream(ctx context.Context, link *transport.Link) {
	reader := &buf.BufferedReader{Reader: link.Reader}
	for {
		query, err := readPrefixedMessage(reader)
		if err != nil {
			if err != io.EOF {
				errors.LogInfoInner(ctx, err, "tunnel DNS: failed to read query")
			}
			return
		}
		response, err := answerTunnelDNS(ctx, query)
		if err != nil {
			// Nothing to say and no way to say it: close so the client's read
			// fails now and it falls back to a resolver of its own, instead of
			// waiting out its timeout for an answer that is never coming.
			errors.LogInfoInner(ctx, err, "tunnel DNS: query not answered")
			return
		}
		if err := writePrefixedMessage(link.Writer, response); err != nil {
			errors.LogInfoInner(ctx, err, "tunnel DNS: failed to write response")
			return
		}
	}
}

// serveTunnelDNSDatagrams answers one bare DNS message per datagram, which is
// how a Hysteria2 hybrid client asks for its relay target.
func serveTunnelDNSDatagrams(ctx context.Context, link *transport.Link) {
	for {
		buffers, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			if err != io.EOF {
				errors.LogInfoInner(ctx, err, "tunnel DNS: failed to read datagram")
			}
			return
		}
		for _, b := range buffers {
			response, err := answerTunnelDNS(ctx, b.Bytes())
			b.Release()
			if err != nil {
				errors.LogInfoInner(ctx, err, "tunnel DNS: query not answered")
				continue
			}
			out := buf.NewWithSize(int32(len(response)))
			if _, err := out.Write(response); err != nil {
				out.Release()
				return
			}
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{out}); err != nil {
				errors.LogInfoInner(ctx, err, "tunnel DNS: failed to write response")
				return
			}
		}
	}
}

// answerTunnelDNS turns one query into one reply. Everything the client could
// have got wrong is answered with an rcode rather than an error, so it learns
// the destination is served here and stops asking; an error is reserved for a
// message this cannot reply to at all.
func answerTunnelDNS(ctx context.Context, query []byte) ([]byte, error) {
	request := new(mdns.Msg)
	if err := request.Unpack(query); err != nil {
		return nil, errors.New("malformed query").Base(err)
	}

	response := new(mdns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true

	if request.Response || request.Opcode != mdns.OpcodeQuery || len(request.Question) != 1 {
		response.Rcode = mdns.RcodeFormatError
		return response.Pack()
	}

	question := request.Question[0]
	if question.Qclass != mdns.ClassINET || !tunnelDNSTypes[question.Qtype] {
		response.Rcode = mdns.RcodeRefused
		return response.Pack()
	}

	var answer *dnsfeature.RecordResponse
	var err error
	bundle := false
	if opt := request.IsEdns0(); opt != nil && question.Qtype == mdns.TypeHTTPS {
		for _, option := range opt.Option {
			if local, ok := option.(*mdns.EDNS0_LOCAL); ok && local.Code == 65001 && string(local.Data) == "\x01" {
				bundle = true
			}
		}
	}
	if bundle || question.Qtype == mdns.TypeHTTPS {
		answer, err = internet.QueryDomainDNS(ctx, question.Name)
		// Ordinary clients may still use a DNS implementation without bundles,
		// or retrieve service records when an address lookup is unavailable.
		if err != nil && !bundle {
			answer, err = internet.QueryRecordDNS(ctx, question.Name, question.Qtype)
		}
	} else {
		answer, err = internet.QueryRecordDNS(ctx, question.Name, question.Qtype)
	}
	if err != nil {
		errors.LogInfoInner(ctx, err, "tunnel DNS: ", question.Name, " could not be resolved")
		response.Rcode = mdns.RcodeServerFailure
		return response.Pack()
	}

	response.Rcode = answer.RCode
	for _, raw := range answer.Records {
		// Each record was packed on its own, so it unpacks from offset zero.
		rr, _, err := mdns.UnpackRR(raw, 0)
		if err != nil {
			errors.LogInfoInner(ctx, err, "tunnel DNS: dropping an unreadable record")
			continue
		}
		response.Answer = append(response.Answer, rr)
	}
	if bundle {
		for _, raw := range answer.Additional {
			rr, _, err := mdns.UnpackRR(raw, 0)
			if err != nil {
				return nil, err
			}
			response.Extra = append(response.Extra, rr)
		}
		response.SetEdns0(1232, false)
		response.IsEdns0().Option = append(response.IsEdns0().Option, &mdns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}})
	}
	return response.Pack()
}

func readPrefixedMessage(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[:])
	if length == 0 {
		return nil, errors.New("empty DNS message")
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(reader, message); err != nil {
		return nil, err
	}
	return message, nil
}

func writePrefixedMessage(writer buf.Writer, message []byte) error {
	if len(message) > tunnelDNSMaxMessage {
		return errors.New("DNS response is too large for a length-prefixed stream")
	}
	// Sized to the message: buf.New() is a fixed 8KiB, which a service binding
	// carrying ech keys can outgrow.
	b := buf.NewWithSize(int32(len(message)) + 2)
	if err := binary.Write(b, binary.BigEndian, uint16(len(message))); err != nil {
		b.Release()
		return err
	}
	if _, err := b.Write(message); err != nil {
		b.Release()
		return err
	}
	return writer.WriteMultiBuffer(buf.MultiBuffer{b})
}
