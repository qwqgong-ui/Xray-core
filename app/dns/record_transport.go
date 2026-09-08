package dns

import (
	"context"
	"encoding/binary"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

// Every name server answers record queries over its own existing transport.
// None of them opens a second kind of connection, and none of them exposes
// wire framing past this file: queryRecord hands down bytes and gets bytes
// back, and the caller above it sees records.

// QueryRecord implements RecordServer by reusing the server's own HTTP client,
// so the query travels the same connection, routing and padding path an
// address query would.
func (s *DoHNameServer) QueryRecord(ctx context.Context, domain string, qtype uint16) (*dns_feature.RecordResponse, error) {
	return queryRecord(ctx, s.dohHTTPSContext, domain, qtype)
}

// QueryRecord implements RecordServer using the server's existing dialer.
func (s *TCPNameServer) QueryRecord(ctx context.Context, domain string, qtype uint16) (*dns_feature.RecordResponse, error) {
	return queryRecord(ctx, func(ctx context.Context, query []byte) ([]byte, error) {
		conn, err := s.dial(ctx)
		if err != nil {
			return nil, errors.New("failed to dial name server").Base(err)
		}
		defer conn.Close()
		return exchangeRecordStream(ctx, conn, query)
	}, domain, qtype)
}

// QueryRecord implements RecordServer using the server's existing QUIC
// connection.
func (s *QUICNameServer) QueryRecord(ctx context.Context, domain string, qtype uint16) (*dns_feature.RecordResponse, error) {
	return queryRecord(ctx, func(ctx context.Context, query []byte) ([]byte, error) {
		stream, err := s.openStream(ctx)
		if err != nil {
			return nil, errors.New("failed to open QUIC stream").Base(err)
		}
		defer stream.Close()
		stop := context.AfterFunc(ctx, func() { stream.CancelRead(0); stream.CancelWrite(0) })
		defer stop()

		onWire, id := zeroQUICMessageID(query)
		response, err := exchangeOverStream(stream, onWire)
		if err != nil {
			return nil, err
		}
		return restoreQUICMessageID(response, id), nil
	}, domain, qtype)
}

// QueryRecord implements RecordServer for a plain UDP name server by asking it
// over TCP instead (RFC 7766, which every recursive resolver must support).
//
// A record query is the one case where the datagram transport is the wrong
// tool: a service binding carries ech keys and outgrows the bare 512-byte
// limit easily, so a UDP answer would come back truncated and there would be
// nothing to do about it but open the TCP connection anyway. Opening it up
// front costs one round trip and removes truncation, EDNS0 sizing and response
// demultiplexing from this path entirely.
func (s *ClassicNameServer) QueryRecord(ctx context.Context, domain string, qtype uint16) (*dns_feature.RecordResponse, error) {
	return queryRecord(ctx, func(ctx context.Context, query []byte) ([]byte, error) {
		destination := net.TCPDestination(s.address.Address, s.address.Port)
		link, err := s.dispatcher.Dispatch(toDnsContext(ctx, destination.String()), destination)
		if err != nil {
			return nil, errors.New("failed to reach name server over TCP").Base(err)
		}
		conn := cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
		)
		defer conn.Close()
		return exchangeRecordStream(ctx, conn, query)
	}, domain, qtype)
}

// zeroQUICMessageID returns the query as RFC 9250 requires it on the wire --
// message id zero -- along with the id that was there. The id is ours to
// choose, so it is sent as zero rather than sent as something the server was
// told not to echo and then hoped for.
func zeroQUICMessageID(query []byte) (onWire []byte, id uint16) {
	onWire = append([]byte(nil), query...)
	if len(onWire) < 2 {
		return onWire, 0
	}
	id = binary.BigEndian.Uint16(onWire[:2])
	binary.BigEndian.PutUint16(onWire[:2], 0)
	return onWire, id
}

// restoreQUICMessageID puts the caller's id back on a response that came over
// DoQ, so it can be matched like any other DNS answer.
func restoreQUICMessageID(response []byte, id uint16) []byte {
	if len(response) >= 2 {
		binary.BigEndian.PutUint16(response[:2], id)
	}
	return response
}

// exchangeOverStream speaks length-prefixed DNS (RFC 1035 4.2.2), shared by
// DNS over TCP, TLS and QUIC.
func exchangeOverStream(conn interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}, query []byte,
) ([]byte, error) {
	if len(query) > 65535 {
		return nil, errors.New("record query is too large for a length-prefixed stream")
	}
	request := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(request[:2], uint16(len(query)))
	copy(request[2:], query)
	if _, err := conn.Write(request); err != nil {
		return nil, errors.New("failed to send record query").Base(err)
	}

	header := buf.New()
	defer header.Release()
	if _, err := header.ReadFullFrom(conn, 2); err != nil {
		return nil, errors.New("failed to read record response length").Base(err)
	}
	length := binary.BigEndian.Uint16(header.Bytes())
	if length == 0 {
		return nil, errors.New("record response is empty")
	}

	body := buf.NewWithSize(int32(length))
	defer body.Release()
	if _, err := body.ReadFullFrom(conn, int32(length)); err != nil {
		return nil, errors.New("failed to read record response").Base(err)
	}
	return append([]byte(nil), body.Bytes()...), nil
}

// A bounded record lookup must interrupt the underlying stream, including
// dispatch-backed connections whose dial path detaches the caller's context.
func exchangeRecordStream(ctx context.Context, conn net.Conn, query []byte) ([]byte, error) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	response, err := exchangeOverStream(conn, query)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return response, err
}
