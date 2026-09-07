// Package hybrid carries unchanged QUIC datagrams over a reliable proxy stream
// and, when available, an independent raw UDP path.
package hybrid

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const Address = "hybrid-quic.invalid:443"
const Magic = "HQS1"
const MaxPacket = 65507

// A zero frame permanently disables raw in both directions. EOF ends the flow.
func ReadFrame(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n == 65535 {
		return nil, nil
	} // stream keepalive; no application datagram
	if n > MaxPacket {
		return nil, errors.New("hybrid: oversized packet")
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}
func WriteFrame(w io.Writer, p []byte) error {
	if len(p) > MaxPacket {
		return errors.New("hybrid: oversized packet")
	}
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	return WriteAll(w, b)
}
func WriteAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Addresses use a two-byte length followed by a canonical host:port string.
func WriteAddress(w io.Writer, address string) error {
	if len(address) > 259 {
		return errors.New("hybrid: address too long")
	}
	return WriteFrame(w, []byte(address))
}
func ReadAddress(r io.Reader) (string, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return "", err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n == 0 || n > 259 {
		return "", errors.New("hybrid: invalid address length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	host, port, err := net.SplitHostPort(string(b))
	if err != nil || host == "" {
		return "", errors.New("hybrid: invalid address")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", errors.New("hybrid: invalid port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p))), nil
}
func IsReserved(host string) bool {
	return strings.EqualFold(strings.TrimSuffix(host, "."), "hybrid-quic.invalid")
}
func Initial(p []byte) bool {
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(p[1:5])
	t := (p[0] >> 4) & 3
	return (v == 1 && t == 0) || (v == 0x6b3343cf && t == 1)
}
func Short(p []byte) bool { return len(p) > 1 && p[0]&0xc0 == 0x40 }

// LongCIDs also accepts Version Negotiation and Retry, whose visible CID
// fields use the same layout. They always remain on the stream.
func LongCIDs(p []byte) (string, string, bool) {
	if len(p) < 7 || p[0]&0x80 == 0 {
		return "", "", false
	}
	n := int(p[5])
	if n > 20 || len(p) < 7+n {
		return "", "", false
	}
	m := int(p[6+n])
	if m > 20 || len(p) < 7+n+m {
		return "", "", false
	}
	return string(p[6 : 6+n]), string(p[7+n : 7+n+m]), true
}
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("198.18.0.0/15").Contains(ip)
}

// Request has no flow ID. Forwarded origin information is accepted only from
// explicitly trusted inbound tags; clients always send Hops=0 and no ClientIP.
type Request struct {
	Target   string
	ClientIP netip.Addr
	Hops     byte
}

func ReadRequest(r io.Reader) (Request, error) {
	var q Request
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return q, err
	}
	if string(h[:4]) != Magic || h[4] > 8 {
		return q, errors.New("hybrid: unsupported request")
	}
	q.Hops = h[4]
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return q, err
	}
	if n[0] != 0 && n[0] != 4 && n[0] != 16 {
		return q, errors.New("hybrid: invalid origin")
	}
	if n[0] != 0 {
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return q, err
		}
		q.ClientIP, _ = netip.AddrFromSlice(b)
		q.ClientIP = q.ClientIP.Unmap()
	}
	var err error
	q.Target, err = ReadAddress(r)
	return q, err
}
func WriteRequest(w io.Writer, q Request) error {
	b := append([]byte(Magic), q.Hops)
	if q.ClientIP.IsValid() {
		ip := q.ClientIP.Unmap().AsSlice()
		b = append(b, byte(len(ip)))
		b = append(b, ip...)
	} else {
		b = append(b, 0)
	}
	if err := WriteAll(w, b); err != nil {
		return err
	}
	return WriteAddress(w, q.Target)
}

// WriteKeepAlive preserves the lifetime anchor while application packets use raw.
func WriteKeepAlive(w io.Writer) error { return WriteAll(w, []byte{255, 255}) }
