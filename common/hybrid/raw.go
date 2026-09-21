package hybrid

import (
	"net"
	"net/netip"
)

// One UDP GSO send carries up to gsoSegments datagrams of one size, the last
// possibly shorter. 64 is the kernel's UDP_MAX_SEGMENTS before 6.x raised it;
// the byte bound keeps the whole run inside one IP datagram.
const (
	gsoSegments = 64
	gsoBytes    = 65000
)

type addrPortWriter interface {
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
}

// writeRaw sends ps to tuple in order and returns how many left before an
// error. Where the socket allows, each run of equal-sized datagrams leaves in
// one UDP GSO send, so the kernel walks its UDP/IP path and the qdisc once per
// run rather than once per datagram, and the relay makes one system call.
func (s *Server) writeRaw(conn net.PacketConn, tuple netip.AddrPort, ps [][]byte) (int, error) {
	sent := 0
	for sent < len(ps) {
		if s.gso.Load() {
			if end := gsoRun(ps, sent); end-sent > 1 {
				err := writeGSO(conn, tuple, ps[sent:end])
				if err == nil {
					sent = end
					continue
				}
				if !gsoRefused(err) {
					return sent, err
				}
				if gsoUnsupported(err) {
					s.gso.Store(false)
				}
				// Carry the refused run one datagram at a time.
				for ; sent < end; sent++ {
					if err := writeOne(conn, tuple, ps[sent]); err != nil {
						return sent, err
					}
				}
				continue
			}
		}
		if err := writeOne(conn, tuple, ps[sent]); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// gsoRun returns the end of the run from ps[i] that one GSO send can carry.
func gsoRun(ps [][]byte, i int) int {
	size := len(ps[i])
	total := size
	end := i + 1
	for end < len(ps) && end-i < gsoSegments {
		n := len(ps[end])
		if n > size || total+n > gsoBytes {
			break
		}
		total += n
		end++
		if n < size {
			break // only the last segment may be short
		}
	}
	return end
}

func writeOne(conn net.PacketConn, tuple netip.AddrPort, p []byte) error {
	if c, ok := conn.(addrPortWriter); ok {
		_, err := c.WriteToUDPAddrPort(p, tuple)
		return err
	}
	_, err := conn.WriteTo(p, net.UDPAddrFromAddrPort(tuple))
	return err
}
