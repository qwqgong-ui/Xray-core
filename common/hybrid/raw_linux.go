//go:build linux

package hybrid

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type msgWriter interface {
	WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error)
	SyscallConn() (syscall.RawConn, error)
}

var gsoScratch = sync.Pool{New: func() any { return new([gsoBytes]byte) }}

// gsoSupported asks the kernel whether the socket takes UDP_SEGMENT, as
// quic-go does before it sends with GSO on the same socket.
func gsoSupported(conn net.PacketConn) bool {
	c, ok := conn.(msgWriter)
	if !ok {
		return false
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var serr error
	if err = rc.Control(func(fd uintptr) {
		_, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
	}); err != nil {
		return false
	}
	return serr == nil
}

func writeGSO(conn net.PacketConn, tuple netip.AddrPort, run [][]byte) error {
	c, ok := conn.(msgWriter)
	if !ok {
		return syscall.EOPNOTSUPP
	}
	scratch := gsoScratch.Get().(*[gsoBytes]byte)
	defer gsoScratch.Put(scratch)
	n := 0
	for _, p := range run {
		n += copy(scratch[n:], p)
	}
	var oob [unix.SizeofCmsghdr + 8]byte
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(len(run[0])))
	_, _, err := c.WriteMsgUDPAddrPort(scratch[:n], oob[:unix.CmsgSpace(2)], tuple)
	return err
}

// gsoRefused reports an error that the same datagrams sent one at a time may
// not meet: the kernel refused the segmented send itself.
func gsoRefused(err error) bool {
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EMSGSIZE) || errors.Is(err, unix.EOPNOTSUPP)
}

// gsoUnsupported reports a refusal that every later GSO send would meet too.
// EIO is what udp_send_skb returns when the device lacks TX checksum offload.
func gsoUnsupported(err error) bool {
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EOPNOTSUPP)
}
