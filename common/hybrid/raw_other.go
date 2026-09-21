//go:build !linux

package hybrid

import (
	"errors"
	"net"
	"net/netip"
)

var errNoGSO = errors.New("hybrid: UDP GSO is Linux-only")

func gsoSupported(net.PacketConn) bool { return false }

func writeGSO(net.PacketConn, netip.AddrPort, [][]byte) error { return errNoGSO }

func gsoRefused(err error) bool { return errors.Is(err, errNoGSO) }

func gsoUnsupported(err error) bool { return errors.Is(err, errNoGSO) }
