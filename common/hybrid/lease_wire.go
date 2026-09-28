package hybrid

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const leaseDuration = 30 * time.Second
const (
	leaseBind byte = iota + 1
	leaseBound
	leaseActivate
	leaseRenew
	leaseRenewed
	leaseConfirmed
)

type leaseControl struct {
	kind   byte
	seq    uint64
	digest [32]byte
}

// Controls exist only inside the authenticated hybrid-quic.invalid stream.
// UDP payloads are never wrapped or marked.
func writeLease(w io.Writer, c leaseControl) error {
	var b [43]byte
	binary.BigEndian.PutUint16(b[:2], 65534)
	b[2] = c.kind
	binary.BigEndian.PutUint64(b[3:11], c.seq)
	copy(b[11:], c.digest[:])
	return WriteAll(w, b[:])
}
func readRecord(r io.Reader) ([]byte, *leaseControl, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n == 65534 {
		var b [41]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, nil, err
		}
		c := &leaseControl{kind: b[0], seq: binary.BigEndian.Uint64(b[1:9])}
		copy(c.digest[:], b[9:])
		if c.kind < leaseBind || c.kind > leaseConfirmed || c.seq == 0 {
			return nil, nil, errors.New("hybrid: invalid lease control")
		}
		return nil, c, nil
	}
	if n == 65535 {
		return nil, nil, nil
	}
	if n > MaxPacket {
		return nil, nil, errors.New("hybrid: oversized packet")
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, nil, err
}
