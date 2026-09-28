package hybrid

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"time"
)

// Called with s.mu held. Only a short-lived proof registered on an existing
// reserved stream can establish a tuple. The observed NAT port is authoritative.
// This probe was already sent on the stream, so do not forward it twice.
func (s *Server) bindLeaseLocked(p []byte, a netip.AddrPort, now time.Time) bool {
	digest := sha256.Sum256(p)
	var match *flow
	for f := range s.flows {
		if !f.lease || f.disabled || f.target == nil || f.peer != a.Addr() ||
			!now.Before(f.leaseProbeUntil) || f.leaseDigest != digest {
			continue
		}
		if match != nil {
			return false
		}
		match = f
	}
	if match == nil {
		return false
	}
	f := match
	if f.tuple.IsValid() && f.tuple != a && now.Before(f.leaseUntil) {
		return false
	}
	if s.tuples[f.tuple] == f {
		delete(s.tuples, f.tuple)
	}
	f.tuple = a
	s.tuples[a] = f
	f.leaseProbeUntil = time.Time{}
	f.leaseUntil = now.Add(leaseDuration)
	f.leaseProof = nil
	f.leaseProofNext = time.Time{}
	f.leaseConfirmUntil = now.Add(3 * time.Second)
	f.paused = true // wait for reliable acknowledgement before switching downstream
	f.leaseUpReady = false
	seq := f.leaseSeq
	select {
	case f.leaseAcks <- leaseControl{kind: leaseBound, seq: seq}:
	default: // bounded queue; the client can retry on the reliable stream
	}
	return true
}
func (f *flow) writeLeaseAcks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-f.leaseAcks:
			if err := f.sendLease(c); err != nil {
				f.close()
				return
			}
		}
	}
}
func (f *flow) sendLease(c leaseControl) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	return writeLease(f.stream, c)
}
func (f *flow) handleLease(c leaseControl) error {
	s := f.server
	s.mu.Lock()
	now := time.Now()
	if f.disabled {
		s.mu.Unlock()
		return nil
	}
	switch c.kind {
	case leaseBind:
		if c.seq <= f.leaseSeq {
			s.mu.Unlock()
			return errors.New("hybrid: stale lease request")
		}
		// Rebinding an unexpired tuple needs an explicit pause first.
		if f.tuple.IsValid() && !f.paused && now.Before(f.leaseUntil) {
			s.mu.Unlock()
			return errors.New("hybrid: active lease binding")
		}
		if s.tuples[f.tuple] == f {
			delete(s.tuples, f.tuple)
		}
		f.tuple = netip.AddrPort{}
		f.leaseUntil = time.Time{}
		f.leaseUpReady = false
		f.leaseProof = nil
		f.leaseConfirmUntil = time.Time{}
		f.leaseSeq = c.seq
		f.leaseDigest = c.digest
		f.leaseProbeUntil = now.Add(3 * time.Second)
	case leaseActivate:
		if c.seq == f.leaseSeq && f.tuple.IsValid() && now.Before(f.leaseUntil) && now.Before(f.leaseConfirmUntil) {
			if len(f.leaseProof) == 0 || f.leaseProofDigest != c.digest {
				s.mu.Unlock()
				return nil
			}
			// Accept upstream once the reverse proof is validated, before the
			// acknowledgement can reach the client. Downstream stays mirrored
			// until that acknowledgement has been written.
			f.leaseUpReady = true
			f.leaseConfirmUntil = time.Time{}
			f.leaseProof = nil
			s.mu.Unlock()
			if err := f.sendLease(leaseControl{kind: leaseConfirmed, seq: c.seq}); err != nil {
				return err
			}
			s.mu.Lock()
			if c.seq == f.leaseSeq && time.Now().Before(f.leaseUntil) && !f.disabled {
				f.paused = false
			}
		}
	case leaseRenew:
		if c.seq <= f.leaseSeq {
			s.mu.Unlock()
			return errors.New("hybrid: stale lease renewal")
		}
		if !f.tuple.IsValid() || !now.Before(f.leaseUntil) {
			s.mu.Unlock()
			return nil
		}
		f.leaseSeq = c.seq
		// Assign from now, never add to the existing deadline. UDP cannot renew it.
		f.leaseUntil = now.Add(leaseDuration)
		s.mu.Unlock()
		return f.sendLease(leaseControl{kind: leaseRenewed, seq: c.seq})
	default:
		s.mu.Unlock()
		return errors.New("hybrid: unexpected client lease control")
	}
	s.mu.Unlock()
	return nil
}

// Prove the reverse path using real target bytes, while delivering a reliable
// copy until confirmation. No digest or secret is disclosed over the control
// stream before the client reports what actually arrived on its UDP socket.
func (f *flow) probeLeaseDownstream(p []byte) {
	if !Short(p) {
		return
	}
	s := f.server
	s.mu.Lock()
	now := time.Now()
	if f.disabled || !f.paused || !f.tuple.IsValid() || !now.Before(f.leaseUntil) || !now.Before(f.leaseConfirmUntil) || now.Before(f.leaseProofNext) || s.conn == nil {
		s.mu.Unlock()
		return
	}
	// Keep the first proof stable for this attempt. A burst must neither
	// evict it before the ACK returns nor mirror the entire download to UDP.
	if f.leaseProof == nil {
		f.leaseProof = append([]byte(nil), p...)
		f.leaseProofDigest = sha256.Sum256(p)
	}
	f.leaseProofNext = now.Add(250 * time.Millisecond)
	proof := f.leaseProof
	conn, tuple := s.conn, f.tuple
	s.mu.Unlock()
	// A failed probe leaves the reliable copy intact; the client will time out.
	s.writeRaw(conn, tuple, [][]byte{proof})
}
