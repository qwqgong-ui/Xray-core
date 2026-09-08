package dns

import (
	"context"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	dnsfeature "github.com/xtls/xray-core/features/dns"
)

type domainEntry struct {
	answer  *dnsfeature.RecordResponse
	expires time.Time
}
type domainCache struct {
	mu      sync.Mutex
	entries map[string]domainEntry
}

func (c *domainCache) get(domain string) *dnsfeature.RecordResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := strings.ToLower(strings.TrimSuffix(domain, "."))
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !time.Now().Before(entry.expires) {
		delete(c.entries, key)
		return nil
	}
	ttl := uint32(time.Until(entry.expires) / time.Second)
	result := &dnsfeature.RecordResponse{RCode: entry.answer.RCode}
	copyRecords := func(records []dnsfeature.RawRecord) []dnsfeature.RawRecord {
		var copied []dnsfeature.RawRecord
		for _, raw := range records {
			rr, _, err := mdns.UnpackRR(raw, 0)
			if err != nil {
				return nil
			}
			rr.Header().Ttl = ttl
			packed, err := packRecord(rr)
			if err != nil {
				return nil
			}
			copied = append(copied, packed)
		}
		return copied
	}
	result.Records = copyRecords(entry.answer.Records)
	result.Additional = copyRecords(entry.answer.Additional)
	return result
}

func (c *domainCache) put(domain string, answer *dnsfeature.RecordResponse, ttl uint32) {
	if ttl == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]domainEntry)
	}
	if len(c.entries) >= 1024 {
		// Bound memory without allowing an expired entry to survive a read.
		for key := range c.entries {
			delete(c.entries, key)
			break
		}
	}
	copy := &dnsfeature.RecordResponse{RCode: answer.RCode}
	for _, raw := range answer.Records {
		copy.Records = append(copy.Records, append(dnsfeature.RawRecord(nil), raw...))
	}
	for _, raw := range answer.Additional {
		copy.Additional = append(copy.Additional, append(dnsfeature.RawRecord(nil), raw...))
	}
	c.entries[domain] = domainEntry{answer: copy, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
}

func (c *domainCache) lookup(domain string, option dnsfeature.IPOption) ([]net.IP, uint32, bool) {
	answer := c.get(domain)
	if answer == nil {
		return nil, 0, false
	}
	var ips []net.IP
	var ttl uint32
	for _, raw := range answer.Additional {
		rr, _, err := mdns.UnpackRR(raw, 0)
		if err != nil {
			return nil, 0, false
		}
		ttl = rr.Header().Ttl
		switch rr := rr.(type) {
		case *mdns.A:
			if option.IPv4Enable {
				ips = append(ips, rr.A)
			}
		case *mdns.AAAA:
			if option.IPv6Enable {
				ips = append(ips, rr.AAAA)
			}
		}
	}
	// A missing family may be disabled by DNS policy; let normal resolution
	// decide rather than synthesizing a permanent empty answer.
	return ips, ttl, len(ips) > 0
}

// QueryDomain resolves addresses through LookupIP (hosts, query strategy,
// expected-IP filters and fallback included), while HTTPS uses RecordClient.
// It publishes the result only after both operations finish. Outbound address
// lookups can then reuse the very addresses returned to this client.
func (s *DNS) QueryDomain(ctx context.Context, domain string) (*dnsfeature.RecordResponse, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if answer := s.domains.get(domain); answer != nil {
		return answer, nil
	}
	ctx, cancel := context.WithTimeout(ctx, recordQueryTimeout)
	defer cancel()
	type addresses struct {
		ips []net.IP
		ttl uint32
		err error
	}
	ipCh := make(chan addresses, 1)
	go func() {
		ips, ttl, err := s.LookupIP(domain, dnsfeature.IPOption{IPv4Enable: true, IPv6Enable: true})
		ipCh <- addresses{ips, ttl, err}
	}()
	service, err := s.QueryRecord(ctx, domain, mdns.TypeHTTPS)
	if err != nil {
		return nil, err
	}
	var address addresses
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case address = <-ipCh:
	}
	if address.err != nil {
		return nil, address.err
	}
	result := &dnsfeature.RecordResponse{RCode: service.RCode}
	ttl := address.ttl
	if service.RCode != mdns.RcodeSuccess {
		return service, nil
	}
	// No SOA accompanies RecordResponse, so a negative HTTPS answer cannot be
	// assigned an invented negative-cache lifetime.
	if len(service.Records) == 0 {
		ttl = 0
	}
	var records []mdns.RR
	for _, raw := range service.Records {
		rr, _, err := mdns.UnpackRR(raw, 0)
		if err != nil {
			return nil, err
		}
		ttl = min(ttl, rr.Header().Ttl)
		records = append(records, rr)
	}
	for _, rr := range records {
		rr.Header().Ttl = ttl
		raw, err := packRecord(rr)
		if err != nil {
			return nil, err
		}
		result.Records = append(result.Records, raw)
	}
	for _, ip := range address.ips {
		header := mdns.RR_Header{Name: mdns.Fqdn(domain), Class: mdns.ClassINET, Ttl: ttl}
		var rr mdns.RR
		if v4 := ip.To4(); v4 != nil {
			header.Rrtype = mdns.TypeA
			rr = &mdns.A{Hdr: header, A: v4}
		} else {
			header.Rrtype = mdns.TypeAAAA
			rr = &mdns.AAAA{Hdr: header, AAAA: ip}
		}
		raw, err := packRecord(rr)
		if err != nil {
			return nil, err
		}
		result.Additional = append(result.Additional, raw)
	}
	s.domains.put(domain, result, ttl)
	return result, nil
}

func (s *DNS) LookupDomainCache(domain string, option dnsfeature.IPOption) ([]net.IP, uint32, bool) {
	return s.domains.lookup(domain, option)
}
