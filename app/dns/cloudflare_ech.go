package dns

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	dnsfeature "github.com/xtls/xray-core/features/dns"
)

const cloudflareECHName = "cloudflare-ech.com"

// Official proxy ranges, verified 2026-09-08. Keep both lists in sync with
// https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6.
// These are an eligibility filter, not proof that a zone enabled ECH.
var cloudflareECHPrefixes = []netip.Prefix{
	netip.MustParsePrefix("173.245.48.0/20"), netip.MustParsePrefix("103.21.244.0/22"),
	netip.MustParsePrefix("103.22.200.0/22"), netip.MustParsePrefix("103.31.4.0/22"),
	netip.MustParsePrefix("141.101.64.0/18"), netip.MustParsePrefix("108.162.192.0/18"),
	netip.MustParsePrefix("190.93.240.0/20"), netip.MustParsePrefix("188.114.96.0/20"),
	netip.MustParsePrefix("197.234.240.0/22"), netip.MustParsePrefix("198.41.128.0/17"),
	netip.MustParsePrefix("162.158.0.0/15"), netip.MustParsePrefix("104.16.0.0/13"),
	netip.MustParsePrefix("104.24.0.0/14"), netip.MustParsePrefix("172.64.0.0/13"),
	netip.MustParsePrefix("131.0.72.0/22"), netip.MustParsePrefix("2400:cb00::/32"),
	netip.MustParsePrefix("2606:4700::/32"), netip.MustParsePrefix("2803:f800::/32"),
	netip.MustParsePrefix("2405:b500::/32"), netip.MustParsePrefix("2405:8100::/32"),
	netip.MustParsePrefix("2a06:98c0::/29"), netip.MustParsePrefix("2c0f:f248::/32"),
}

func allCloudflareIPs(ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			return false
		}
		address = address.Unmap()
		found := false
		for _, prefix := range cloudflareECHPrefixes {
			if prefix.Contains(address) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type cloudflareECHCache struct {
	mu                  sync.Mutex
	config              []byte
	expires, retryAfter time.Time
	pending             chan struct{}
}

// load shares one bounded refresh across domains, without serving expired keys
// or holding a mutex over DNS I/O. A failed refresh leaves original answers usable.
func (c *cloudflareECHCache) load(ctx context.Context, query func(context.Context) (*dnsfeature.RecordResponse, error)) ([]byte, uint32) {
	for {
		c.mu.Lock()
		if time.Now().Before(c.expires) {
			config := append([]byte(nil), c.config...)
			ttl := uint32(time.Until(c.expires) / time.Second)
			c.mu.Unlock()
			return config, ttl
		}
		if time.Now().Before(c.retryAfter) {
			c.mu.Unlock()
			return nil, 0
		}
		if pending := c.pending; pending != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, 0
			case <-pending:
				continue
			}
		}
		c.pending = make(chan struct{})
		c.mu.Unlock()
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		answer, err := query(work)
		cancel()
		var config []byte
		ttl := uint32(^uint32(0))
		if err == nil && answer != nil && answer.RCode == mdns.RcodeSuccess {
			for _, raw := range answer.Records {
				rr, _, err := mdns.UnpackRR(raw, 0)
				if err != nil {
					config = nil
					break
				}
				ttl = min(ttl, rr.Header().Ttl)
				https, ok := rr.(*mdns.HTTPS)
				if !ok || https.Priority == 0 || !strings.EqualFold(https.Hdr.Name, cloudflareECHName+".") {
					continue
				}
				for _, value := range https.Value {
					if ech, ok := value.(*mdns.SVCBECHConfig); ok && len(ech.ECH) >= 6 && int(binary.BigEndian.Uint16(ech.ECH)) == len(ech.ECH)-2 {
						config = append([]byte(nil), ech.ECH...)
					}
				}
			}
		}
		c.mu.Lock()
		if len(config) > 0 {
			c.config = append([]byte(nil), config...)
			c.expires = time.Now().Add(time.Duration(ttl) * time.Second)
		} else {
			c.retryAfter = time.Now().Add(30 * time.Second)
		}
		close(c.pending)
		c.pending = nil
		c.mu.Unlock()
		if len(config) == 0 {
			return nil, 0
		}
		return config, ttl
	}
}

// supplementCloudflareECH only edits the DNS answer, never a forwarded TLS
// ClientHello. Use resolved addresses, never HTTPS hints or the node's IP.
func (s *DNS) supplementCloudflareECH(ctx context.Context, domain string, ips []net.IP, addressTTL uint32, answer *dnsfeature.RecordResponse) *dnsfeature.RecordResponse {
	if answer.RCode != mdns.RcodeSuccess || !allCloudflareIPs(ips) || strings.EqualFold(domain, cloudflareECHName) {
		return answer
	}
	owner := mdns.Fqdn(strings.ToLower(domain))
	records := make([]mdns.RR, 0, len(answer.Records)+1)
	aliases := map[string]string{}
	for _, raw := range answer.Records {
		rr, _, err := mdns.UnpackRR(raw, 0)
		if err != nil {
			return answer
		}
		records = append(records, rr)
		if cname, ok := rr.(*mdns.CNAME); ok {
			key := strings.ToLower(cname.Hdr.Name)
			target := strings.ToLower(cname.Target)
			if previous, ok := aliases[key]; ok && previous != target {
				return answer
			}
			aliases[key] = target
		}
	}
	visited := map[string]bool{}
	for aliases[owner] != "" {
		if visited[owner] {
			return answer
		}
		visited[owner] = true
		owner = aliases[owner]
	}
	var candidates []*mdns.HTTPS
	for _, rr := range records {
		https, ok := rr.(*mdns.HTTPS)
		if !ok {
			continue
		}
		// Don't attach an IP-gated key to AliasMode or a different service endpoint.
		if !strings.EqualFold(https.Hdr.Name, owner) || https.Priority == 0 || https.Target != "." && !strings.EqualFold(https.Target, owner) {
			return answer
		}
		existing := false
		for _, value := range https.Value {
			if value.Key() == mdns.SVCB_ECHCONFIG {
				existing = true
				break
			}
		}
		if !existing {
			candidates = append(candidates, https)
		}
	}
	hasService := false
	for _, rr := range records {
		if _, ok := rr.(*mdns.HTTPS); ok {
			hasService = true
		}
	}
	if hasService && len(candidates) == 0 {
		return answer
	}
	config, ttl := s.cloudflareECH.load(ctx, func(ctx context.Context) (*dnsfeature.RecordResponse, error) {
		return s.QueryRecord(ctx, cloudflareECHName, mdns.TypeHTTPS)
	})
	if len(config) == 0 {
		return answer
	}
	ttl = min(ttl, addressTTL)
	if !hasService {
		https := &mdns.HTTPS{SVCB: mdns.SVCB{Hdr: mdns.RR_Header{Name: owner, Rrtype: mdns.TypeHTTPS, Class: mdns.ClassINET, Ttl: ttl}, Priority: 1, Target: "."}}
		records = append(records, https)
		candidates = append(candidates, https)
	}
	for _, https := range candidates {
		https.Value = append(https.Value, &mdns.SVCBECHConfig{ECH: append([]byte(nil), config...)})
		https.Hdr.Ttl = min(https.Hdr.Ttl, ttl)
	}
	result := &dnsfeature.RecordResponse{RCode: answer.RCode, Additional: answer.Additional}
	for _, rr := range records {
		if sig, ok := rr.(*mdns.RRSIG); ok && sig.TypeCovered == mdns.TypeHTTPS && strings.EqualFold(sig.Hdr.Name, owner) {
			continue
		}
		raw, err := packRecord(rr)
		if err != nil {
			return answer
		}
		result.Records = append(result.Records, raw)
	}
	return result
}
