package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	dnsfeature "github.com/xtls/xray-core/features/dns"
)

type bundleTestServer struct {
	ips, https atomic.Int32
	fail       bool
	ttl        uint32
}

func (*bundleTestServer) Name() string         { return "bundle-test" }
func (*bundleTestServer) IsDisableCache() bool { return false }
func (s *bundleTestServer) QueryIP(context.Context, string, dnsfeature.IPOption) ([]net.IP, uint32, error) {
	s.ips.Add(1)
	return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, 120, nil
}
func (s *bundleTestServer) QueryRecord(context.Context, string, uint16) (*dnsfeature.RecordResponse, error) {
	s.https.Add(1)
	if s.fail {
		return nil, errors.New("HTTPS unavailable")
	}
	rr, _ := mdns.NewRR(`example.com. 30 IN HTTPS 1 . alpn="h3,h2" port=8443 ech=AQID ipv4hint=192.0.2.99`)
	rr.Header().Ttl = s.ttl
	raw, err := packRecord(rr)
	return &dnsfeature.RecordResponse{Records: []dnsfeature.RawRecord{raw}}, err
}
func newBundleTestDNS(t *testing.T, server *bundleTestServer) *DNS {
	t.Helper()
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	option := &dnsfeature.IPOption{IPv4Enable: true, IPv6Enable: true}
	return &DNS{ctx: context.Background(), hosts: hosts, ipOption: option, clients: []*Client{{server: server, ipOption: option, timeoutMs: time.Second}}}
}
func TestDomainBundleWarmsOutboundAndExpiresTogether(t *testing.T) {
	server := &bundleTestServer{ttl: 30}
	resolver := newBundleTestDNS(t, server)
	answer, err := resolver.QueryDomain(t.Context(), "EXAMPLE.com.")
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Additional) != 2 || len(answer.Records) != 1 {
		t.Fatalf("incomplete bundle: %+v", answer)
	}
	for _, raw := range append(append([]dnsfeature.RawRecord{}, answer.Records...), answer.Additional...) {
		rr, _, err := mdns.UnpackRR(raw, 0)
		if err != nil || rr.Header().Ttl != 30 {
			t.Fatalf("TTL: %v %v", rr, err)
		}
	}
	ips, ttl, err := resolver.LookupIP("example.com", dnsfeature.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.1" || ttl > 30 {
		t.Fatalf("outbound: %v %d %v", ips, ttl, err)
	}
	if _, err := resolver.QueryRecord(t.Context(), "example.com", mdns.TypeHTTPS); err != nil {
		t.Fatal(err)
	}
	if server.ips.Load() != 1 || server.https.Load() != 1 {
		t.Fatal("first outbound or HTTPS query performed another lookup")
	}
	resolver.domains.mu.Lock()
	entry := resolver.domains.entries["example.com"]
	entry.expires = time.Now().Add(-time.Second)
	resolver.domains.entries["example.com"] = entry
	resolver.domains.mu.Unlock()
	if _, err := resolver.QueryDomain(t.Context(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if server.ips.Load() != 2 || server.https.Load() != 2 {
		t.Fatal("bundle did not refresh as a whole")
	}
}
func TestDomainBundleDoesNotPublishFailedOrZeroTTLMetadata(t *testing.T) {
	for _, fail := range []bool{true, false} {
		server := &bundleTestServer{fail: fail}
		resolver := newBundleTestDNS(t, server)
		_, err := resolver.QueryDomain(t.Context(), "example.com")
		if (err != nil) != fail {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolver.domains.get("example.com") != nil {
			t.Fatal("incomplete or zero TTL result cached")
		}
	}
}

type bundleContextServer struct {
	bundleTestServer
	inbound   *session.Inbound
	outbounds []*session.Outbound
}

func (s *bundleContextServer) QueryRecord(ctx context.Context, domain string, qtype uint16) (*dnsfeature.RecordResponse, error) {
	s.inbound = session.InboundFromContext(ctx)
	s.outbounds = session.OutboundsFromContext(ctx)
	return s.bundleTestServer.QueryRecord(ctx, domain, qtype)
}
func TestRecordQueryDetachesUserSpliceContext(t *testing.T) {
	server := &bundleContextServer{bundleTestServer: bundleTestServer{ttl: 30}}
	resolver := newBundleTestDNS(t, &server.bundleTestServer)
	resolver.clients[0].server = server
	resolver.clients[0].tag = "internal-dns"
	original := &session.Inbound{Tag: "user", CanSpliceCopy: 1}
	ctx := session.ContextWithInbound(t.Context(), original)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	if _, err := resolver.QueryRecord(ctx, "example.com", mdns.TypeHTTPS); err != nil {
		t.Fatal(err)
	}
	if server.inbound == original || server.inbound.CanSpliceCopy != 0 || server.inbound.Tag != "internal-dns" || len(server.outbounds) != 0 {
		t.Fatal("record query inherited a user's connection or lost DNS routing tag")
	}
	if original.CanSpliceCopy != 1 || original.Tag != "user" {
		t.Fatal("record query mutated user context")
	}
}
