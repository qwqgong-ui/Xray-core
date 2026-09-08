package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	dnsfeature "github.com/xtls/xray-core/features/dns"
)

const testCloudflareECH = "AEX+DQBBdgAgACA/G5mHYgLkpPaR5jusdDm9B5pqD4Yt2VOkQIeOi7rKHQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

type cloudflareTestServer struct {
	bundleTestServer
	addresses []net.IP
	answer    *dnsfeature.RecordResponse
	seedCalls atomic.Int32
	seedFail  bool
}

func (s *cloudflareTestServer) QueryIP(context.Context, string, dnsfeature.IPOption) ([]net.IP, uint32, error) {
	return s.addresses, 120, nil
}
func (s *cloudflareTestServer) QueryRecord(_ context.Context, domain string, _ uint16) (*dnsfeature.RecordResponse, error) {
	if domain == cloudflareECHName {
		s.seedCalls.Add(1)
		if s.seedFail {
			return nil, errors.New("seed unavailable")
		}
		rr, _ := mdns.NewRR(cloudflareECHName + ". 30 IN HTTPS 1 . ech=" + testCloudflareECH)
		raw, err := packRecord(rr)
		return &dnsfeature.RecordResponse{Records: []dnsfeature.RawRecord{raw}}, err
	}
	return s.answer, nil
}
func cfAnswer(t *testing.T, records ...string) *dnsfeature.RecordResponse {
	t.Helper()
	answer := &dnsfeature.RecordResponse{}
	for _, text := range records {
		rr, err := mdns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := packRecord(rr)
		if err != nil {
			t.Fatal(err)
		}
		answer.Records = append(answer.Records, raw)
	}
	return answer
}
func cfResolver(t *testing.T, server *cloudflareTestServer) *DNS {
	resolver := newBundleTestDNS(t, &server.bundleTestServer)
	resolver.clients[0].server = server
	return resolver
}
func findECH(t *testing.T, answer *dnsfeature.RecordResponse) []byte {
	t.Helper()
	for _, raw := range answer.Records {
		rr, _, err := mdns.UnpackRR(raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		if https, ok := rr.(*mdns.HTTPS); ok {
			for _, value := range https.Value {
				if ech, ok := value.(*mdns.SVCBECHConfig); ok {
					return ech.ECH
				}
			}
		}
	}
	return nil
}
func TestCloudflareECHPrefixes(t *testing.T) {
	for _, ip := range []string{"104.16.0.0", "104.23.255.255", "104.24.0.0", "104.27.255.255", "2606:4700::1", "::ffff:104.16.1.1"} {
		if !allCloudflareIPs([]net.IP{net.ParseIP(ip)}) {
			t.Fatalf("CF not matched: %s", ip)
		}
	}
	for _, ip := range []string{"104.15.255.255", "104.28.0.0", "1.1.1.1", "2606:4701::1", "192.0.2.1"} {
		if allCloudflareIPs([]net.IP{net.ParseIP(ip)}) {
			t.Fatalf("non-CF matched: %s", ip)
		}
	}
	if allCloudflareIPs(nil) || allCloudflareIPs([]net.IP{nil}) || allCloudflareIPs([]net.IP{net.ParseIP("104.16.1.1"), net.ParseIP("192.0.2.1")}) {
		t.Fatal("empty, invalid, or mixed address set eligible")
	}
}
func TestCloudflareECHSupplementKeepsParametersAndBoundsBundleTTL(t *testing.T) {
	original := cfAnswer(t, `example.com. 120 IN HTTPS 1 . alpn="h2" port=8443`)
	before := append([]byte(nil), original.Records[0]...)
	server := &cloudflareTestServer{addresses: []net.IP{net.ParseIP("104.16.1.1"), net.ParseIP("2606:4700::1")}, answer: original}
	resolver := cfResolver(t, server)
	answer, err := resolver.QueryDomain(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := base64.StdEncoding.DecodeString(testCloudflareECH)
	if !bytes.Equal(findECH(t, answer), expected) {
		t.Fatal("missing or wrong seed config")
	}
	if !bytes.Equal(original.Records[0], before) {
		t.Fatal("mutated original DNS response")
	}
	rr, _, _ := mdns.UnpackRR(answer.Records[0], 0)
	https := rr.(*mdns.HTTPS)
	if https.Hdr.Ttl != 30 || https.Value[0].(*mdns.SVCBAlpn).Alpn[0] != "h2" || https.Value[1].(*mdns.SVCBPort).Port != 8443 {
		t.Fatalf("lost parameters: %s", https)
	}
	for _, raw := range answer.Additional {
		rr, _, _ := mdns.UnpackRR(raw, 0)
		if rr.Header().Ttl != 30 {
			t.Fatal("address lifetime detached from ECH")
		}
	}
	if _, err := resolver.QueryDomain(t.Context(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if server.seedCalls.Load() != 1 {
		t.Fatal("cached bundle fetched seed again")
	}
}
func TestCloudflareECHCreatesMinimalRecordAfterCNAME(t *testing.T) {
	server := &cloudflareTestServer{addresses: []net.IP{net.ParseIP("2606:4700::1")}, answer: cfAnswer(t, "example.com. 10 IN CNAME edge.example.")}
	answer, err := cfResolver(t, server).QueryDomain(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Records) != 2 {
		t.Fatal("missing synthesized record")
	}
	rr, _, _ := mdns.UnpackRR(answer.Records[1], 0)
	https := rr.(*mdns.HTTPS)
	if https.Hdr.Name != "edge.example." || https.Hdr.Ttl != 10 || https.Target != "." || len(https.Value) != 1 {
		t.Fatalf("unexpected synthesized record: %s", https)
	}
}
func TestCloudflareECHSkipsIneligibleAndExistingRecords(t *testing.T) {
	cases := []struct {
		name, record string
		ips          []net.IP
	}{
		{"non-CF with CF hint", `example.com. 120 IN HTTPS 1 . ipv4hint=104.16.1.1`, []net.IP{net.ParseIP("192.0.2.1")}},
		{"mixed", `example.com. 120 IN HTTPS 1 .`, []net.IP{net.ParseIP("104.16.1.1"), net.ParseIP("192.0.2.1")}},
		{"existing ECH", `example.com. 120 IN HTTPS 1 . ech=AQID`, []net.IP{net.ParseIP("104.16.1.1")}},
		{"alias", `example.com. 120 IN HTTPS 0 edge.example.`, []net.IP{net.ParseIP("104.16.1.1")}},
		{"different target", `example.com. 120 IN HTTPS 1 edge.example.`, []net.IP{net.ParseIP("104.16.1.1")}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := &cloudflareTestServer{addresses: test.ips, answer: cfAnswer(t, test.record)}
			answer, err := cfResolver(t, server).QueryDomain(t.Context(), "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(answer.Records[0], server.answer.Records[0]) || server.seedCalls.Load() != 0 {
				t.Fatal("changed or fetched ECH for excluded record")
			}
		})
	}
}
func TestCloudflareECHSeedFailurePreservesAnswer(t *testing.T) {
	server := &cloudflareTestServer{addresses: []net.IP{net.ParseIP("104.16.1.1")}, answer: cfAnswer(t, `example.com. 120 IN HTTPS 1 . alpn="h2"`), seedFail: true}
	answer, err := cfResolver(t, server).QueryDomain(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(answer.Records[0], server.answer.Records[0]) {
		t.Fatal("failed seed changed record")
	}
}
func TestCloudflareECHCacheRefreshAndConcurrentWait(t *testing.T) {
	var cache cloudflareECHCache
	var calls atomic.Int32
	gate := make(chan struct{})
	query := func(ctx context.Context) (*dnsfeature.RecordResponse, error) {
		calls.Add(1)
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return cfAnswer(t, cloudflareECHName+". 30 IN HTTPS 1 . ech="+testCloudflareECH), nil
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			config, _ := cache.load(t.Context(), query)
			if len(config) == 0 {
				t.Error("missing config")
			}
		})
	}
	close(gate)
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate refresh: %d", calls.Load())
	}
	cache.mu.Lock()
	cache.expires = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	if config, _ := cache.load(t.Context(), query); len(config) == 0 {
		t.Fatal("refresh failed")
	}
	if calls.Load() != 2 {
		t.Fatal("expired ECH reused")
	}
}

func TestRecordStreamCancellationInterruptsStalledSeed(t *testing.T) {
	client, server := stdnet.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	written := make(chan struct{})
	go func() { _, _ = io.CopyN(io.Discard, server, 3); close(written) }()
	done := make(chan error, 1)
	go func() { _, err := exchangeRecordStream(ctx, client, []byte{0}); done <- err }()
	<-written
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled seed ignored cancellation")
	}
}

func TestCloudflareECHRemovesOnlyInvalidatedHTTPSRRSIG(t *testing.T) {
	server := &cloudflareTestServer{addresses: []net.IP{net.ParseIP("104.16.1.1")}, answer: cfAnswer(t, `example.com. 120 IN HTTPS 1 . alpn="h2"`)}
	for _, covered := range []uint16{mdns.TypeHTTPS, mdns.TypeCNAME} {
		sig := &mdns.RRSIG{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeRRSIG, Class: mdns.ClassINET, Ttl: 120}, TypeCovered: covered, Algorithm: 8, Labels: 2, OrigTtl: 120, SignerName: "example.com.", Signature: "AQID"}
		raw, err := packRecord(sig)
		if err != nil {
			t.Fatal(err)
		}
		server.answer.Records = append(server.answer.Records, raw)
	}
	answer, err := cfResolver(t, server).QueryDomain(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Records) != 2 {
		t.Fatal("wrong signature removal")
	}
	rr, _, _ := mdns.UnpackRR(answer.Records[1], 0)
	if sig, ok := rr.(*mdns.RRSIG); !ok || sig.TypeCovered != mdns.TypeCNAME {
		t.Fatal("unmodified RRset signature removed")
	}
	if len(server.answer.Records) != 3 {
		t.Fatal("mutated source")
	}
}

func TestCloudflareECHDoesNotSynthesizeNXDOMAIN(t *testing.T) {
	server := &cloudflareTestServer{addresses: []net.IP{net.ParseIP("104.16.1.1")}, answer: &dnsfeature.RecordResponse{RCode: mdns.RcodeNameError}}
	answer, err := cfResolver(t, server).QueryDomain(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if answer.RCode != mdns.RcodeNameError || len(answer.Records) != 0 || server.seedCalls.Load() != 0 {
		t.Fatal("synthesized over NXDOMAIN")
	}
}
