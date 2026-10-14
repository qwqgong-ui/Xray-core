package dns

import (
	"bytes"
	"context"
	"errors"
	"io"
	stdnet "net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	dnsfeature "github.com/xtls/xray-core/features/dns"
)

type echPassthroughServer struct {
	bundleTestServer
	answer  *dnsfeature.RecordResponse
	queries []string
}

func (*echPassthroughServer) QueryIP(context.Context, string, dnsfeature.IPOption) ([]net.IP, uint32, error) {
	return []net.IP{net.ParseIP("104.16.1.1"), net.ParseIP("2606:4700::1")}, 120, nil
}

func (s *echPassthroughServer) QueryRecord(_ context.Context, domain string, _ uint16) (*dnsfeature.RecordResponse, error) {
	s.queries = append(s.queries, domain)
	return s.answer, nil
}

func TestDomainBundlePreservesUpstreamECH(t *testing.T) {
	for _, record := range []string{
		"",
		`example.com. 120 IN CNAME edge.example.`,
		`example.com. 120 IN HTTPS 1 . alpn="h2"`,
		`example.com. 120 IN HTTPS 1 . ech=AQID`,
	} {
		t.Run(record, func(t *testing.T) {
			answer := &dnsfeature.RecordResponse{}
			if record != "" {
				rr, err := mdns.NewRR(record)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := packRecord(rr)
				if err != nil {
					t.Fatal(err)
				}
				answer.Records = []dnsfeature.RawRecord{raw}
			}
			server := &echPassthroughServer{answer: answer}
			resolver := newBundleTestDNS(t, &server.bundleTestServer)
			resolver.clients[0].server = server
			got, err := resolver.QueryDomain(t.Context(), "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if len(server.queries) != 1 || server.queries[0] != "example.com" {
				t.Fatalf("unexpected DNS queries: %v", server.queries)
			}
			if len(got.Records) != len(answer.Records) {
				t.Fatal("synthesized service record")
			}
			for i, raw := range got.Records {
				if !bytes.Equal(raw, answer.Records[i]) {
					t.Fatal("changed upstream service metadata")
				}
			}
		})
	}
}

func TestRecordStreamCancellationInterruptsStalledQuery(t *testing.T) {
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
		t.Fatal("stalled query ignored cancellation")
	}
}
