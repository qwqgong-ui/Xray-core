package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/google/go-cmp/cmp"
	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

func newTestQUICNameServer(t *testing.T) (*QUICNameServer, *atomic.Uint32) {
	t.Helper()
	generated, err := cert.Generate(nil, cert.DNSNames("doq.test"))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := generated.ToPEM()
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		NextProtos:   []string{NextProtoDQ},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	queries := new(atomic.Uint32)
	serverErrors := make(chan error, 1)
	done := make(chan struct{})
	var connection *quic.Conn
	t.Cleanup(func() {
		cancel()
		if connection != nil {
			_ = connection.CloseWithError(0, "")
		}
		_ = listener.Close()
		<-done
		select {
		case err := <-serverErrors:
			t.Error(err)
		default:
		}
	})
	go func() {
		defer close(done)
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				serverErrors <- err
			}
			return
		}
		defer conn.CloseWithError(0, "")
		for {
			stream, err := conn.AcceptStream(ctx)
			if err == nil {
				err = serveTestQUICQuery(stream, queries)
			}
			if err != nil {
				if ctx.Err() == nil {
					serverErrors <- err
				}
				return
			}
		}
	}()
	// Trust only this fixture's certificate, without changing process-wide roots
	// or adding a test-only TLS option to the production resolver.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to load fixture certificate")
	}
	connection, err = quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		RootCAs: roots, ServerName: "doq.test", NextProtos: []string{NextProtoDQ},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("quic://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewQUICNameServer(u, false, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.connection = connection
	return s, queries
}

func serveTestQUICQuery(stream *quic.Stream, queries *atomic.Uint32) error {
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	wire, err := io.ReadAll(stream)
	if err != nil {
		return err
	}
	if len(wire) < 2 || int(binary.BigEndian.Uint16(wire)) != len(wire)-2 {
		return fmt.Errorf("invalid DoQ length prefix: %d bytes", len(wire))
	}
	request := new(mdns.Msg)
	if err := request.Unpack(wire[2:]); err != nil {
		return err
	}
	if request.Id != 0 || len(request.Question) != 1 || request.Question[0].Name != "example.test." {
		return fmt.Errorf("invalid DoQ request: %v", request)
	}
	queries.Add(1)
	question := request.Question[0]
	response := new(mdns.Msg)
	response.SetReply(request)
	header := mdns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: mdns.ClassINET, Ttl: 120}
	switch question.Qtype {
	case mdns.TypeA:
		response.Answer = []mdns.RR{&mdns.A{Hdr: header, A: net.ParseIP("192.0.2.1")}}
	case mdns.TypeAAAA:
		response.Answer = []mdns.RR{&mdns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::1")}}
	default:
		return fmt.Errorf("unexpected query type: %d", question.Qtype)
	}
	wire, err = response.Pack()
	if err != nil {
		return err
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
	if _, err := stream.Write(append(framed, wire...)); err != nil {
		return err
	}
	return stream.Close()
}

func TestQUICNameServer(t *testing.T) {
	s, queries := newTestQUICNameServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, _, err := s.QueryIP(ctx, "example.test", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	want := []net.IP{net.ParseIP("192.0.2.1").To4(), net.ParseIP("2001:db8::1")}
	if diff := cmp.Diff(want, ips); diff != "" {
		t.Fatal(diff)
	}
	if got := queries.Load(); got != 2 {
		t.Fatalf("got %d queries, want one A and one AAAA", got)
	}
	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips2, _, err := s.QueryIP(ctx2, "example.test", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if r := cmp.Diff(ips2, ips); r != "" {
		t.Fatal(r)
	}
	if got := queries.Load(); got != 2 {
		t.Fatalf("cache hit sent additional queries: got %d, want 2", got)
	}
}

func TestQUICNameServerWithIPv4Override(t *testing.T) {
	s, queries := newTestQUICNameServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, _, err := s.QueryIP(ctx, "example.test", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	want := []net.IP{net.ParseIP("192.0.2.1").To4()}
	if diff := cmp.Diff(want, ips); diff != "" {
		t.Fatal(diff)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("got %d queries, want only one A query", got)
	}
}

func TestQUICNameServerWithIPv6Override(t *testing.T) {
	s, queries := newTestQUICNameServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, _, err := s.QueryIP(ctx, "example.test", dns_feature.IPOption{
		IPv4Enable: false,
		IPv6Enable: true,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	want := []net.IP{net.ParseIP("2001:db8::1")}
	if diff := cmp.Diff(want, ips); diff != "" {
		t.Fatal(diff)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("got %d queries, want only one AAAA query", got)
	}
}

func TestQUICNameServerPublic(t *testing.T) {
	if os.Getenv("XRAY_TEST_DNS_QUIC_PUBLIC") != "1" {
		t.Skip("set XRAY_TEST_DNS_QUIC_PUBLIC=1 to check the public DoQ endpoint")
	}
	u, err := url.Parse("quic://dns.adguard-dns.com")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewQUICNameServer(u, false, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		t.Fatalf("public DoQ lookup failed: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("public DoQ lookup returned no addresses")
	}
}
