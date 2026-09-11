package freedom

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type cachedDomainClient struct {
	dns.Client
	calls int
}

func (c *cachedDomainClient) LookupDomainCache(string, dns.IPOption) ([]net.IP, uint32, bool) {
	c.calls++
	return []net.IP{net.ParseIP("192.0.2.1")}, 60, true
}

type captureDomainDialer struct {
	internet.Dialer
	destinations []net.Destination
}

func (d *captureDomainDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func (d *captureDomainDialer) Dial(_ context.Context, dest net.Destination) (stat.Connection, error) {
	d.destinations = append(d.destinations, dest)
	return nil, errors.New("stop after recording destination")
}

func TestProcessDomainCacheWithDialerStrategy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		dialerProxy bool
		strategy    internet.DomainStrategy
		wantAddress string
		wantCache   bool
	}{
		{name: "asis reuses bundle", wantAddress: "192.0.2.1", wantCache: true},
		{name: "dialer proxy keeps domain", dialerProxy: true, wantAddress: "cached.invalid"},
		{name: "explicit strategy stays with dialer", strategy: internet.DomainStrategy_USE_IP, wantAddress: "cached.invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &cachedDomainClient{}
			internet.InitSystemDialer(client, nil)
			defer internet.InitSystemDialer(nil, nil)
			target := net.TCPDestination(net.DomainAddress("cached.invalid"), 443)
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
			h := &Handler{config: &Config{}, usesDialerProxy: tc.dialerProxy, resolveStrategy: tc.strategy}
			dialer := &captureDomainDialer{}
			if err := h.Process(ctx, &transport.Link{}, dialer); err == nil {
				t.Fatal("expected the recording dialer to stop processing")
			}
			if len(dialer.destinations) == 0 {
				t.Fatal("no dial attempt")
			}
			for _, dest := range dialer.destinations {
				if dest.Address.String() != tc.wantAddress || dest.Port != target.Port || dest.Network != target.Network {
					t.Errorf("dial destination = %v, want %s:443 over TCP", dest, tc.wantAddress)
				}
			}
			if (client.calls > 0) != tc.wantCache {
				t.Errorf("cache lookups = %d, want cache used = %v", client.calls, tc.wantCache)
			}
		})
	}
}

func TestProcessCachedDomainStillAppliesFinalRules(t *testing.T) {
	client := &cachedDomainClient{}
	internet.InitSystemDialer(client, nil)
	defer internet.InitSystemDialer(nil, nil)
	target := net.TCPDestination(net.DomainAddress("cached.invalid"), 443)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	h := &Handler{config: &Config{}, finalRules: []*FinalRule{defaultBlockAllRule}}
	dialer := &captureDomainDialer{}
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: buf.Discard}
	if err := h.Process(ctx, link, dialer); err != nil {
		t.Fatal(err)
	}
	if client.calls == 0 || len(dialer.destinations) != 0 {
		t.Fatalf("blocked cached destination: cache lookups = %d, dial attempts = %d", client.calls, len(dialer.destinations))
	}
}
