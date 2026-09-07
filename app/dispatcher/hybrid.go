package dispatcher

import (
	"context"
	"io"
	gonet "net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/hybrid"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

func isHybridDestination(dest net.Destination) bool {
	return dest.Address != nil && dest.Address.Family().IsDomain() && hybrid.IsReserved(dest.Address.Domain())
}
func (d *DefaultDispatcher) initHybrid(config *Config) error {
	d.hybridForward = make(map[string]bool)
	for _, tag := range config.HybridForwardOutbounds {
		d.hybridForward[tag] = true
	}
	d.hybridTrusted = make(map[string]bool)
	for _, tag := range config.HybridTrustedInbounds {
		d.hybridTrusted[tag] = true
	}
	if config.HybridListen == "" && config.HybridAdvertise == "" {
		return nil
	}
	listen, err := netip.ParseAddrPort(config.HybridListen)
	if err != nil || listen.Port() != 443 {
		return errors.New("hybrid: listen must be an IP on UDP 443")
	}
	advertised, err := netip.ParseAddrPort(config.HybridAdvertise)
	if err != nil || advertised.Port() != 443 || !hybrid.Public(advertised.Addr()) {
		return errors.New("hybrid: advertise must be a public IP on UDP 443")
	}
	d.hybrid = hybrid.NewServer(advertised)
	d.hybridListen = netip.AddrPortFrom(listen.Addr().Unmap(), listen.Port())
	d.hybridShared = config.HybridShareHysteria
	// Register at initialization: inbound transports may listen before Start.
	if d.hybridShared {
		return hybrid.RegisterShared(d.hybridListen, d.hybrid)
	}
	return nil
}
func (d *DefaultDispatcher) startHybrid() error {
	if d.hybrid == nil || d.hybridShared {
		return nil
	}
	network := "udp4"
	if d.hybridListen.Addr().Is6() {
		network = "udp6"
	}
	conn, err := gonet.ListenUDP(network, gonet.UDPAddrFromAddrPort(d.hybridListen))
	if err != nil {
		return err
	}
	if err = d.hybrid.Attach(conn); err != nil {
		conn.Close()
		return err
	}
	d.hybridSocket = conn
	go d.hybrid.ReadRaw(conn)
	return nil
}
func (d *DefaultDispatcher) closeHybrid() error {
	if d.hybrid == nil {
		return nil
	}
	hybrid.UnregisterShared(d.hybridListen, d.hybrid)
	d.hybrid.Close()
	if d.hybridSocket != nil {
		return d.hybridSocket.Close()
	}
	return nil
}
func (d *DefaultDispatcher) dispatchHybrid(ctx context.Context, dest net.Destination) *transport.Link {
	ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
	dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)
	go d.serveHybrid(ctx, dest, &transport.Link{Reader: ur, Writer: dw})
	return &transport.Link{Reader: dr, Writer: uw}
}
func (d *DefaultDispatcher) serveHybrid(ctx context.Context, dest net.Destination, link *transport.Link) {
	stream := &hybridStream{link: link, reader: &buf.BufferedReader{Reader: link.Reader}}
	defer stream.Close()
	defer func() { buf.ReleaseMulti(stream.reader.Buffer); stream.reader.Close() }()
	// Match the hostname at every port/network, and reject unsupported uses.
	// The reserved destination must never enter DNS, sniffing or outbound routing.
	if (d.hybrid == nil && len(d.hybridForward) == 0) || dest.Network != net.Network_TCP || dest.Port != 443 {
		return
	}
	var peer netip.Addr
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.Address != nil && inbound.Source.Address.Family().IsIP() {
		peer, _ = netip.AddrFromSlice(inbound.Source.Address.IP())
	}
	// Only setup has a deadline. An established stream is the lifetime anchor.
	timer := time.AfterFunc(10*time.Second, func() { stream.Close() })
	defer timer.Stop()
	request, err := hybrid.ReadRequest(stream)
	if err != nil {
		return
	}
	if request.Hops == 0 {
		if request.ClientIP.IsValid() {
			return
		}
		request.ClientIP = peer
	} else {
		inbound := session.InboundFromContext(ctx)
		if inbound == nil || !d.hybridTrusted[inbound.Tag] || !request.ClientIP.IsValid() {
			return
		}
	}
	host, port, err := gonet.SplitHostPort(request.Target)
	if err != nil || port != "443" || hybrid.IsReserved(host) {
		return
	}
	realTarget := net.UDPDestination(net.ParseAddress(host), 443)
	// Route exactly once, on the original application's UDP destination.
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: realTarget, OriginalTarget: realTarget}})
	content := &session.Content{Protocol: "quic"}
	if old := session.ContentFromContext(ctx); old != nil {
		content.Attributes = make(map[string]string)
		for k, v := range old.Attributes {
			content.Attributes[k] = v
		}
	}
	ctx = session.ContextWithContent(ctx, content)
	handler := d.hybridHandler(ctx)
	if handler == nil {
		return
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		log.Record(&log.AccessMessage{From: inbound.Source, To: realTarget, Status: log.AccessAccepted, Detour: inbound.Tag + " -> " + handler.Tag()})
	}
	if d.hybridForward[handler.Tag()] {
		if request.Hops >= 8 || !hybridForwardCapable(handler) {
			return
		}
		request.Hops++
		timer.Stop()
		d.forwardHybrid(ctx, handler, request, stream)
		return
	}
	if d.hybrid == nil {
		return
	}
	err = d.hybrid.Serve(ctx, stream, request.ClientIP, request.Target, func(ctx context.Context, address string) (hybrid.Target, netip.AddrPort, error) {
		target, resolved, err := d.dialHybrid(ctx, address, handler)
		if err == nil {
			timer.Stop()
		}
		return target, resolved, err
	})
	if err != nil && err != io.EOF {
		errors.LogDebugInner(ctx, err, "hybrid stream ended")
	}
}

type hybridStream struct {
	link   *transport.Link
	reader *buf.BufferedReader
	once   sync.Once
}

func (s *hybridStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *hybridStream) Write(p []byte) (int, error) {
	b := buf.NewWithSize(int32(len(p)))
	b.Write(p)
	if err := s.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (s *hybridStream) Close() error {
	s.once.Do(func() { common.Interrupt(s.link.Reader); common.Interrupt(s.link.Writer); common.Close(s.link.Writer) })
	return nil
}
func (d *DefaultDispatcher) dialHybrid(ctx context.Context, address string, handler outbound.Handler) (hybrid.Target, netip.AddrPort, error) {
	host, port, err := gonet.SplitHostPort(address)
	if err != nil || port != "443" || hybrid.IsReserved(host) {
		return nil, netip.AddrPort{}, errors.New("hybrid: invalid target")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, e := internet.LookupForIP(host, internet.DomainStrategy_USE_IP, nil)
		if e != nil {
			return nil, netip.AddrPort{}, e
		}
		for _, candidate := range ips {
			a, ok := netip.AddrFromSlice(candidate)
			if ok && hybrid.Public(a) {
				ip = a
				break
			}
		}
	}
	if !hybrid.Public(ip) {
		return nil, netip.AddrPort{}, errors.New("hybrid: target is not public")
	}
	ip = ip.Unmap()
	resolved := netip.AddrPortFrom(ip, 443)
	target := net.UDPDestination(net.IPAddress(ip.AsSlice()), 443)
	route := net.UDPDestination(net.ParseAddress(host), 443)
	ctx, cancel := context.WithCancel(ctx)
	// Never mutate the enclosing inbound stream's outbound/content objects.
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{RouteTarget: route}})
	content := &session.Content{Protocol: "quic"}
	if old := session.ContentFromContext(ctx); old != nil {
		content.Attributes = old.Attributes
	}
	ctx = session.ContextWithContent(ctx, content)
	ob := session.OutboundsFromContext(ctx)[0]
	ob.Target = target
	ob.OriginalTarget = route
	ob.Tag = handler.Tag()
	link, out := d.getLink(ctx)
	go handler.Dispatch(ctx, out)
	t := &hybridTarget{link: link, cancel: cancel, queue: make(chan []byte, 64), done: make(chan struct{})}
	go t.writeLoop()
	return t, resolved, nil
}

type hybridTarget struct {
	link    *transport.Link
	cancel  context.CancelFunc
	queue   chan []byte
	done    chan struct{}
	once    sync.Once
	pending [][]byte
}

func (t *hybridTarget) WritePacket(p []byte) error {
	select {
	case <-t.done:
		return io.ErrClosedPipe
	default:
	}
	select {
	case t.queue <- append([]byte(nil), p...):
	case <-t.done:
		return io.ErrClosedPipe
	default: /* bounded UDP queue; QUIC retransmits */
	}
	return nil
}
func (t *hybridTarget) writeLoop() {
	for {
		select {
		case <-t.done:
			return
		case p := <-t.queue:
			b := buf.NewWithSize(int32(len(p)))
			b.Write(p)
			if t.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}) != nil {
				t.Close()
				return
			}
		}
	}
}
func (t *hybridTarget) ReadPacket() ([]byte, error) {
	for len(t.pending) == 0 {
		mb, err := t.link.Reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return nil, err
		}
		for _, b := range mb {
			t.pending = append(t.pending, append([]byte(nil), b.Bytes()...))
		}
		buf.ReleaseMulti(mb)
	}
	p := t.pending[0]
	t.pending[0] = nil
	t.pending = t.pending[1:]
	return p, nil
}
func (t *hybridTarget) Close() error {
	t.once.Do(func() {
		close(t.done)
		t.cancel()
		common.Interrupt(t.link.Reader)
		common.Interrupt(t.link.Writer)
		common.Close(t.link.Writer)
	})
	return nil
}

func (d *DefaultDispatcher) hybridHandler(ctx context.Context) outbound.Handler {
	if tag := session.GetForcedOutboundTagFromContext(ctx); tag != "" {
		return d.ohm.GetHandler(tag)
	}
	if d.router != nil {
		if route, err := d.router.PickRoute(routing_session.AsRoutingContext(ctx)); err == nil {
			return d.ohm.GetHandler(route.GetOutboundTag())
		}
	}
	return d.ohm.GetDefaultHandler()
}
func (d *DefaultDispatcher) forwardHybrid(ctx context.Context, h outbound.Handler, request hybrid.Request, up *hybridStream) {
	// Calling the selected handler directly prevents marker-domain re-routing.
	ob := session.OutboundsFromContext(ctx)[0]
	ob.RouteTarget = ob.Target
	ob.Target = net.TCPDestination(net.DomainAddress("hybrid-quic.invalid"), 443)
	ob.Tag = h.Tag()
	incoming, outgoing := d.getLink(ctx)
	next := &hybridStream{link: incoming, reader: &buf.BufferedReader{Reader: incoming.Reader}}
	defer next.Close()
	defer func() { buf.ReleaseMulti(next.reader.Buffer); next.reader.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { up.Close(); next.Close() })
	defer stop()
	go h.Dispatch(ctx, outgoing)
	timer := time.AfterFunc(10*time.Second, func() { next.Close(); up.Close() })
	if err := hybrid.WriteRequest(next, request); err != nil {
		timer.Stop()
		return
	}
	// Wait for the terminal's reply before removing the setup deadline.
	var status [1]byte
	if _, err := io.ReadFull(next, status[:]); err != nil {
		timer.Stop()
		return
	}
	if hybrid.WriteAll(up, status[:]) != nil {
		timer.Stop()
		return
	}
	timer.Stop()
	done := make(chan struct{})
	go func() { io.Copy(next, up); next.Close(); up.Close(); close(done) }()
	io.Copy(up, next)
	next.Close()
	up.Close()
	<-done
}

// A configured forward tag must carry domains in its protocol header. In
// particular, never send the internal marker to freedom or an IP-only tunnel.
func hybridForwardCapable(h outbound.Handler) bool {
	settings := h.ProxySettings()
	if settings == nil {
		return false
	}
	switch settings.Type {
	case "xray.proxy.vless.outbound.Config", "xray.proxy.vmess.outbound.Config",
		"xray.proxy.trojan.ClientConfig", "xray.proxy.shadowsocks.ClientConfig",
		"xray.proxy.shadowsocks_2022.ClientConfig", "xray.proxy.socks.ClientConfig",
		"xray.proxy.http.ClientConfig", "xray.proxy.hysteria.ClientConfig":
		return true
	default:
		return false
	}
}
