package hysteria

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/net/ipv4"
)

type fqTestPacketConn struct {
	*stdnet.UDPConn
	batch *ipv4.PacketConn
	delay time.Duration
}

func (c *fqTestPacketConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	n, err := c.batch.ReadBatch(messages, flags)
	if n > 0 {
		time.Sleep(c.delay)
	}
	return n, err
}

func (c *fqTestPacketConn) WriteBatch(messages []ipv4.Message, flags int) (int, error) {
	return c.batch.WriteBatch(messages, flags)
}

// Dynamic window checks can legitimately leave the connection in software
// pacing after its final write. Observe activation over the entire transfer.
func observeKernelPacing(parent context.Context, conn *quic.Conn) func() bool {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan bool, 1)
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		seen := conn.KernelPacingEnabled()
		for {
			select {
			case <-ticker.C:
				seen = seen || conn.KernelPacingEnabled()
			case <-ctx.Done():
				done <- seen || conn.KernelPacingEnabled()
				return
			}
		}
	}()
	return func() bool { cancel(); return <-done }
}

// Run the server and client roles in isolated veth namespaces with fq. This
// exercises HY2 HTTP/3 authentication, controller replacement, TCP streams,
// bidirectional ACKs, PMTU and two clients sharing the server UDP socket.
func TestBBRFQEndToEnd(t *testing.T) {
	role, addr := os.Getenv("XRAY_HY2_FQ_ROLE"), os.Getenv("XRAY_HY2_FQ_ADDR")
	if role == "" || addr == "" {
		t.Skip("requires paired isolated network namespaces")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("hy2-bbr-fq-roundtrip-"), 200_000)
	params := &internet.QuicParams{Congestion: "bbr", BbrProfile: "standard", DisableChromeParrot: true}
	if role == "server" {
		generated, _ := cert.MustGenerate(nil)
		key := common.Must2(x509.ParsePKCS8PrivateKey(generated.PrivateKey))
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{generated.Certificate}, PrivateKey: key}}, NextProtos: []string{"h3"}}
		udp := common.Must2(stdnet.ListenPacket("udp4", addr))
		defer udp.Close()
		packetConn := udp
		if delay, _ := strconv.Atoi(os.Getenv("XRAY_HY2_FQ_DELAY_MS")); delay > 0 {
			base := udp.(*stdnet.UDPConn)
			packetConn = &fqTestPacketConn{UDPConn: base, batch: ipv4.NewPacketConn(base), delay: time.Duration(delay) * time.Millisecond}
		}
		tr := &quic.Transport{Conn: packetConn}
		defer tr.Close()
		ql := common.Must2(tr.Listen(tlsConfig, &quic.Config{EnableDatagrams: true, DisablePathManager: true}))
		defer ql.Close()
		done := make(chan error, 2)
		listener := &Listener{config: &Config{Auth: "fq-test"}, quicParams: params}
		var observations []func() bool
		listener.addConn = func(conn stat.Connection) {
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				buf := make([]byte, len(payload))
				_, err := io.ReadFull(conn, buf)
				if err == nil && !bytes.Equal(buf, payload) {
					err = fmt.Errorf("upload contents differ")
				}
				if err == nil {
					_, err = conn.Write(buf)
				}
				done <- err
			}()
		}
		for range 2 {
			conn, err := ql.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			observations = append(observations, observeKernelPacing(ctx, conn))
			go listener.handleClient(conn)
		}
		for range 2 {
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		for _, observed := range observations {
			seen := observed()
			if expected := os.Getenv("QUIC_KERNEL_PACING_EXPECT_FQ"); expected != "" && seen != (expected != "0") {
				t.Fatalf("server EDT observed=%t, expected=%s", seen, expected)
			}
		}
		// Wait for peer closure so final stream data and ACKs have been received.
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
		return
	}
	if role != "client" {
		t.Fatalf("unknown role %q", role)
	}
	remote := common.Must2(net.ResolveUDPAddr("udp4", addr))
	done := make(chan error, 2)
	start := time.Now()
	for range 2 {
		go func() {
			c := &client{lock: make(chan struct{}, 1), dest: net.UDPDestination(net.IPAddress(remote.IP), net.Port(remote.Port)), config: &Config{Auth: "fq-test"}, tlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, quicParams: params}
			conn, err := c.tcp(ctx)
			if err != nil {
				done <- err
				return
			}
			defer c.close()
			defer conn.Close()
			observed := observeKernelPacing(ctx, c.conn)
			conn.SetDeadline(time.Now().Add(20 * time.Second))
			_, err = conn.Write(payload)
			if err != nil {
				err = fmt.Errorf("upload write: %w", err)
			}
			if err == nil {
				buf := make([]byte, len(payload))
				_, err = io.ReadFull(conn, buf)
				if err != nil {
					err = fmt.Errorf("download read: %w", err)
				}
				if err == nil && !bytes.Equal(buf, payload) {
					err = fmt.Errorf("download contents differ")
				}
			}
			seen := observed()
			if expected := os.Getenv("QUIC_KERNEL_PACING_EXPECT_FQ"); err == nil && expected != "" && seen != (expected != "0") {
				err = fmt.Errorf("client EDT observed=%t, expected=%s", seen, expected)
			}
			done <- err
		}()
	}
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	t.Logf("two HY2 clients: %d bytes each direction per client, round trip %v", len(payload), time.Since(start))
}
