package hysteria

import (
	"context"
	"math/rand"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
	URLHost                   = "hysteria"
	URLPath                   = "/auth"
	RequestHeaderAuth         = "Hysteria-Auth"
	ResponseHeaderUDPEnabled  = "Hysteria-UDP"
	CommonHeaderCCRX          = "Hysteria-CC-RX"
	CommonHeaderPadding       = "Hysteria-Padding"
	StatusAuthOK              = 233
	FrameTypeTCPRequest       = 0x401
	// MaxDatagramFrameSize is the max_datagram_frame_size we advertise, the
	// value we assume for peers that omit the parameter, and the size of the
	// buffer UDPReader.ReadFrom reads into. Official hysteria v2.8.2 pins it at
	// 1200, which caps every relayed UDP datagram at 1197 bytes however large
	// the path MTU turns out to be: on a 1441-byte path each full-size inner
	// datagram then splits in two, doubling the packet rate for the same bytes.
	// 1452 is the largest QUIC packet quic-go will ever build, so a DATAGRAM
	// frame cannot exceed it either; advertising it hands the bound back to
	// path MTU discovery instead of a constant.
	//
	// Raising it is one-way compatible for what we receive: a peer only sends
	// larger datagrams once we advertise that we accept them. What we send is
	// bounded by the peer's own advertised value, except for peers that omit it
	// and fall to AssumePeerMaxDatagramFrameSize below — Xray clients do, from
	// the OmitMaxDatagramFrameSize date in dialer.go. Those peers must carry
	// this constant too, or they will silently truncate us in ReadFrom.
	MaxDatagramFrameSize = 1452
	udpMessageChanSize   = 1024
	idleCleanupInterval  = 1 * time.Second
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type padding struct {
	Min int
	Max int
}

func (p padding) String() string {
	n := p.Min + rand.Intn(p.Max-p.Min)
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = paddingChars[rand.Intn(len(paddingChars))]
	}
	return string(bs)
}

var (
	AuthRequestPadding  = padding{Min: 256, Max: 2048}
	AuthResponsePadding = padding{Min: 256, Max: 2048}
	TcpRequestPadding   = padding{Min: 64, Max: 512}
	TcpResponsePadding  = padding{Min: 128, Max: 1024}
)

type datagramKey struct{}

func ContextWithDatagram(ctx context.Context, v bool) context.Context {
	return context.WithValue(ctx, datagramKey{}, v)
}

func DatagramFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(datagramKey{}).(bool)
	return v
}

type validatorKey struct{}

func ContextWithValidator(ctx context.Context, v *account.Validator) context.Context {
	return context.WithValue(ctx, validatorKey{}, v)
}

func ValidatorFromContext(ctx context.Context) *account.Validator {
	v, _ := ctx.Value(validatorKey{}).(*account.Validator)
	return v
}

type status int

const (
	StatusNull status = iota
	StatusActive
	StatusInactive
)

const protocolName = "hysteria"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return &Config{
			UdpIdleTimeout: 60,
		}
	}))
}
