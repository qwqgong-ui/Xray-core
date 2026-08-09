package inbound

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func TestShouldAggregateDownlink(t *testing.T) {
	tests := []struct {
		name    string
		request *protocol.RequestHeader
		want    bool
	}{
		{name: "tcp 443", request: &protocol.RequestHeader{Command: protocol.RequestCommandTCP, Port: net.Port(443)}, want: true},
		{name: "tcp 80", request: &protocol.RequestHeader{Command: protocol.RequestCommandTCP, Port: net.Port(80)}},
		{name: "udp 443", request: &protocol.RequestHeader{Command: protocol.RequestCommandUDP, Port: net.Port(443)}},
		{name: "xudp mux", request: &protocol.RequestHeader{Command: protocol.RequestCommandMux, Port: net.Port(443)}},
		{name: "nil request"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldAggregateDownlink(test.request); got != test.want {
				t.Fatalf("shouldAggregateDownlink() = %v, want %v", got, test.want)
			}
		})
	}
}
