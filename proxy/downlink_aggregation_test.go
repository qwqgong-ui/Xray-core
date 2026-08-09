package proxy

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type aggregationTestConn struct {
	net.Conn
	enabled bool
}

func (c *aggregationTestConn) SetDownlinkWriteAggregation(enabled bool) {
	c.enabled = enabled
}

func TestSetDownlinkWriteAggregationUnwrapsStatsConnection(t *testing.T) {
	raw := new(aggregationTestConn)
	conn := &stat.CounterConnection{Connection: raw}
	if !SetDownlinkWriteAggregation(conn, true) {
		t.Fatal("supported connection was not detected")
	}
	if !raw.enabled {
		t.Fatal("aggregation was not enabled on the underlying connection")
	}
}

func TestSetDownlinkWriteAggregationIgnoresUnsupportedConnection(t *testing.T) {
	if SetDownlinkWriteAggregation(nil, true) {
		t.Fatal("nil connection unexpectedly reported aggregation support")
	}
}
