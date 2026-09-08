package dns

import (
	"context"
	"github.com/xtls/xray-core/common/net"

	"github.com/xtls/xray-core/common/errors"
)

// RawRecord is one resource record in wire format -- owner name, type, class,
// TTL, RDLENGTH and RDATA -- packed without name compression, so it stands on
// its own and can be placed into any message. Keeping it opaque is what lets
// this package describe record answers without depending on a DNS library, and
// packing it uncompressed is what makes that safe: a compression pointer only
// means something inside the message it came from.
type RawRecord []byte

// RecordResponse is the answer to one record query.
type RecordResponse struct {
	// RCode is the response code of the upstream answer.
	RCode int
	// Records are the answer section's resource records, in order. A CNAME
	// chain is preserved, so the caller sees the answer exactly as it was
	// given rather than a filtered view of it.
	Records []RawRecord
	// Additional holds real address records in a complete domain bundle.
	Additional []RawRecord
}

// RecordClient is an optional capability of a Client: resolving one record
// type rather than only addresses. Reach it with a type assertion on Client;
// an implementation that only resolves addresses simply does not satisfy it.
//
// It exists so a component that must answer a DNS question on a client's
// behalf can use this instance's own DNS stack -- and get back records, not
// wire bytes. How the answer was fetched, and over which transport, stays
// inside the DNS implementation where it belongs.
//
// xray:api:beta
type RecordClient interface {
	// QueryRecord resolves one record type for one domain. domain carries no
	// trailing dot. qtype is a DNS TYPE value.
	QueryRecord(ctx context.Context, domain string, qtype uint16) (*RecordResponse, error)
}

// ErrRecordQueryUnsupported is returned when the configured DNS cannot answer
// record queries.
var ErrRecordQueryUnsupported = errors.New("configured DNS cannot answer record queries")

// DomainClient resolves addresses and HTTPS metadata as one expiring result.
type DomainClient interface {
	QueryDomain(context.Context, string) (*RecordResponse, error)
}

// DomainCacheClient exposes only already resolved, unexpired addresses.
type DomainCacheClient interface {
	LookupDomainCache(string, IPOption) ([]net.IP, uint32, bool)
}
