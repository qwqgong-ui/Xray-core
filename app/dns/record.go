package dns

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"

	mdns "github.com/miekg/dns"
)

// recordQueryTimeout bounds one record query across all name servers.
const recordQueryTimeout = 5 * time.Second

// RecordServer is implemented by name servers that can answer a query for one
// record type. It is an optional capability reached through a type assertion,
// so the Server interface and the whole QueryIP path are untouched.
type RecordServer interface {
	QueryRecord(ctx context.Context, domain string, qtype uint16) (*dns_feature.RecordResponse, error)
}

// QueryRecord implements dns.RecordClient.
//
// Server selection reuses sortClients, so a record query follows exactly the
// same domain rules, ordering and fallback as the equivalent address query
// would have. Name servers that cannot answer record queries are skipped
// rather than failing the query.
func (s *DNS) QueryRecord(ctx context.Context, domain string, qtype uint16) (*dns_feature.RecordResponse, error) {
	domain = trimTrailingDot(domain)
	if domain == "" {
		return nil, errors.New("record query has an empty domain")
	}

	if qtype == mdns.TypeHTTPS {
		if answer := s.domains.get(domain); answer != nil {
			return answer, nil
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, recordQueryTimeout)
		defer cancel()
	}
	// Mark the query so a name server's own dial does not recurse back into
	// DNS resolution, matching what the address path sets up for itself.
	ctx = session.ContextWithContent(ctx, &session.Content{
		Protocol:       "dns",
		SkipDNSResolve: true,
	})

	var (
		errs      []error
		anyServer bool
	)
	for _, client := range s.sortClients(domain) {
		server, ok := client.server.(RecordServer)
		if !ok {
			continue
		}
		anyServer = true
		// A resolver lookup is an internal connection. Inheriting the user's
		// inbound Conn/CanSpliceCopy can splice upstream DNS bytes directly
		// into the tunnel, bypassing its response framing and message ID.
		queryCtx := session.ContextWithInbound(ctx, &session.Inbound{Tag: client.tag})
		queryCtx = session.ContextWithOutbounds(queryCtx, nil)
		response, err := server.QueryRecord(queryCtx, domain, qtype)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return response, nil
	}
	if !anyServer {
		return nil, dns_feature.ErrRecordQueryUnsupported
	}
	return nil, errors.Combine(errs...)
}

// queryRecord builds the question, hands the wire bytes to one name server's
// own transport, and turns the reply back into records. Every name server
// shares it, so how a query is framed and how an answer is read is decided
// once rather than per transport.
func queryRecord(ctx context.Context, exchange func(context.Context, []byte) ([]byte, error), domain string, qtype uint16) (*dns_feature.RecordResponse, error) {
	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(domain), qtype)
	request.RecursionDesired = true

	query, err := request.Pack()
	if err != nil {
		return nil, errors.New("failed to build record query").Base(err)
	}

	wire, err := exchange(ctx, query)
	if err != nil {
		return nil, err
	}

	response := new(mdns.Msg)
	if err := response.Unpack(wire); err != nil {
		return nil, errors.New("failed to parse record response").Base(err)
	}
	if !response.Response || response.Id != request.Id {
		return nil, errors.New("record response does not answer the query")
	}

	answer := &dns_feature.RecordResponse{RCode: response.Rcode}
	for _, rr := range response.Answer {
		raw, err := packRecord(rr)
		if err != nil {
			errors.LogInfoInner(ctx, err, "record response: dropping an answer that cannot be re-packed")
			continue
		}
		answer.Records = append(answer.Records, raw)
	}
	return answer, nil
}

// packRecord serialises one resource record on its own, without compression:
// a compression pointer only means something inside the message it came from,
// and this record is about to be placed into a different one.
func packRecord(rr mdns.RR) (dns_feature.RawRecord, error) {
	buf := make([]byte, mdns.Len(rr))
	n, err := mdns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func trimTrailingDot(domain string) string {
	for len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	return domain
}
