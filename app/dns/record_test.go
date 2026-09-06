package dns

import (
	"context"
	"errors"
	"testing"

	dns_feature "github.com/xtls/xray-core/features/dns"

	mdns "github.com/miekg/dns"
)

// Every name server type must be able to answer record queries, otherwise a
// deployment silently loses the feature depending on which transport its DNS
// happens to use. LocalNameServer is the deliberate exception: it wraps Go's
// resolver, which cannot ask for an arbitrary record type at all.
func TestNameServersImplementRecordServer(t *testing.T) {
	for name, server := range map[string]any{
		"DoH":  (*DoHNameServer)(nil),
		"TCP":  (*TCPNameServer)(nil),
		"QUIC": (*QUICNameServer)(nil),
		"UDP":  (*ClassicNameServer)(nil),
	} {
		if _, ok := server.(RecordServer); !ok {
			t.Fatalf("%s name server cannot answer record queries", name)
		}
	}
	if _, ok := any((*LocalNameServer)(nil)).(RecordServer); ok {
		t.Fatal("localhost cannot answer record queries; claiming otherwise hides the fallback")
	}
}

// The whole answer section is carried through, in order, including a CNAME
// chain: the caller asked this server what it sees, not for a filtered view.
func TestQueryRecordCarriesTheAnswerSection(t *testing.T) {
	cname, err := mdns.NewRR("example.com. 300 IN CNAME edge.cdn.example.")
	if err != nil {
		t.Fatalf("cname: %v", err)
	}
	https, err := mdns.NewRR(`edge.cdn.example. 60 IN HTTPS 1 . alpn="h3,h2" ipv4hint=192.0.2.1`)
	if err != nil {
		t.Fatalf("https: %v", err)
	}

	exchange := func(_ context.Context, query []byte) ([]byte, error) {
		request := new(mdns.Msg)
		if err := request.Unpack(query); err != nil {
			return nil, err
		}
		if len(request.Question) != 1 || request.Question[0].Name != "example.com." {
			return nil, errors.New("unexpected question")
		}
		if request.Question[0].Qtype != mdns.TypeHTTPS {
			return nil, errors.New("unexpected type")
		}
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{cname, https}
		return response.Pack()
	}

	answer, err := queryRecord(context.Background(), exchange, "example.com", mdns.TypeHTTPS)
	if err != nil {
		t.Fatalf("queryRecord: %v", err)
	}
	if answer.RCode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %s", mdns.RcodeToString[answer.RCode])
	}
	if len(answer.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(answer.Records))
	}

	// Each record must stand on its own: a name inside it cannot be a
	// compression pointer, because it is about to be put in another message.
	want := []string{cname.String(), https.String()}
	for i, raw := range answer.Records {
		rr, consumed, err := mdns.UnpackRR(raw, 0)
		if err != nil {
			t.Fatalf("record %d does not stand alone: %v", i, err)
		}
		if consumed != len(raw) {
			t.Fatalf("record %d has %d trailing bytes", i, len(raw)-consumed)
		}
		if rr.String() != want[i] {
			t.Fatalf("record %d = %q, want %q", i, rr.String(), want[i])
		}
	}
}

// An rcode is an answer, not a failure: the caller relays it and must not be
// told the server was unreachable.
func TestQueryRecordRelaysRcode(t *testing.T) {
	exchange := func(_ context.Context, query []byte) ([]byte, error) {
		request := new(mdns.Msg)
		if err := request.Unpack(query); err != nil {
			return nil, err
		}
		response := new(mdns.Msg)
		response.SetRcode(request, mdns.RcodeNameError)
		return response.Pack()
	}

	answer, err := queryRecord(context.Background(), exchange, "nope.example", mdns.TypeSVCB)
	if err != nil {
		t.Fatalf("queryRecord: %v", err)
	}
	if answer.RCode != mdns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", mdns.RcodeToString[answer.RCode])
	}
	if len(answer.Records) != 0 {
		t.Fatalf("records = %d, want none", len(answer.Records))
	}
}

// A reply that does not belong to this query must not be accepted as one.
func TestQueryRecordRejectsAMismatchedReply(t *testing.T) {
	for name, exchange := range map[string]func(context.Context, []byte) ([]byte, error){
		"not a response": func(_ context.Context, query []byte) ([]byte, error) {
			return query, nil
		},
		"wrong id": func(_ context.Context, query []byte) ([]byte, error) {
			request := new(mdns.Msg)
			if err := request.Unpack(query); err != nil {
				return nil, err
			}
			response := new(mdns.Msg)
			response.SetReply(request)
			response.Id = request.Id ^ 0xffff
			return response.Pack()
		},
	} {
		if _, err := queryRecord(context.Background(), exchange, "example.com", mdns.TypeA); err == nil {
			t.Fatalf("%s: must be rejected", name)
		}
	}
}

func TestTrimTrailingDot(t *testing.T) {
	for input, want := range map[string]string{
		"example.com.":  "example.com",
		"example.com":   "example.com",
		"example.com..": "example.com",
		".":             "",
		"":              "",
	} {
		if got := trimTrailingDot(input); got != want {
			t.Fatalf("trimTrailingDot(%q) = %q, want %q", input, got, want)
		}
	}
}

var _ dns_feature.RecordClient = (*DNS)(nil)
