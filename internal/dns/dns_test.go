package dns

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"open-go-dig/internal/dnstest"
	"open-go-dig/internal/model"
)

// silenceTimeout bounds the tests in which a resolver never answers.
const silenceTimeout = 200 * time.Millisecond

func newClient(addrs ...string) *Client {
	c := NewClient(addrs, 1, 8)
	c.Timeout = silenceTimeout
	return c
}

// answering replies to each type with the given zone-file records.
func answering(t *testing.T, byType map[uint16][]string) dnstest.Handler {
	t.Helper()
	parsed := map[uint16][]mdns.RR{}
	for typ, records := range byType {
		for _, r := range records {
			parsed[typ] = append(parsed[typ], dnstest.RR(t, r))
		}
	}
	return func(q dnstest.Query, reply *mdns.Msg) bool {
		reply.Answer = parsed[q.Type]
		return true
	}
}

func groupTypes(groups []model.RecordGroup) []string {
	out := []string{}
	for _, g := range groups {
		out = append(out, g.Type)
	}
	return out
}

func lookup(t *testing.T, c *Client, types ...uint16) *model.DNSResult {
	t.Helper()
	res, err := c.Lookup(context.Background(), "example.com", types, false, "")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return res
}

func TestLookupGroupsRecordsByType(t *testing.T) {
	srv := dnstest.New(t, answering(t, map[uint16][]string{
		mdns.TypeA:  {"example.com. 300 IN A 192.0.2.1", "example.com. 300 IN A 192.0.2.2"},
		mdns.TypeMX: {"example.com. 300 IN MX 10 mail.example.com."},
	}))
	res := lookup(t, newClient(srv.Addr), mdns.TypeA, mdns.TypeMX)

	if res.Query != "example.com" || res.QueryType != model.QueryForward {
		t.Errorf("Query = %q (%s)", res.Query, res.QueryType)
	}
	if res.Server != srv.Addr || res.Rcode != "NOERROR" {
		t.Errorf("Server = %q, Rcode = %q", res.Server, res.Rcode)
	}
	if got := groupTypes(res.Records); !reflect.DeepEqual(got, []string{"A", "MX"}) {
		t.Fatalf("groups = %v", got)
	}
	if len(res.Records[0].Records) != 2 {
		t.Errorf("A records = %+v", res.Records[0].Records)
	}
	if mx := res.Records[1].Records[0]; mx.Value != "mail.example.com." || mx.Priority != 10 {
		t.Errorf("MX record = %+v", mx)
	}
	if !strings.Contains(res.RawResponse, ";; MX records for example.com. (from "+srv.Addr+")") ||
		!strings.Contains(res.RawResponse, "192.0.2.2") {
		t.Errorf("RawResponse = %q", res.RawResponse)
	}
}

func TestLookupWithoutTypesQueriesTheDefaults(t *testing.T) {
	srv := dnstest.New(t, nil)
	lookup(t, newClient(srv.Addr))

	got := map[uint16]bool{}
	for _, q := range srv.Queries() {
		got[q.Type] = true
	}
	for _, typ := range defaultTypes {
		if !got[typ] {
			t.Errorf("%s not queried", TypeName(typ))
		}
	}
	if len(got) != len(defaultTypes) {
		t.Errorf("queried %d types, want %d", len(got), len(defaultTypes))
	}
}

// The first type asked for answers last: the output must not depend on timing.
func TestLookupOrderDoesNotDependOnTiming(t *testing.T) {
	delays := map[uint16]time.Duration{mdns.TypeA: 60 * time.Millisecond, mdns.TypeMX: 30 * time.Millisecond}
	records := map[uint16]mdns.RR{
		mdns.TypeA:  dnstest.RR(t, "example.com. 300 IN A 192.0.2.1"),
		mdns.TypeMX: dnstest.RR(t, "example.com. 300 IN MX 10 mail.example.com."),
		mdns.TypeNS: dnstest.RR(t, "example.com. 300 IN NS ns.example.com."),
	}
	srv := dnstest.New(t, func(q dnstest.Query, reply *mdns.Msg) bool {
		time.Sleep(delays[q.Type])
		reply.Answer = []mdns.RR{records[q.Type]}
		return true
	})
	res := lookup(t, newClient(srv.Addr), mdns.TypeA, mdns.TypeMX, mdns.TypeNS)

	if got := groupTypes(res.Records); !reflect.DeepEqual(got, []string{"A", "MX", "NS"}) {
		t.Errorf("groups = %v", got)
	}
	a, mx, ns := strings.Index(res.RawResponse, ";; A "), strings.Index(res.RawResponse, ";; MX "), strings.Index(res.RawResponse, ";; NS ")
	if !(a < mx && mx < ns) {
		t.Errorf("raw sections out of order: %q", res.RawResponse)
	}
}

// Types found in the answers without being asked for (CNAME, RRSIG…) come after
// the requested ones, in a stable order: a map iteration here would make the
// page reshuffle between two identical requests.
func TestLookupExtraTypesHaveAStableOrder(t *testing.T) {
	srv := dnstest.New(t, answering(t, map[uint16][]string{
		mdns.TypeDNSKEY: {
			"example.com. 300 IN RRSIG DNSKEY 13 2 300 20300101000000 20200101000000 1 example.com. aGVsbG8=",
			"example.com. 300 IN DNSKEY 257 3 13 aGVsbG8=",
			"example.com. 300 IN CNAME target.example.net.",
			"example.com. 300 IN TXT \"odd\"",
			"example.com. 300 IN A 192.0.2.1",
		},
	}))
	want := []string{"DNSKEY", "A", "CNAME", "RRSIG", "TXT"}
	for range 30 {
		res := lookup(t, newClient(srv.Addr), mdns.TypeDNSKEY)
		if got := groupTypes(res.Records); !reflect.DeepEqual(got, want) {
			t.Fatalf("groups = %v, want %v", got, want)
		}
	}
}

// Every query against a CNAME'd name brings the CNAME back: it must appear once.
func TestLookupDeduplicatesRecordsAcrossQueries(t *testing.T) {
	cname := "www.example.com. 300 IN CNAME target.example.net."
	srv := dnstest.New(t, answering(t, map[uint16][]string{
		mdns.TypeA:     {cname, "target.example.net. 300 IN A 192.0.2.1"},
		mdns.TypeAAAA:  {cname, "target.example.net. 300 IN AAAA 2001:db8::1"},
		mdns.TypeCNAME: {cname},
		mdns.TypeTXT:   {cname},
	}))
	res := lookup(t, newClient(srv.Addr), mdns.TypeA, mdns.TypeAAAA, mdns.TypeCNAME, mdns.TypeTXT)

	for _, g := range res.Records {
		if g.Type == "CNAME" && len(g.Records) != 1 {
			t.Errorf("CNAME appears %d times", len(g.Records))
		}
	}
	// The raw view stays faithful to what each query got back.
	if got := strings.Count(res.RawResponse, "target.example.net.\n"); got != 4 {
		t.Errorf("raw response holds the CNAME %d times, want 4", got)
	}
}

// The TTL counts down between the queries of a same lookup.
func TestLookupDeduplicatesAcrossDifferentTTLs(t *testing.T) {
	srv := dnstest.New(t, answering(t, map[uint16][]string{
		mdns.TypeA:   {"www.example.com. 300 IN CNAME target.example.net."},
		mdns.TypeTXT: {"www.example.com. 299 IN CNAME target.example.net."},
	}))
	res := lookup(t, newClient(srv.Addr), mdns.TypeA, mdns.TypeTXT)
	if len(res.Records) != 1 || len(res.Records[0].Records) != 1 {
		t.Errorf("records = %+v", res.Records)
	}
	if got := res.Records[0].Records[0].TTL; got != 300 {
		t.Errorf("TTL = %d, want the first one seen", got)
	}
}

// Both keys read "257 3 13 [key]": comparing what is displayed would lose one.
func TestLookupKeepsKeysThatLookAlike(t *testing.T) {
	srv := dnstest.New(t, answering(t, map[uint16][]string{
		mdns.TypeDNSKEY: {
			"example.com. 300 IN DNSKEY 257 3 13 aGVsbG8=",
			"example.com. 300 IN DNSKEY 257 3 13 d29ybGQ=",
		},
	}))
	res := lookup(t, newClient(srv.Addr), mdns.TypeDNSKEY)
	if got := len(res.Records[0].Records); got != 2 {
		t.Errorf("kept %d keys, want 2", got)
	}
}

func TestLookupKeepsDistinctRecords(t *testing.T) {
	srv := dnstest.New(t, answering(t, map[uint16][]string{
		mdns.TypeMX: {
			"example.com. 300 IN MX 10 mail.example.com.",
			"example.com. 300 IN MX 20 mail.example.com.",
			"example.com. 300 IN MX 10 backup.example.com.",
		},
	}))
	res := lookup(t, newClient(srv.Addr), mdns.TypeMX)
	if got := len(res.Records[0].Records); got != 3 {
		t.Errorf("kept %d MX records, want 3", got)
	}
}

func TestLookupFallsBackToTCPWhenTruncated(t *testing.T) {
	record := dnstest.RR(t, "example.com. 300 IN TXT \"complete\"")
	srv := dnstest.New(t, func(q dnstest.Query, reply *mdns.Msg) bool {
		if q.Net == "udp" {
			reply.Truncated = true
			return true
		}
		reply.Answer = []mdns.RR{record}
		return true
	})
	res := lookup(t, newClient(srv.Addr), mdns.TypeTXT)

	nets := []string{}
	for _, q := range srv.Queries() {
		nets = append(nets, q.Net)
	}
	if !reflect.DeepEqual(nets, []string{"udp", "tcp"}) {
		t.Errorf("transports = %v", nets)
	}
	if res.Flags.Truncated || len(res.Records) != 1 {
		t.Errorf("flags = %+v, records = %+v", res.Flags, res.Records)
	}
}

func TestLookupKeepsTruncatedAnswerWhenTCPFails(t *testing.T) {
	record := dnstest.RR(t, "example.com. 300 IN TXT \"partial\"")
	srv := dnstest.New(t, func(q dnstest.Query, reply *mdns.Msg) bool {
		if q.Net == "tcp" {
			return false
		}
		reply.Truncated = true
		reply.Answer = []mdns.RR{record}
		return true
	})
	res := lookup(t, newClient(srv.Addr), mdns.TypeTXT)
	if !res.Flags.Truncated || len(res.Records) != 1 {
		t.Errorf("flags = %+v, records = %+v", res.Flags, res.Records)
	}
}

func TestLookupFailsOverOnNetworkError(t *testing.T) {
	silent := dnstest.New(t, func(dnstest.Query, *mdns.Msg) bool { return false })
	healthy := dnstest.New(t, nil)

	for name, first := range map[string]string{"refused": dnstest.DeadAddr(t), "silent": silent.Addr} {
		t.Run(name, func(t *testing.T) {
			res := lookup(t, newClient(first, healthy.Addr), mdns.TypeA)
			if res.Server != healthy.Addr {
				t.Errorf("Server = %q, want %q", res.Server, healthy.Addr)
			}
			if len(res.Warnings) != 0 {
				t.Errorf("Warnings = %v", res.Warnings)
			}
		})
	}
}

// A resolver that answers has answered, even with SERVFAIL: showing that answer
// is the whole point of a dig-like tool.
func TestLookupDoesNotFailOverOnDNSError(t *testing.T) {
	for _, rcode := range []int{mdns.RcodeServerFailure, mdns.RcodeRefused, mdns.RcodeNameError} {
		t.Run(mdns.RcodeToString[rcode], func(t *testing.T) {
			first := dnstest.New(t, func(_ dnstest.Query, reply *mdns.Msg) bool {
				reply.Rcode = rcode
				return true
			})
			second := dnstest.New(t, nil)
			res := lookup(t, newClient(first.Addr, second.Addr), mdns.TypeA)
			if res.Rcode != mdns.RcodeToString[rcode] {
				t.Errorf("Rcode = %q", res.Rcode)
			}
			if got := second.Queries(); len(got) != 0 {
				t.Errorf("second resolver queried: %+v", got)
			}
		})
	}
}

func TestLookupResolverOverrideDisablesFailover(t *testing.T) {
	healthy := dnstest.New(t, nil)
	dead := dnstest.DeadAddr(t)
	if _, err := newClient(healthy.Addr).Lookup(context.Background(), "example.com", []uint16{mdns.TypeA}, false, dead); err == nil {
		t.Error("Lookup succeeded through a dead override")
	}
	if got := healthy.Queries(); len(got) != 0 {
		t.Errorf("configured resolver queried despite the override: %+v", got)
	}
}

func TestLookupSetsDOBitOnDNSSECTypesOnly(t *testing.T) {
	srv := dnstest.New(t, nil)
	c := newClient(srv.Addr)
	c.MaxParallel = 64
	all := slices.Collect(func(yield func(uint16) bool) {
		for _, code := range allSupportedTypes {
			if !yield(code) {
				return
			}
		}
	})
	lookup(t, c, all...)

	queries := srv.Queries()
	if len(queries) != len(all) {
		t.Fatalf("%d queries, want %d", len(queries), len(all))
	}
	for _, q := range queries {
		name := TypeName(q.Type)
		if q.DO != dnssecTypes[q.Type] {
			t.Errorf("%s: DO = %v", name, q.DO)
		}
		if dnssecTypes[q.Type] && q.UDPSize != dnssecUDPSize {
			t.Errorf("%s: UDP size = %d", name, q.UDPSize)
		}
	}
}

func TestLookupBoundsParallelism(t *testing.T) {
	for _, limit := range []int{1, 3} {
		var inFlight, peak atomic.Int32
		srv := dnstest.New(t, func(dnstest.Query, *mdns.Msg) bool {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			return true
		})
		c := newClient(srv.Addr)
		c.MaxParallel = limit
		lookup(t, c, ParseRecordTypes("A,AAAA,MX,NS,TXT,CNAME,SOA,CAA,HTTPS,SRV,NAPTR,URI")...)

		got := int(peak.Load())
		if got > limit {
			t.Errorf("limit %d: %d queries in flight", limit, got)
		}
		if limit > 1 && got < 2 {
			t.Errorf("limit %d: queries were not parallel (peak %d)", limit, got)
		}
	}
}

func TestLookupReverse(t *testing.T) {
	tests := []struct{ ip, ptr string }{
		{"8.8.8.8", "8.8.8.8.in-addr.arpa."},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			record := dnstest.RR(t, tt.ptr+" 300 IN PTR host.example.com.")
			srv := dnstest.New(t, func(_ dnstest.Query, reply *mdns.Msg) bool {
				reply.Answer = []mdns.RR{record}
				return true
			})
			// Any requested type is ignored: a reverse lookup is a PTR lookup.
			res, err := newClient(srv.Addr).Lookup(context.Background(), tt.ip, []uint16{mdns.TypeMX}, true, "")
			if err != nil {
				t.Fatal(err)
			}
			want := []dnstest.Query{{Name: tt.ptr, Type: mdns.TypePTR, Net: "udp"}}
			if got := srv.Queries(); !reflect.DeepEqual(got, want) {
				t.Errorf("queries = %+v", got)
			}
			if res.Query != tt.ip || res.QueryType != model.QueryReverse {
				t.Errorf("Query = %q (%s)", res.Query, res.QueryType)
			}
			if len(res.Records) != 1 || res.Records[0].Records[0].Value != "host.example.com." {
				t.Errorf("records = %+v", res.Records)
			}
		})
	}
	if _, err := newClient("127.0.0.1:1").Lookup(context.Background(), "not-an-ip", nil, true, ""); err == nil {
		t.Error("reverse lookup of a non-IP succeeded")
	}
}

// One type failing must not lose the others; the warning names the culprit and
// the answer metadata comes from the first query that did succeed.
func TestLookupPartialFailureBecomesAWarning(t *testing.T) {
	record := dnstest.RR(t, "example.com. 300 IN MX 10 mail.example.com.")
	srv := dnstest.New(t, func(q dnstest.Query, reply *mdns.Msg) bool {
		if q.Type == mdns.TypeA {
			return false
		}
		reply.Answer = []mdns.RR{record}
		return true
	})
	res := lookup(t, newClient(srv.Addr), mdns.TypeA, mdns.TypeMX)

	if len(res.Warnings) != 1 || !strings.HasPrefix(res.Warnings[0], "A: ") {
		t.Errorf("Warnings = %v", res.Warnings)
	}
	if res.Server != srv.Addr || res.Rcode != "NOERROR" || len(res.Records) != 1 {
		t.Errorf("result = %+v", res)
	}
}

func TestLookupFailsWhenEveryQueryFails(t *testing.T) {
	silent := dnstest.New(t, func(dnstest.Query, *mdns.Msg) bool { return false })
	for name, addr := range map[string]string{"refused": dnstest.DeadAddr(t), "silent": silent.Addr} {
		t.Run(name, func(t *testing.T) {
			if res, err := newClient(addr).Lookup(context.Background(), "example.com", []uint16{mdns.TypeA, mdns.TypeMX}, false, ""); err == nil {
				t.Errorf("no error, result = %+v", res)
			}
		})
	}
}

func TestLookupHonoursCancellation(t *testing.T) {
	srv := dnstest.New(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newClient(srv.Addr).Lookup(ctx, "example.com", []uint16{mdns.TypeA}, false, ""); err == nil {
		t.Error("cancelled lookup succeeded")
	}
	if got := srv.Queries(); len(got) != 0 {
		t.Errorf("cancelled lookup sent %+v", got)
	}
}

func TestCheckResolver(t *testing.T) {
	withRcode := func(rcode int) dnstest.Handler {
		return func(_ dnstest.Query, reply *mdns.Msg) bool {
			reply.Rcode = rcode
			return true
		}
	}
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"healthy", dnstest.New(t, nil).Addr, false},
		{"servfail", dnstest.New(t, withRcode(mdns.RcodeServerFailure)).Addr, true},
		{"refused rcode", dnstest.New(t, withRcode(mdns.RcodeRefused)).Addr, true},
		{"dead", dnstest.DeadAddr(t), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			latency, err := CheckResolver(context.Background(), tt.addr, silenceTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if latency <= 0 {
				t.Errorf("latency = %v", latency)
			}
		})
	}
}

func TestParseRR(t *testing.T) {
	const b64 = "aGVsbG8="
	tests := []struct {
		zone     string
		value    string
		priority uint16
	}{
		{"h. 1 IN A 192.0.2.1", "192.0.2.1", 0},
		{"h. 1 IN AAAA 2001:db8::1", "2001:db8::1", 0},
		{"h. 1 IN CNAME t.example.", "t.example.", 0},
		{"h. 1 IN DNAME t.example.", "t.example.", 0},
		{"h. 1 IN MX 10 m.example.", "m.example.", 10},
		{"h. 1 IN NS n.example.", "n.example.", 0},
		{"h. 1 IN PTR p.example.", "p.example.", 0},
		{"h. 1 IN SOA n.example. a.example. 1 2 3 4 5", "n.example. a.example. 1 2 3 4 5", 0},
		{`h. 1 IN TXT "one" "two"`, "one two", 0},
		{"h. 1 IN SRV 5 6 443 t.example.", "t.example.:443", 5},
		{`h. 1 IN NAPTR 10 20 "U" "E2U+sip" "!^.*$!sip:a@b!" .`, `20 "U" "E2U+sip" "!^.*$!sip:a@b!" .`, 10},
		{`h. 1 IN HTTPS 1 . alpn="h2,h3"`, ". alpn=h2,h3", 1},
		{"h. 1 IN HTTPS 0 cdn.example.", "cdn.example.", 0},
		{`h. 1 IN SVCB 2 s.example. port="8443"`, "s.example. port=8443", 2},
		{`h. 1 IN URI 10 1 "https://example.com/"`, "1 https://example.com/", 10},
		{"h. 1 IN KX 10 k.example.", "k.example.", 10},
		{"h. 1 IN AFSDB 1 a.example.", "a.example.", 1},
		{`h. 1 IN CAA 0 issue "ca.example"`, `0 issue "ca.example"`, 0},
		{"h. 1 IN TLSA 3 1 1 abcd", "3 1 1 abcd", 0},
		{"h. 1 IN SMIMEA 3 1 1 abcd", "3 1 1 abcd", 0},
		{"h. 1 IN SSHFP 4 2 abcd", "4 2 abcd", 0},
		{"h. 1 IN OPENPGPKEY " + b64, "[key]", 0},
		{"h. 1 IN CERT 1 2 3 " + b64, "1 2 3 [cert]", 0},
		{"h. 1 IN IPSECKEY 10 1 2 192.0.2.1 " + b64, "10 1 2 192.0.2.1 [key]", 0},
		{"h. 1 IN IPSECKEY 10 3 2 gw.example. " + b64, "10 3 2 gw.example. [key]", 0},
		{"h. 1 IN IPSECKEY 10 0 2 . " + b64, "10 0 2 . [key]", 0},
		{"h. 1 IN DNSKEY 257 3 13 " + b64, "257 3 13 [key]", 0},
		{"h. 1 IN CDNSKEY 257 3 13 " + b64, "257 3 13 [key]", 0},
		{"h. 1 IN DS 1 13 2 abcd", "1 13 2 abcd", 0},
		{"h. 1 IN CDS 1 13 2 abcd", "1 13 2 abcd", 0},
		{"h. 1 IN RRSIG A 13 2 1 20300101000000 20200101000000 7 s.example. " + b64,
			"A alg=13 tag=7 s.example. 20200101000000-20300101000000", 0},
		{"h. 1 IN NSEC n.example. A MX", "n.example. A MX", 0},
		{"h. 1 IN NSEC3 1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A", "1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A", 0},
		{"h. 1 IN NSEC3PARAM 1 0 0 -", "1 0 0 -", 0},
		{"h. 1 IN NSEC3PARAM 1 0 5 ab12", "1 0 5 ab12", 0},
		{"h. 1 IN CSYNC 7 3 A NS", "7 3 A NS", 0},
		{"h. 1 IN ZONEMD 7 1 1 abcd", "7 1 1 abcd", 0},
		{`h. 1 IN HINFO "cpu" "os"`, `"cpu" "os"`, 0},
		{"h. 1 IN RP m.example. t.example.", "m.example. t.example.", 0},
		// Types without a case of their own go through the generic fallback.
		{"h. 1 IN EUI48 00-00-5e-00-53-2a", "00-00-5e-00-53-2a", 0},
		{"h. 1 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m", "52 22 23.000 N 04 53 32.000 E -2m 0.00m 10000m 10m", 0},
	}
	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			rr := dnstest.RR(t, tt.zone)
			got := parseRR(rr)
			if got.Value != tt.value {
				t.Errorf("Value = %q, want %q", got.Value, tt.value)
			}
			if got.Priority != tt.priority {
				t.Errorf("Priority = %d, want %d", got.Priority, tt.priority)
			}
			if got.Name != "h." || got.TTL != 1 || got.Class != "IN" || got.Type != mdns.TypeToString[rr.Header().Rrtype] {
				t.Errorf("header = %+v", got)
			}
		})
	}
}
