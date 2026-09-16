// Package dns provides a DNS client using github.com/miekg/dns for multi-type lookups.
package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"open-go-dig/internal/model"
)

// defaultResolvers are used when no resolvers are configured.
var defaultResolvers = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

// defaultMaxParallel bounds the per-lookup fan-out when the configuration
// leaves it unset.
const defaultMaxParallel = 8

// Client performs DNS queries against configured resolvers.
type Client struct {
	Resolvers []string
	Timeout   time.Duration
	// MaxParallel caps the number of record-type queries in flight for a
	// single lookup. Zero or less falls back to defaultMaxParallel.
	MaxParallel int
	Debug       bool
}

// NewClient creates a DNS client with the given resolvers, timeout and
// per-lookup parallelism cap.
func NewClient(resolvers []string, timeoutSec, maxParallel int) *Client {
	if len(resolvers) == 0 {
		resolvers = defaultResolvers
	}
	if maxParallel <= 0 {
		maxParallel = defaultMaxParallel
	}
	// Ensure all resolvers have a port
	for i, r := range resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			resolvers[i] = r + ":53"
		}
	}
	return &Client{
		Resolvers:   resolvers,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		MaxParallel: maxParallel,
	}
}

// ParseRecordTypes converts a comma-separated type string to DNS type codes.
func ParseRecordTypes(typeStr string) []uint16 {
	if typeStr == "" {
		return nil
	}
	var types []uint16
	for _, t := range strings.Split(typeStr, ",") {
		t = strings.TrimSpace(strings.ToUpper(t))
		if t == "ALL" || t == "" {
			continue
		}
		if code, ok := allSupportedTypes[t]; ok {
			types = append(types, code)
		}
	}
	return types
}

// TypeName returns the string name for a DNS type code.
func TypeName(t uint16) string {
	return mdns.TypeToString[t]
}

// Lookup performs DNS queries for the requested types.
// If recordTypes is empty, default types are queried.
// For reverse DNS (IP input), a PTR query is performed.
// If resolverOverride is non-empty, it is the only resolver used (no failover).
// The caller is responsible for ensuring resolverOverride belongs to a trusted
// list — this method does NOT validate it.
func (c *Client) Lookup(ctx context.Context, name string, recordTypes []uint16, isReverse bool, resolverOverride string) (*model.DNSResult, error) {
	resolvers := c.Resolvers
	if resolverOverride != "" {
		resolvers = []string{resolverOverride}
	}

	result := &model.DNSResult{
		Query:     name,
		QueryType: model.QueryForward,
	}

	if isReverse {
		result.QueryType = model.QueryReverse
		ptrName, err := mdns.ReverseAddr(name)
		if err != nil {
			return nil, fmt.Errorf("invalid IP for reverse DNS: %w", err)
		}
		name = ptrName
		recordTypes = []uint16{mdns.TypePTR}
	}

	if len(recordTypes) == 0 {
		recordTypes = defaultTypes
	}

	// Ensure FQDN
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	start := time.Now()

	// One query per record type, fanned out but bounded: ?type= accepts the
	// whole catalogue, and an unbounded fan-out would turn a single HTTP
	// request into 44 simultaneous packets aimed at the same resolver.
	// Results are written to a pre-sized slot rather than appended, so the
	// assembly below stays in the order the types were asked for, whatever
	// order the answers come back in.
	type typeResult struct {
		resp   *mdns.Msg
		server string
		err    error
	}
	results := make([]typeResult, len(recordTypes))

	limit := c.MaxParallel
	if limit <= 0 {
		limit = defaultMaxParallel
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, rtype := range recordTypes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			msg := new(mdns.Msg)
			msg.SetQuestion(name, rtype)
			msg.RecursionDesired = true
			if dnssecTypes[rtype] {
				msg.SetEdns0(dnssecUDPSize, true)
			}

			resp, server, err := c.exchange(ctx, msg, resolvers)
			results[i] = typeResult{resp: resp, server: server, err: err}
		}()
	}
	wg.Wait()

	var rawBuf strings.Builder
	groupMap := make(map[string]*model.RecordGroup)

	for i, rtype := range recordTypes {
		resp, server, err := results[i].resp, results[i].server, results[i].err
		if err != nil {
			if c.Debug {
				log.Printf("[dns] %s %s: %v", name, TypeName(rtype), err)
			}
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", TypeName(rtype), err))
			continue
		}

		if result.Server == "" {
			result.Server = server
		}

		// Capture flags and rcode from first successful response
		if result.Rcode == "" {
			result.Rcode = mdns.RcodeToString[resp.Rcode]
			result.Flags = model.DNSFlags{
				Authoritative:      resp.Authoritative,
				RecursionDesired:   resp.RecursionDesired,
				RecursionAvailable: resp.RecursionAvailable,
				AuthenticData:      resp.AuthenticatedData,
				CheckingDisabled:   resp.CheckingDisabled,
				Truncated:          resp.Truncated,
			}
		}

		// Build raw response
		rawBuf.WriteString(fmt.Sprintf(";; %s records for %s (from %s)\n", TypeName(rtype), name, server))
		for _, rr := range resp.Answer {
			rawBuf.WriteString(rr.String())
			rawBuf.WriteString("\n")

			rec := parseRR(rr)
			typeName := rec.Type
			grp, ok := groupMap[typeName]
			if !ok {
				grp = &model.RecordGroup{Type: typeName}
				groupMap[typeName] = grp
			}
			grp.Records = append(grp.Records, rec)
		}
		rawBuf.WriteString("\n")
	}

	result.QueryTime = time.Since(start)
	result.RawResponse = rawBuf.String()

	// Ordered groups: follow the order of record types queried
	seen := make(map[string]bool)
	for _, rtype := range recordTypes {
		tn := TypeName(rtype)
		if grp, ok := groupMap[tn]; ok && !seen[tn] {
			result.Records = append(result.Records, *grp)
			seen[tn] = true
		}
	}
	// Add any extra types found in answers but not in the query list
	for tn, grp := range groupMap {
		if !seen[tn] {
			result.Records = append(result.Records, *grp)
		}
	}

	return result, nil
}

// exchange sends a DNS message trying each resolver in order.
// Uses UDP first, falls back to TCP if the response is truncated.
func (c *Client) exchange(ctx context.Context, msg *mdns.Msg, resolvers []string) (*mdns.Msg, string, error) {
	cl := &mdns.Client{
		Net:     "udp",
		Timeout: c.Timeout,
	}

	var lastErr error
	for _, server := range resolvers {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}

		resp, _, err := cl.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}

		// Fallback to TCP if truncated
		if resp.Truncated {
			tcpCl := &mdns.Client{
				Net:     "tcp",
				Timeout: c.Timeout,
			}
			tcpResp, _, tcpErr := tcpCl.ExchangeContext(ctx, msg, server)
			if tcpErr == nil {
				return tcpResp, server, nil
			}
		}

		return resp, server, nil
	}

	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", fmt.Errorf("no resolvers available")
}

// parseRR extracts record information from a dns.RR.
func parseRR(rr mdns.RR) model.RecordInfo {
	hdr := rr.Header()
	rec := model.RecordInfo{
		Name:  hdr.Name,
		TTL:   hdr.Ttl,
		Class: mdns.ClassToString[hdr.Class],
		Type:  mdns.TypeToString[hdr.Rrtype],
	}

	switch v := rr.(type) {
	// ── Core ──────────────────────────────────────────────────────────────
	case *mdns.A:
		rec.Value = v.A.String()
	case *mdns.AAAA:
		rec.Value = v.AAAA.String()
	case *mdns.CNAME:
		rec.Value = v.Target
	case *mdns.DNAME:
		rec.Value = v.Target
	case *mdns.MX:
		rec.Value = v.Mx
		rec.Priority = v.Preference
	case *mdns.NS:
		rec.Value = v.Ns
	case *mdns.PTR:
		rec.Value = v.Ptr
	case *mdns.SOA:
		rec.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *mdns.TXT:
		rec.Value = strings.Join(v.Txt, " ")

	// ── Services & discovery ──────────────────────────────────────────────
	case *mdns.SRV:
		rec.Value = fmt.Sprintf("%s:%d", v.Target, v.Port)
		rec.Priority = v.Priority
	case *mdns.NAPTR:
		rec.Value = fmt.Sprintf("%d %q %q %q %s",
			v.Preference, v.Flags, v.Service, v.Regexp, v.Replacement)
		rec.Priority = v.Order
	case *mdns.HTTPS:
		rec.Value = formatSVCB(&v.SVCB)
		rec.Priority = v.Priority
	case *mdns.SVCB:
		rec.Value = formatSVCB(v)
		rec.Priority = v.Priority
	case *mdns.URI:
		rec.Value = fmt.Sprintf("%d %s", v.Weight, v.Target)
		rec.Priority = v.Priority
	case *mdns.KX:
		rec.Value = v.Exchanger
		rec.Priority = v.Preference
	case *mdns.AFSDB:
		rec.Value = v.Hostname
		rec.Priority = v.Subtype

	// ── Security & certificates ───────────────────────────────────────────
	case *mdns.CAA:
		rec.Value = fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value)
	case *mdns.TLSA:
		rec.Value = fmt.Sprintf("%d %d %d %s", v.Usage, v.Selector, v.MatchingType, v.Certificate)
	case *mdns.SMIMEA:
		rec.Value = fmt.Sprintf("%d %d %d %s", v.Usage, v.Selector, v.MatchingType, v.Certificate)
	case *mdns.SSHFP:
		rec.Value = fmt.Sprintf("%d %d %s", v.Algorithm, v.Type, v.FingerPrint)
	case *mdns.OPENPGPKEY:
		rec.Value = "[key]"
	case *mdns.CERT:
		rec.Value = fmt.Sprintf("%d %d %d [cert]", v.Type, v.KeyTag, v.Algorithm)
	case *mdns.IPSECKEY:
		gateway := v.GatewayHost
		if gateway == "" && v.GatewayAddr != nil {
			gateway = v.GatewayAddr.String()
		}
		if gateway == "" {
			gateway = "."
		}
		rec.Value = fmt.Sprintf("%d %d %d %s [key]",
			v.Precedence, v.GatewayType, v.Algorithm, gateway)

	// ── DNSSEC ────────────────────────────────────────────────────────────
	case *mdns.DNSKEY:
		rec.Value = fmt.Sprintf("%d %d %d [key]", v.Flags, v.Protocol, v.Algorithm)
	case *mdns.CDNSKEY:
		rec.Value = fmt.Sprintf("%d %d %d [key]", v.Flags, v.Protocol, v.Algorithm)
	case *mdns.DS:
		rec.Value = fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, v.Digest)
	case *mdns.CDS:
		rec.Value = fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, v.Digest)
	case *mdns.RRSIG:
		rec.Value = fmt.Sprintf("%s alg=%d tag=%d %s %s-%s",
			mdns.Type(v.TypeCovered).String(), v.Algorithm, v.KeyTag, v.SignerName,
			mdns.TimeToString(v.Inception), mdns.TimeToString(v.Expiration))
	case *mdns.NSEC:
		rec.Value = strings.TrimSpace(v.NextDomain + " " + formatTypeBitmap(v.TypeBitMap))
	case *mdns.NSEC3:
		rec.Value = strings.TrimSpace(fmt.Sprintf("%d %d %d %s %s %s",
			v.Hash, v.Flags, v.Iterations, formatSalt(v.Salt), v.NextDomain,
			formatTypeBitmap(v.TypeBitMap)))
	case *mdns.NSEC3PARAM:
		rec.Value = fmt.Sprintf("%d %d %d %s",
			v.Hash, v.Flags, v.Iterations, formatSalt(v.Salt))
	case *mdns.CSYNC:
		rec.Value = strings.TrimSpace(fmt.Sprintf("%d %d %s",
			v.Serial, v.Flags, formatTypeBitmap(v.TypeBitMap)))
	case *mdns.ZONEMD:
		rec.Value = fmt.Sprintf("%d %d %d %s", v.Serial, v.Scheme, v.Hash, v.Digest)

	// ── Infrastructure & misc ─────────────────────────────────────────────
	case *mdns.HINFO:
		rec.Value = fmt.Sprintf("%q %q", v.Cpu, v.Os)
	case *mdns.RP:
		rec.Value = fmt.Sprintf("%s %s", v.Mbox, v.Txt)

	default:
		// Fallback: use the string representation minus the header. LOC, APL,
		// DHCID, EUI48/64 and the ILNP family (NID, L32, L64, LP) render fine
		// this way, and so does any type miekg/dns learns before we do.
		full := rr.String()
		hdrStr := hdr.String()
		rec.Value = strings.TrimPrefix(full, hdrStr)
		rec.Value = strings.TrimSpace(rec.Value)
	}

	return rec
}

// formatSVCB renders SVCB/HTTPS RDATA as "target key=value …". The priority is
// carried separately in RecordInfo.Priority; at priority 0 (AliasMode) the
// parameter list is empty by definition — RFC 9460 §2.4.2.
func formatSVCB(v *mdns.SVCB) string {
	parts := make([]string, 0, len(v.Value)+1)
	parts = append(parts, v.Target)
	for _, kv := range v.Value {
		parts = append(parts, fmt.Sprintf("%s=%s", kv.Key(), kv.String()))
	}
	return strings.Join(parts, " ")
}

// formatSalt renders an NSEC3 salt, spelling the empty salt "-" the way the
// presentation format does (RFC 5155 §3.3) rather than leaving a hole.
func formatSalt(salt string) string {
	if salt == "" {
		return "-"
	}
	return salt
}

// formatTypeBitmap renders the type bitmap carried by NSEC, NSEC3 and CSYNC as
// a plain list of type names.
func formatTypeBitmap(bitmap []uint16) string {
	names := make([]string, 0, len(bitmap))
	for _, t := range bitmap {
		names = append(names, mdns.Type(t).String())
	}
	return strings.Join(names, " ")
}

// CheckResolver tests a resolver by sending a simple query and returns the latency.
func CheckResolver(ctx context.Context, server string, timeout time.Duration) (time.Duration, error) {
	cl := &mdns.Client{
		Net:     "udp",
		Timeout: timeout,
	}
	msg := new(mdns.Msg)
	msg.SetQuestion(".", mdns.TypeNS)
	msg.RecursionDesired = true

	start := time.Now()
	_, _, err := cl.ExchangeContext(ctx, msg, server)
	return time.Since(start), err
}
