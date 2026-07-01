// Package dns provides a DNS client using github.com/miekg/dns for multi-type lookups.
package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"open-go-dig/internal/model"
)

// defaultResolvers are used when no resolvers are configured.
var defaultResolvers = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

// defaultTypes are queried when no specific type is requested.
var defaultTypes = []uint16{
	mdns.TypeA, mdns.TypeAAAA, mdns.TypeMX, mdns.TypeNS,
	mdns.TypeTXT, mdns.TypeCNAME, mdns.TypeSOA, mdns.TypeCAA,
}

// allSupportedTypes maps type names to their DNS type codes.
var allSupportedTypes = map[string]uint16{
	"A":      mdns.TypeA,
	"AAAA":   mdns.TypeAAAA,
	"MX":     mdns.TypeMX,
	"NS":     mdns.TypeNS,
	"TXT":    mdns.TypeTXT,
	"CNAME":  mdns.TypeCNAME,
	"SOA":    mdns.TypeSOA,
	"PTR":    mdns.TypePTR,
	"SRV":    mdns.TypeSRV,
	"CAA":    mdns.TypeCAA,
	"DNSKEY": mdns.TypeDNSKEY,
	"DS":     mdns.TypeDS,
	"TLSA":   mdns.TypeTLSA,
}

// Client performs DNS queries against configured resolvers.
type Client struct {
	Resolvers []string
	Timeout   time.Duration
	Debug     bool
}

// NewClient creates a DNS client with the given resolvers and timeout.
func NewClient(resolvers []string, timeoutSec int) *Client {
	if len(resolvers) == 0 {
		resolvers = defaultResolvers
	}
	// Ensure all resolvers have a port
	for i, r := range resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			resolvers[i] = r + ":53"
		}
	}
	return &Client{
		Resolvers: resolvers,
		Timeout:   time.Duration(timeoutSec) * time.Second,
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
	var rawBuf strings.Builder
	groupMap := make(map[string]*model.RecordGroup)

	for _, rtype := range recordTypes {
		msg := new(mdns.Msg)
		msg.SetQuestion(name, rtype)
		msg.RecursionDesired = true

		resp, server, err := c.exchange(ctx, msg, resolvers)
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
	case *mdns.A:
		rec.Value = v.A.String()
	case *mdns.AAAA:
		rec.Value = v.AAAA.String()
	case *mdns.MX:
		rec.Value = v.Mx
		rec.Priority = v.Preference
	case *mdns.NS:
		rec.Value = v.Ns
	case *mdns.TXT:
		rec.Value = strings.Join(v.Txt, " ")
	case *mdns.CNAME:
		rec.Value = v.Target
	case *mdns.SOA:
		rec.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *mdns.PTR:
		rec.Value = v.Ptr
	case *mdns.SRV:
		rec.Value = fmt.Sprintf("%s:%d", v.Target, v.Port)
		rec.Priority = v.Priority
	case *mdns.CAA:
		rec.Value = fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value)
	case *mdns.DNSKEY:
		rec.Value = fmt.Sprintf("%d %d %d [key]", v.Flags, v.Protocol, v.Algorithm)
	case *mdns.DS:
		rec.Value = fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, v.Digest)
	case *mdns.TLSA:
		rec.Value = fmt.Sprintf("%d %d %d %s", v.Usage, v.Selector, v.MatchingType, v.Certificate)
	default:
		// Fallback: use the string representation minus the header
		full := rr.String()
		hdrStr := hdr.String()
		rec.Value = strings.TrimPrefix(full, hdrStr)
		rec.Value = strings.TrimSpace(rec.Value)
	}

	return rec
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
