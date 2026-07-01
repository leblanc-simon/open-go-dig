package model

import "time"

// QueryType distinguishes forward from reverse DNS lookups.
type QueryType string

const (
	QueryForward QueryType = "forward"
	QueryReverse QueryType = "reverse"
)

// DNSResult contains all data from a DNS resolution.
type DNSResult struct {
	Query       string        // Domain or IP queried
	QueryType   QueryType     // forward or reverse
	Server      string        // Resolver used
	Records     []RecordGroup // Records grouped by type
	Flags       DNSFlags      // Response flags
	Rcode       string        // NOERROR, NXDOMAIN, SERVFAIL, etc.
	QueryTime   time.Duration // Resolution time
	Error       string        // Non-empty on failure
	Warnings    []string      // Non-blocking warnings
	RawResponse string        // Raw response in dig-like format
}

// RecordGroup groups DNS records of the same type.
type RecordGroup struct {
	Type    string       // "A", "AAAA", "MX", etc.
	Records []RecordInfo // Individual records
}

// RecordInfo represents a single DNS record.
type RecordInfo struct {
	Name     string // Record name
	TTL      uint32 // Time to live
	Class    string // IN, CH, etc.
	Type     string // A, AAAA, MX, etc.
	Value    string // IP, hostname, text, etc.
	Priority uint16 // For MX and SRV only
}

// DNSFlags represents the flags from a DNS response.
type DNSFlags struct {
	Authoritative      bool `json:"authoritative"`      // AA
	RecursionDesired   bool `json:"recursionDesired"`    // RD
	RecursionAvailable bool `json:"recursionAvailable"`  // RA
	AuthenticData      bool `json:"authenticData"`       // AD (DNSSEC)
	CheckingDisabled   bool `json:"checkingDisabled"`    // CD
	Truncated          bool `json:"truncated"`           // TC
}

// APIResponse is the JSON representation exposed by the API.
type APIResponse struct {
	Query     string        `json:"query"`
	QueryType string        `json:"queryType"`
	Server    string        `json:"server"`
	Rcode     string        `json:"rcode"`
	Flags     DNSFlags      `json:"flags"`
	QueryTime string        `json:"queryTime"`
	Records   []RecordGroup `json:"records,omitempty"`
	Warnings  []string      `json:"warnings,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// ToAPIResponse converts a DNSResult to its API representation.
func (d *DNSResult) ToAPIResponse() APIResponse {
	return APIResponse{
		Query:     d.Query,
		QueryType: string(d.QueryType),
		Server:    d.Server,
		Rcode:     d.Rcode,
		Flags:     d.Flags,
		QueryTime: d.QueryTime.String(),
		Records:   d.Records,
		Warnings:  d.Warnings,
		Error:     d.Error,
	}
}
