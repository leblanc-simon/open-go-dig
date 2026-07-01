// Package query provides query type detection (domain or IP for reverse DNS).
package query

import (
	"net"
	"strings"
)

// Type represents the DNS query type.
type Type int

const (
	TypeDomain Type = iota
	TypeIPv4        // → reverse DNS (PTR)
	TypeIPv6        // → reverse DNS (PTR)
)

func (t Type) String() string {
	switch t {
	case TypeDomain:
		return "domain"
	case TypeIPv4:
		return "ipv4"
	case TypeIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// Detect determines if the input is a domain or an IP (for reverse DNS).
func Detect(input string) Type {
	s := strings.TrimSpace(input)

	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return TypeIPv4
		}
		return TypeIPv6
	}

	return TypeDomain
}
