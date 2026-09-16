package dns

import (
	"net"
	"strings"
)

// Resolver is an upstream DNS server, with the optional display name given in
// the configuration. The name is a picker affordance and nothing else: the
// query path, the SSRF allowlist (handler.AllowedResolver), the status probe
// and every log line key off Addr alone, so renaming a resolver can never
// change which server is talked to.
type Resolver struct {
	Name string
	Addr string
}

// nameSeparator splits "Name=host:port" in a configured resolver entry. An
// address never contains '=', so an unnamed entry stays unambiguous — the
// bracketed IPv6 form "[2001:678:8::3]:53" included.
const nameSeparator = "="

// ParseResolver reads one configuration entry — "host:port", "host" or
// "Name=host:port" — and normalizes the address: a missing port becomes :53,
// and a bare IPv6 literal is bracketed first so it does not end up as the
// nonsense "2001:678:8::3:53". An entry with no address yields the zero
// Resolver, which ParseResolvers drops.
func ParseResolver(entry string) Resolver {
	name, addr, named := strings.Cut(entry, nameSeparator)
	if !named {
		name, addr = "", name
	}
	name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
	if addr == "" {
		return Resolver{}
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
			addr = "[" + addr + "]"
		}
		addr += ":53"
	}
	return Resolver{Name: name, Addr: addr}
}

// ParseResolvers converts the configured entries, keeping their order and
// dropping the empty ones.
func ParseResolvers(entries []string) []Resolver {
	out := make([]Resolver, 0, len(entries))
	for _, e := range entries {
		if r := ParseResolver(e); r.Addr != "" {
			out = append(out, r)
		}
	}
	return out
}

// Label is what the picker shows: "Name - host:port" when the entry is named,
// the bare address otherwise.
func (r Resolver) Label() string {
	if r.Name == "" {
		return r.Addr
	}
	return r.Name + " - " + r.Addr
}
