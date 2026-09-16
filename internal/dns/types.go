package dns

import (
	"fmt"

	mdns "github.com/miekg/dns"
)

// TypeGroup is a family of record types. The catalogue below is the single
// source of truth: the query parser, the type picker on the search form and
// the record-type descriptions all walk the same slice, so adding a record
// type to OpenGoDig is a one-line change here plus its locale keys.
//
// Key doubles as an i18n suffix — `index.type_group_<Key>` must exist in every
// locale file, as must `result.record_type_<lowercased type name>` for each
// entry of Types.
type TypeGroup struct {
	Key   string
	Types []string
}

// TypeCatalog lists every record type OpenGoDig can query, in display order.
//
// Deliberately absent: the obsolete types (MD, MF, MB, MG, MR, MINFO, NULL,
// WKS, X25, ISDN, RT, NSAP-PTR, SIG, KEY, GPOS, NXT, TA, DLV, and SPF which
// RFC 7208 folded back into TXT), and the meta types (OPT, TSIG, TKEY, AXFR,
// IXFR, ANY) which a recursive resolver will not answer.
var TypeCatalog = []TypeGroup{
	{Key: "core", Types: []string{
		"A", "AAAA", "CNAME", "DNAME", "MX", "NS", "PTR", "SOA", "TXT",
	}},
	{Key: "service", Types: []string{
		"SRV", "NAPTR", "HTTPS", "SVCB", "URI", "KX", "AFSDB",
	}},
	{Key: "security", Types: []string{
		"CAA", "TLSA", "SMIMEA", "SSHFP", "OPENPGPKEY", "CERT", "IPSECKEY",
	}},
	{Key: "dnssec", Types: []string{
		"DNSKEY", "DS", "CDS", "CDNSKEY", "RRSIG", "NSEC", "NSEC3",
		"NSEC3PARAM", "CSYNC", "ZONEMD",
	}},
	{Key: "infra", Types: []string{
		"LOC", "HINFO", "RP", "APL", "DHCID", "EUI48", "EUI64",
		"NID", "L32", "L64", "LP",
	}},
}

// defaultTypes are queried when no specific type is requested. HTTPS earns its
// place next to the classics: it is what actually drives HTTP/3, ALPN and ECH
// negotiation on the modern web.
var defaultTypes = []uint16{
	mdns.TypeA, mdns.TypeAAAA, mdns.TypeMX, mdns.TypeNS,
	mdns.TypeTXT, mdns.TypeCNAME, mdns.TypeSOA, mdns.TypeCAA,
	mdns.TypeHTTPS,
}

// dnssecTypes must be queried with the EDNS0 DO bit set: without it a resolver
// strips signatures and denial-of-existence records from the answer, and the
// card would come back empty for no visible reason.
var dnssecTypes = map[uint16]bool{
	mdns.TypeDNSKEY:     true,
	mdns.TypeDS:         true,
	mdns.TypeCDS:        true,
	mdns.TypeCDNSKEY:    true,
	mdns.TypeRRSIG:      true,
	mdns.TypeNSEC:       true,
	mdns.TypeNSEC3:      true,
	mdns.TypeNSEC3PARAM: true,
}

// dnssecUDPSize is the EDNS0 buffer advertised for DNSSEC queries. Signed
// answers routinely exceed the 512-byte floor; anything still truncated falls
// back to TCP in exchange().
const dnssecUDPSize = 4096

// allSupportedTypes maps type names to their DNS type codes, derived from
// TypeCatalog.
var allSupportedTypes = buildTypeIndex()

func buildTypeIndex() map[string]uint16 {
	m := make(map[string]uint16, 64)
	for _, g := range TypeCatalog {
		for _, name := range g.Types {
			code, ok := mdns.StringToType[name]
			if !ok {
				panic(fmt.Sprintf("dns: unknown record type %q in TypeCatalog", name))
			}
			m[name] = code
		}
	}
	return m
}

// SupportedTypeCount reports how many record types the catalogue exposes.
func SupportedTypeCount() int {
	return len(allSupportedTypes)
}
