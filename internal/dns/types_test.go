package dns

import (
	"reflect"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestValidRecordTypes(t *testing.T) {
	tests := map[string]bool{
		"":        true,
		"ALL":     true,
		",":       true,
		"MX":      true,
		"mx, ns":  true,
		",MX":     true,
		"ALL,MX":  true,
		"FOO":     false,
		"MX,FOO":  false,
		"ANY":     false,
		"AXFR":    false,
		"MX;NS":   false,
		"MX NS":   false,
		"TYPE255": false,
	}
	for input, want := range tests {
		if got := ValidRecordTypes(input); got != want {
			t.Errorf("ValidRecordTypes(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestParseRecordTypes(t *testing.T) {
	tests := []struct {
		input string
		want  []uint16
	}{
		{"", nil},
		{"MX", []uint16{mdns.TypeMX}},
		{"mx", []uint16{mdns.TypeMX}},
		{" mx , ns ", []uint16{mdns.TypeMX, mdns.TypeNS}},
		{"NS,MX", []uint16{mdns.TypeNS, mdns.TypeMX}},
		{"MX,MX,mx", []uint16{mdns.TypeMX}},
		{",,", nil},
		{",MX,", []uint16{mdns.TypeMX}},
		{"ALL", nil},
		{"all", nil},
		{"ALL,MX", []uint16{mdns.TypeMX}},
		{"FOO", nil},
		{"FOO,MX", []uint16{mdns.TypeMX}},
		// Meta and obsolete types stay out of the catalogue on purpose.
		{"ANY", nil},
		{"AXFR", nil},
		{"SPF", nil},
		{"WKS", nil},
	}
	for _, tt := range tests {
		if got := ParseRecordTypes(tt.input); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseRecordTypes(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestTypeCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range TypeCatalog {
		if g.Key == "" || len(g.Types) == 0 {
			t.Errorf("incomplete group %+v", g)
		}
		for _, name := range g.Types {
			if seen[name] {
				t.Errorf("%s listed twice in the catalogue", name)
			}
			seen[name] = true
		}
	}
	if len(seen) != 44 {
		t.Errorf("catalogue has %d types, want 44 (update CLAUDE.md if this is deliberate)", len(seen))
	}
	if SupportedTypeCount() != len(seen) {
		t.Errorf("SupportedTypeCount() = %d, want %d", SupportedTypeCount(), len(seen))
	}
}

func TestDefaultTypesBelongToTheCatalogue(t *testing.T) {
	want := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "HTTPS"}
	if got := DefaultTypeNames(); !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultTypeNames() = %v, want %v", got, want)
	}
	for _, name := range want {
		if _, ok := allSupportedTypes[name]; !ok {
			t.Errorf("default type %s is not in the catalogue", name)
		}
	}
}

func TestDNSSECTypesBelongToTheCatalogue(t *testing.T) {
	for code := range dnssecTypes {
		if _, ok := allSupportedTypes[TypeName(code)]; !ok {
			t.Errorf("DNSSEC type %s is not in the catalogue", TypeName(code))
		}
	}
}
