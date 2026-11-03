package query

import "testing"

func TestDetect(t *testing.T) {
	tests := []struct {
		input string
		want  Type
	}{
		{"example.com", TypeDomain},
		{"_dmarc.example.com", TypeDomain},
		{"xn--mnchen-3ya.de", TypeDomain},
		{"", TypeDomain},
		{"1.2.3", TypeDomain},
		{"256.1.1.1", TypeDomain},
		{"1.1.1.1", TypeIPv4},
		{"  8.8.8.8  ", TypeIPv4},
		{"::ffff:1.2.3.4", TypeIPv4}, // IPv4-mapped: its PTR lives under in-addr.arpa
		{"2606:4700:4700::1111", TypeIPv6},
		{"::1", TypeIPv6},
		{"a::1", TypeIPv6},
		{"[::1]", TypeDomain}, // brackets are the sanitizer's business
	}
	for _, tt := range tests {
		if got := Detect(tt.input); got != tt.want {
			t.Errorf("Detect(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestTypeString(t *testing.T) {
	tests := map[Type]string{TypeDomain: "domain", TypeIPv4: "ipv4", TypeIPv6: "ipv6", Type(99): "unknown"}
	for typ, want := range tests {
		if got := typ.String(); got != want {
			t.Errorf("Type(%d).String() = %q, want %q", int(typ), got, want)
		}
	}
}
