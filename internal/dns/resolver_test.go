package dns

import (
	"reflect"
	"testing"
)

func TestParseResolver(t *testing.T) {
	tests := []struct {
		entry string
		want  Resolver
	}{
		{"8.8.8.8:53", Resolver{Addr: "8.8.8.8:53"}},
		{"8.8.8.8", Resolver{Addr: "8.8.8.8:53"}},
		{"8.8.8.8:5353", Resolver{Addr: "8.8.8.8:5353"}},
		{"dns.example", Resolver{Addr: "dns.example:53"}},
		{"Google=8.8.8.8:53", Resolver{Name: "Google", Addr: "8.8.8.8:53"}},
		{"  Google = 8.8.8.8  ", Resolver{Name: "Google", Addr: "8.8.8.8:53"}},
		{"2001:678:8::3", Resolver{Addr: "[2001:678:8::3]:53"}},
		{"[2001:678:8::3]:53", Resolver{Addr: "[2001:678:8::3]:53"}},
		{"AFNIC=2001:678:8::3", Resolver{Name: "AFNIC", Addr: "[2001:678:8::3]:53"}},
		{"", Resolver{}},
		{"   ", Resolver{}},
		{"Google=", Resolver{}},
	}
	for _, tt := range tests {
		if got := ParseResolver(tt.entry); got != tt.want {
			t.Errorf("ParseResolver(%q) = %+v, want %+v", tt.entry, got, tt.want)
		}
	}
}

func TestParseResolversKeepsOrderAndDropsEmpty(t *testing.T) {
	got := ParseResolvers([]string{"B=2.2.2.2", "", "1.1.1.1:53", "Empty="})
	want := []Resolver{{Name: "B", Addr: "2.2.2.2:53"}, {Addr: "1.1.1.1:53"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseResolvers = %+v, want %+v", got, want)
	}
}

func TestResolverLabel(t *testing.T) {
	if got := (Resolver{Name: "Google", Addr: "8.8.8.8:53"}).Label(); got != "Google - 8.8.8.8:53" {
		t.Errorf("named Label() = %q", got)
	}
	if got := (Resolver{Addr: "8.8.8.8:53"}).Label(); got != "8.8.8.8:53" {
		t.Errorf("unnamed Label() = %q", got)
	}
}

func TestNewClientDefaults(t *testing.T) {
	c := NewClient(nil, 2, 0)
	if !reflect.DeepEqual(c.Resolvers, defaultResolvers) {
		t.Errorf("Resolvers = %+v, want the defaults", c.Resolvers)
	}
	if c.MaxParallel != defaultMaxParallel {
		t.Errorf("MaxParallel = %d, want %d", c.MaxParallel, defaultMaxParallel)
	}
	if got := NewClient([]string{"Q=9.9.9.9"}, 2, 3); !reflect.DeepEqual(got.Addrs(), []string{"9.9.9.9:53"}) || got.MaxParallel != 3 {
		t.Errorf("configured client = %+v", got)
	}
}
