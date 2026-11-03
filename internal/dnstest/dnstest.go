// Package dnstest runs a scriptable DNS server on the loopback interface, so
// tests can produce what a live resolver will not do on demand: truncation,
// SERVFAIL, silence, slow answers. It is imported by tests only.
package dnstest

import (
	"net"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"
)

// Query describes a question received by the server.
type Query struct {
	Name    string
	Type    uint16
	DO      bool   // EDNS0 DNSSEC OK bit
	UDPSize uint16 // advertised EDNS0 buffer, 0 without EDNS0
	Net     string // "udp" or "tcp"
}

// Handler fills in the prepared reply. Returning false sends nothing at all,
// which the client experiences as a timeout.
type Handler func(q Query, reply *mdns.Msg) bool

// Server is a DNS server listening on the same port in UDP and TCP.
type Server struct {
	Addr string

	mu      sync.Mutex
	queries []Query
}

// New starts a server stopped automatically at the end of the test.
func New(t testing.TB, h Handler) *Server {
	t.Helper()
	pc, ln := listen(t)
	s := &Server{Addr: pc.LocalAddr().String()}

	serve := func(netName string, srv *mdns.Server) {
		srv.Handler = mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
			s.handle(netName, h, w, r)
		})
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	serve("udp", &mdns.Server{PacketConn: pc})
	serve("tcp", &mdns.Server{Listener: ln})
	return s
}

func (s *Server) handle(netName string, h Handler, w mdns.ResponseWriter, r *mdns.Msg) {
	q := Query{Name: r.Question[0].Name, Type: r.Question[0].Qtype, Net: netName}
	if opt := r.IsEdns0(); opt != nil {
		q.DO = opt.Do()
		q.UDPSize = opt.UDPSize()
	}
	s.mu.Lock()
	s.queries = append(s.queries, q)
	s.mu.Unlock()

	reply := new(mdns.Msg)
	reply.SetReply(r)
	reply.RecursionAvailable = true
	if h != nil && !h(q, reply) {
		return
	}
	_ = w.WriteMsg(reply)
}

// Queries returns a copy of the questions received so far, in arrival order.
func (s *Server) Queries() []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Query(nil), s.queries...)
}

// listen binds UDP and TCP to one free port. The kernel picks the UDP port,
// which may already be taken in TCP, hence the retries.
func listen(t testing.TB) (net.PacketConn, net.Listener) {
	t.Helper()
	var lastErr error
	for range 20 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("dnstest: listen udp: %v", err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln
		}
		lastErr = err
		_ = pc.Close()
	}
	t.Fatalf("dnstest: no free port for udp and tcp: %v", lastErr)
	return nil, nil
}

// DeadAddr returns a loopback address nothing listens on: a resolver there
// fails immediately with "connection refused".
func DeadAddr(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dnstest: listen udp: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// RR parses a record in zone-file syntax.
func RR(t testing.TB, zone string) mdns.RR {
	t.Helper()
	rr, err := mdns.NewRR(zone)
	if err != nil {
		t.Fatalf("dnstest: invalid record %q: %v", zone, err)
	}
	if rr == nil {
		t.Fatalf("dnstest: empty record %q", zone)
	}
	return rr
}
