// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockExchanger implements upstreamExchanger for testing forwardUpstream without
// a live upstream.
type mockExchanger struct {
	resp   *dns.Msg
	err    error
	closed bool
}

func (m *mockExchanger) Exchange(q *dns.Msg, timeout time.Duration, maxRetries int) (*dns.Msg, error) {
	return m.resp, m.err
}

func (m *mockExchanger) Close() { m.closed = true }

// answerMsg builds a reply to q with a single A record at the given TTL.
func answerMsg(q *dns.Msg, ip string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
	}
	rr.A = parseIP(ip)
	m.Answer = append(m.Answer, rr)
	return m
}

func parseIP(s string) []byte {
	rr, err := dns.NewRR("x. 0 IN A " + s)
	if err != nil {
		return nil
	}
	return rr.(*dns.A).A
}

// --- Cache unit tests ---

func TestAnswerCache_RetainsAndReturnsStale(t *testing.T) {
	q := newTestQuery("example.com")
	base := time.Now()

	c := newAnswerCache(10, time.Hour)
	c.now = func() time.Time { return base }
	c.Put(cacheKey(q.Question[0]), answerMsg(q, "93.184.216.34", 60))

	// Advance past the 60s TTL but within the 1h stale window.
	c.now = func() time.Time { return base.Add(2 * time.Minute) }

	if _, ok := c.Get(cacheKey(q.Question[0])); ok {
		t.Error("Get should miss on an expired entry")
	}
	ent, ok := c.GetStale(cacheKey(q.Question[0]))
	if !ok {
		t.Fatal("GetStale should return the expired-but-retained entry")
	}
	if len(ent.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer in stale entry, got %d", len(ent.msg.Answer))
	}
}

func TestAnswerCache_FreshHit(t *testing.T) {
	q := newTestQuery("fresh.com")
	base := time.Now()
	c := newAnswerCache(10, time.Hour)
	c.now = func() time.Time { return base }
	c.Put(cacheKey(q.Question[0]), answerMsg(q, "1.1.1.1", 60))

	if _, ok := c.Get(cacheKey(q.Question[0])); !ok {
		t.Error("Get should hit before TTL expiry")
	}
}

func TestAnswerCache_EvictsBeyondStaleWindow(t *testing.T) {
	q := newTestQuery("old.com")
	base := time.Now()
	c := newAnswerCache(10, time.Minute) // short stale window
	c.now = func() time.Time { return base }
	c.Put(cacheKey(q.Question[0]), answerMsg(q, "2.2.2.2", 30))

	// 30s TTL + 60s stale window = 90s; advance well beyond.
	c.now = func() time.Time { return base.Add(10 * time.Minute) }
	if _, ok := c.GetStale(cacheKey(q.Question[0])); ok {
		t.Error("GetStale should miss beyond the stale retention window")
	}
	// Entry should have been evicted.
	if _, ok := c.items[cacheKey(q.Question[0])]; ok {
		t.Error("expired-beyond-window entry should have been evicted")
	}
}

func TestAnswerCache_MissingKey(t *testing.T) {
	c := newAnswerCache(10, time.Hour)
	if _, ok := c.GetStale("nope|1|1"); ok {
		t.Error("GetStale should miss on an unknown key")
	}
}

func TestAnswerCache_NoAnswerNotCached(t *testing.T) {
	q := newTestQuery("empty.com")
	c := newAnswerCache(10, time.Hour)
	m := new(dns.Msg)
	m.SetReply(q) // no answer records
	c.Put(cacheKey(q.Question[0]), m)
	if _, ok := c.GetStale(cacheKey(q.Question[0])); ok {
		t.Error("responses with no answers should not be cached")
	}
}

func TestAnswerCache_LRUEviction(t *testing.T) {
	c := newAnswerCache(2, time.Hour)
	for _, name := range []string{"a.com", "b.com", "c.com"} {
		q := newTestQuery(name)
		c.Put(cacheKey(q.Question[0]), answerMsg(q, "9.9.9.9", 60))
	}
	// a.com was least-recently used and should have been evicted.
	qa := newTestQuery("a.com")
	if _, ok := c.GetStale(cacheKey(qa.Question[0])); ok {
		t.Error("expected LRU eviction of the oldest entry")
	}
	if c.ll.Len() != 2 {
		t.Errorf("expected cache size capped at 2, got %d", c.ll.Len())
	}
}

func TestCacheKey_DistinctByType(t *testing.T) {
	a := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	aaaa := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	if cacheKey(a) == cacheKey(aaaa) {
		t.Error("A and AAAA questions should have distinct cache keys")
	}
}

// --- forwardUpstream serve-stale behavior ---

func staleEngine(ex upstreamExchanger, enabled bool, c *answerCache) *Engine {
	return &Engine{
		upstreamManager: ex,
		serveStale:      enabled,
		cache:           c,
	}
}

func TestForwardUpstream_ServesStaleOnError(t *testing.T) {
	q := newTestQuery("example.com")
	base := time.Now()
	c := newAnswerCache(10, time.Hour)
	c.now = func() time.Time { return base }
	c.Put(cacheKey(q.Question[0]), answerMsg(q, "93.184.216.34", 60))
	c.now = func() time.Time { return base.Add(5 * time.Minute) } // expired, within window

	e := staleEngine(&mockExchanger{err: errors.New("upstream down")}, true, c)
	w := &mockResponseWriter{}
	e.forwardUpstream(w, q, "example.com")

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Rcode == dns.RcodeServerFailure {
		t.Fatal("expected stale answer, got SERVFAIL")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 stale answer, got %d", len(w.msg.Answer))
	}
	if w.msg.Answer[0].Header().Ttl != staleTTL {
		t.Errorf("expected stale answer TTL clamped to %d, got %d", staleTTL, w.msg.Answer[0].Header().Ttl)
	}
}

func TestForwardUpstream_ServfailWhenDisabled(t *testing.T) {
	q := newTestQuery("example.com")
	// Even with a populated cache, a disabled engine must SERVFAIL.
	base := time.Now()
	c := newAnswerCache(10, time.Hour)
	c.now = func() time.Time { return base }
	c.Put(cacheKey(q.Question[0]), answerMsg(q, "93.184.216.34", 60))

	e := staleEngine(&mockExchanger{err: errors.New("upstream down")}, false, nil)
	w := &mockResponseWriter{}
	e.forwardUpstream(w, q, "example.com")

	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when serve-stale disabled, got %+v", w.msg)
	}
}

func TestForwardUpstream_ServfailWhenNoStale(t *testing.T) {
	q := newTestQuery("nostale.com")
	e := staleEngine(&mockExchanger{err: errors.New("upstream down")}, true, newAnswerCache(10, time.Hour))
	w := &mockResponseWriter{}
	e.forwardUpstream(w, q, "nostale.com")

	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when no stale entry exists, got %+v", w.msg)
	}
}

func TestForwardUpstream_CachesOnSuccess(t *testing.T) {
	q := newTestQuery("cacheme.com")
	resp := answerMsg(q, "5.6.7.8", 60)
	c := newAnswerCache(10, time.Hour)
	e := staleEngine(&mockExchanger{resp: resp}, true, c)
	w := &mockResponseWriter{}
	e.forwardUpstream(w, q, "cacheme.com")

	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected the live answer to be written, got %+v", w.msg)
	}
	if _, ok := c.GetStale(cacheKey(q.Question[0])); !ok {
		t.Error("successful answer should have been cached for future serve-stale")
	}
}
