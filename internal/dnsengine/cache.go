// Bounded LRU response cache used to serve stale answers when the upstream
// is unavailable (serve-stale). It is only populated and consulted when the
// serve-stale feature is enabled, so the normal hot path is unchanged by default.
// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"container/list"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultCacheSize bounds the number of cached answers (TTL LRU).
	defaultCacheSize = 20000
	// defaultStaleFor is how long past its TTL an entry is retained and may be
	// served as a stale fallback.
	defaultStaleFor = time.Hour
	// staleTTL is the (low) TTL, in seconds, stamped onto a stale answer so
	// clients re-query soon once the upstream is expected to recover.
	staleTTL = 30
)

// cacheEntry is a cached DNS answer plus the instant its fresh TTL expires.
type cacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

// reply builds a response for r from the stored answer, clamping record TTLs to
// ttl (seconds) so a stale answer is not cached long by downstream clients.
func (ce *cacheEntry) reply(r *dns.Msg, ttl uint32) *dns.Msg {
	m := ce.msg.Copy()
	m.Id = r.Id
	m.Response = true
	m.Question = r.Question
	setTTL(m.Answer, ttl)
	setTTL(m.Ns, ttl)
	return m
}

func setTTL(rrs []dns.RR, ttl uint32) {
	for _, rr := range rrs {
		if rr != nil {
			rr.Header().Ttl = ttl
		}
	}
}

type lruItem struct {
	key   string
	entry *cacheEntry
}

// answerCache is a mutex-guarded, size-bounded LRU that retains entries a
// bounded time past their TTL so they can be served as a stale fallback.
type answerCache struct {
	mu       sync.Mutex
	max      int
	staleFor time.Duration
	ll       *list.List
	items    map[string]*list.Element
	// now is injectable for deterministic testing; defaults to time.Now.
	now func() time.Time
}

func newAnswerCache(max int, staleFor time.Duration) *answerCache {
	if max <= 0 {
		max = defaultCacheSize
	}
	if staleFor <= 0 {
		staleFor = defaultStaleFor
	}
	return &answerCache{
		max:      max,
		staleFor: staleFor,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
		now:      time.Now,
	}
}

// cacheKey identifies a cached answer by question name (lowercased), type and class.
func cacheKey(q dns.Question) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(q.Name))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(q.Qtype)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(q.Qclass)))
	return b.String()
}

// minTTL returns the smallest TTL across the answer section, or 0 if there are
// no answer records (in which case the response is not worth caching for stale use).
func minTTL(msg *dns.Msg) uint32 {
	var min uint32
	first := true
	for _, rr := range msg.Answer {
		t := rr.Header().Ttl
		if first || t < min {
			min = t
			first = false
		}
	}
	if first {
		return 0
	}
	return min
}

// Put stores a copy of msg keyed by key, with its expiry derived from the answer
// TTL. Responses with no answer records are ignored. Evicts the least-recently
// used entry when over capacity.
func (c *answerCache) Put(key string, msg *dns.Msg) {
	ttl := minTTL(msg)
	if ttl == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ent := &cacheEntry{
		msg:       msg.Copy(),
		expiresAt: c.now().Add(time.Duration(ttl) * time.Second),
	}
	if el, ok := c.items[key]; ok {
		el.Value.(*lruItem).entry = ent
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruItem{key: key, entry: ent})
	c.items[key] = el
	if c.ll.Len() > c.max {
		c.evictOldest()
	}
}

func (c *answerCache) evictOldest() {
	el := c.ll.Back()
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*lruItem).key)
}

// Get returns a non-expired (fresh) entry, if present.
func (c *answerCache) Get(key string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	ent := el.Value.(*lruItem).entry
	if c.now().After(ent.expiresAt) {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return ent, true
}

// GetStale returns an entry usable as a stale fallback: present and within the
// stale retention window (its TTL may already have expired). Entries past the
// window are evicted and reported as a miss.
func (c *answerCache) GetStale(key string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	item := el.Value.(*lruItem)
	if c.now().After(item.entry.expiresAt.Add(c.staleFor)) {
		c.ll.Remove(el)
		delete(c.items, item.key)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return item.entry, true
}
