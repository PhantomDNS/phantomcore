// DNS 0x20 encoding (case-randomization) for outbound upstream queries.
// See draft-vixie-dnsext-dns0x20-00: randomly flipping the case of the ASCII
// letters in the QNAME adds entropy that an off-path spoofer must also guess,
// while remaining transparent because DNS name matching is case-insensitive.
// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"math/rand"
	"strings"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

// randomizeCase applies DNS 0x20 encoding to name: it randomly flips the case
// of each ASCII letter, leaving digits, dots, hyphens and every other byte
// untouched. It is a pure function of (name, r), so seeding r makes the result
// deterministic for tests. The returned string always lower-cases to the same
// value as name (only case changes).
func randomizeCase(name string, r *rand.Rand) string {
	b := []byte(name)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 'a' && c <= 'z':
			if r.Intn(2) == 1 {
				b[i] = c - 0x20 // to upper
			}
		case c >= 'A' && c <= 'Z':
			if r.Intn(2) == 1 {
				b[i] = c + 0x20 // to lower
			}
		}
	}
	return string(b)
}

// equalNameFold reports whether two DNS names are equal ignoring ASCII case.
// It is the case-insensitive match used to validate that an upstream echoed the
// question name we sent (it always should, even after 0x20 randomization).
func equalNameFold(a, b string) bool {
	return strings.EqualFold(a, b)
}

// encodeCase0x20 returns a copy of q whose question names have been case-
// randomized, together with the original (client-requested) names indexed by
// question so the response can be restored later. The input q is not modified.
func encodeCase0x20(q *dns.Msg, r *rand.Rand) (*dns.Msg, []string) {
	out := q.Copy()
	originals := make([]string, len(out.Question))
	for i := range out.Question {
		originals[i] = out.Question[i].Name
		out.Question[i].Name = randomizeCase(out.Question[i].Name, r)
	}
	return out, originals
}

// restoreCase0x20 rewrites resp in place so the client sees the exact case it
// requested. For each question it verifies the upstream echoed the name case-
// insensitively (the anti-spoofing check); on a match it restores the original
// name in the question and in any RR owner names equal to the question name.
// A mismatch is logged and left untouched.
func restoreCase0x20(resp *dns.Msg, originals []string) {
	if resp == nil {
		return
	}
	for i := range resp.Question {
		if i >= len(originals) {
			break
		}
		echoed := resp.Question[i].Name
		if !equalNameFold(echoed, originals[i]) {
			logger.Log.Warnf("0x20: upstream echoed mismatched question name: got %q, want (case-insensitive) %q", echoed, originals[i])
			continue
		}
		resp.Question[i].Name = originals[i]
		restoreOwnerNames(resp.Answer, originals[i])
		restoreOwnerNames(resp.Ns, originals[i])
		restoreOwnerNames(resp.Extra, originals[i])
	}
}

// restoreOwnerNames restores the original case of any RR whose owner name
// matches original case-insensitively (i.e. the query name echoed back).
// Other names in the record set (e.g. CNAME targets) are left untouched.
func restoreOwnerNames(rrs []dns.RR, original string) {
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		if equalNameFold(h.Name, original) {
			h.Name = original
		}
	}
}
