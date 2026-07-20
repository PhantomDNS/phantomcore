// SPDX-License-Identifier: GPL-3.0-or-later
//
// Optional DNSSEC validation of upstream responses (feature I-025).
//
// SCOPE (validated vs not):
//
//	Validated:
//	  - RRSIG signatures over each signed RRset present in the Answer section are
//	    cryptographically verified against the signer zone's DNSKEY RRset
//	    (RFC 4034/4035 §5.3), including RRSIG validity-period (inception/expiration)
//	    checks and KeyTag/Algorithm matching.
//	  - Answers whose signatures fail (tampered, expired, or wrong key) are BOGUS.
//	  - Answers with no signatures are treated as INSECURE and pass through unchanged.
//
//	NOT validated (documented follow-ups, out of scope here):
//	  - The DNSKEY RRset itself is not chained to the parent DS record nor to a root
//	    trust anchor. We validate answer RRSIGs against the DNSKEY served for the
//	    signer zone; full delegation-chain-to-root-anchor validation is a follow-up.
//	  - Negative responses (NXDOMAIN/NODATA) are not authenticated via NSEC/NSEC3.
//	  - If the DNSKEY RRset cannot be retrieved, the answer soft-fails to INSECURE
//	    (pass through) rather than SERVFAIL, to keep a partial validator from
//	    breaking resolution.
//
// The core classification logic below is pure and hermetically unit-tested with
// static, in-test signed fixtures (no live network, no live resolvers).
package dnsengine

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidationStatus is the DNSSEC validation outcome for a response.
type ValidationStatus int

const (
	// StatusInsecure means the answer carried no DNSSEC signatures (unsigned/insecure
	// zone), or nothing validatable was present. Such answers pass through unchanged.
	StatusInsecure ValidationStatus = iota
	// StatusSecure means at least one signed RRset in the answer verified against a
	// DNSKEY and no signed RRset failed. The answer passes through unchanged.
	StatusSecure
	// StatusBogus means the answer contained DNSSEC signatures but at least one signed
	// RRset failed validation (bad signature, wrong key, or outside its validity
	// period). Bogus answers are rejected with SERVFAIL.
	StatusBogus
)

func (s ValidationStatus) String() string {
	switch s {
	case StatusSecure:
		return "SECURE"
	case StatusBogus:
		return "BOGUS"
	default:
		return "INSECURE"
	}
}

// keyFetcher returns the DNSKEY RRset for a signer zone. The live implementation
// queries the upstream resolver; tests inject a hermetic stub.
type keyFetcher func(signer string) ([]*dns.DNSKEY, error)

// coveredRRSet is a group of Answer records sharing an owner name, type and class,
// together with the RRSIG record(s) that cover them.
type coveredRRSet struct {
	name   string
	rtype  uint16
	rrset  []dns.RR
	rrsigs []*dns.RRSIG
}

// groupSignedRRSets partitions the Answer section into RRsets and attaches the
// RRSIG(s) that cover each. RRsets with no covering RRSIG are still returned (with
// an empty rrsigs slice) so callers can distinguish "unsigned" from "absent".
func groupSignedRRSets(answer []dns.RR) []coveredRRSet {
	type key struct {
		name  string
		rtype uint16
		class uint16
	}
	order := make([]key, 0)
	sets := make(map[key]*coveredRRSet)
	var sigs []*dns.RRSIG

	for _, rr := range answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
			continue
		}
		h := rr.Header()
		k := key{strings.ToLower(h.Name), h.Rrtype, h.Class}
		cs, exists := sets[k]
		if !exists {
			cs = &coveredRRSet{name: h.Name, rtype: h.Rrtype}
			sets[k] = cs
			order = append(order, k)
		}
		cs.rrset = append(cs.rrset, rr)
	}

	for _, sig := range sigs {
		k := key{strings.ToLower(sig.Header().Name), sig.TypeCovered, sig.Header().Class}
		if cs, ok := sets[k]; ok {
			cs.rrsigs = append(cs.rrsigs, sig)
		}
	}

	out := make([]coveredRRSet, 0, len(order))
	for _, k := range order {
		out = append(out, *sets[k])
	}
	return out
}

// validateRRSet verifies the RRSIG(s) covering a single RRset against a candidate
// DNSKEY set at time now. It is the pure cryptographic heart of the validator.
//
//	StatusInsecure — no RRSIGs cover the RRset (unsigned).
//	StatusSecure   — at least one RRSIG is within its validity period AND verifies
//	                 against a DNSKEY whose KeyTag and Algorithm match.
//	StatusBogus    — RRSIGs exist but none validate (tampered, expired, or wrong key).
func validateRRSet(cs coveredRRSet, keys []*dns.DNSKEY, now time.Time) ValidationStatus {
	if len(cs.rrsigs) == 0 {
		return StatusInsecure
	}
	for _, sig := range cs.rrsigs {
		if !sig.ValidityPeriod(now) {
			continue // expired or not yet valid
		}
		for _, k := range keys {
			if k == nil || k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(k, cs.rrset); err == nil {
				return StatusSecure
			}
		}
	}
	return StatusBogus
}

// classifyResponse determines the DNSSEC status of resp's Answer section. It fetches
// the DNSKEY RRset for each distinct signer via fetch (cached per call) and returns
// the "worst" outcome: BOGUS if any signed RRset fails, SECURE if at least one signed
// RRset validates and none fail, INSECURE if nothing was signed (or keys were
// unavailable — see package scope note on soft-failing).
func classifyResponse(resp *dns.Msg, fetch keyFetcher, now time.Time) ValidationStatus {
	if resp == nil {
		return StatusInsecure
	}

	keyCache := make(map[string][]*dns.DNSKEY)
	sawSecure := false

	for _, g := range groupSignedRRSets(resp.Answer) {
		if len(g.rrsigs) == 0 {
			continue // unsigned RRset: nothing to prove here
		}

		signer := g.rrsigs[0].SignerName
		keys, cached := keyCache[signer]
		if !cached {
			fetched, err := fetch(signer)
			if err != nil || len(fetched) == 0 {
				// Keys unavailable: soft-fail to insecure rather than break
				// resolution for a partial validator (documented limitation).
				keyCache[signer] = nil
				continue
			}
			keys = fetched
			keyCache[signer] = keys
		}
		if keys == nil {
			continue
		}

		switch validateRRSet(g, keys, now) {
		case StatusBogus:
			return StatusBogus
		case StatusSecure:
			sawSecure = true
		}
	}

	if sawSecure {
		return StatusSecure
	}
	return StatusInsecure
}

// setDO ensures the DNSSEC OK (DO) bit is set on an outgoing query so upstream
// resolvers return RRSIG records. It preserves any existing EDNS0 OPT record.
func setDO(m *dns.Msg) {
	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo(true)
		if opt.UDPSize() < dns.MinMsgSize {
			opt.SetUDPSize(4096)
		}
		return
	}
	m.SetEdns0(4096, true)
}

// extractDNSKEYs pulls the DNSKEY records out of a DNSKEY response's Answer section.
func extractDNSKEYs(resp *dns.Msg) []*dns.DNSKEY {
	if resp == nil {
		return nil
	}
	var keys []*dns.DNSKEY
	for _, rr := range resp.Answer {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys
}
