// Package threat implements heuristic-based suspicious domain detection.
// It uses domain entropy scoring and DGA (Domain Generation Algorithm) pattern
// detection to flag domains that may be malicious even if they're not on any blocklist.
package threat

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Result contains the detection output for a domain.
type Result struct {
	IsSuspicious    bool    `json:"is_suspicious"`
	ThreatScore     float64 `json:"threat_score"`     // 0.0 to 1.0
	DetectionMethod string  `json:"detection_method"` // e.g. "entropy", "dga_pattern", "length", "typosquat"
	Reason          string  `json:"reason"`
	// Block indicates the caller should block (not merely flag) this domain.
	// Only set for typosquat hits when the detector is configured to block.
	Block bool `json:"block,omitempty"`
}

// brandEntry is a precomputed protected brand used for typosquat comparison.
type brandEntry struct {
	domain string // full registrable domain, lowercased, e.g. "paypal.com"
	label  string // registrable label (SLD), lowercased, e.g. "paypal"
	tld    string // public-suffix portion, e.g. "com" or "co.uk"
}

// Detector performs heuristic threat analysis on domain names.
type Detector struct {
	entropyThreshold float64
	lengthThreshold  int

	// Typosquat / homoglyph detection against a protected-brand watchlist.
	// Empty brands => the check is a no-op (feature OFF by default).
	brands          []brandEntry
	typoMaxDistance int  // max Damerau/Levenshtein distance to flag (registrable label)
	blockTyposquat  bool // when true, typosquat hits are marked to block, not just flag
}

// NewDetector creates a detector with sensible defaults and no protected brands.
func NewDetector() *Detector {
	return NewDetectorWithBrands(nil)
}

// NewDetectorWithBrands creates a detector configured with a typosquat watchlist.
// brands is a list of protected registrable domains (e.g. "paypal.com").
// An empty/nil list leaves typosquat detection OFF; all other heuristics run
// exactly as before.
func NewDetectorWithBrands(brands []string) *Detector {
	return &Detector{
		entropyThreshold: 3.7, // high entropy = random-looking = suspicious
		lengthThreshold:  50,  // very long domains are often DGA
		brands:           normalizeBrands(brands),
		typoMaxDistance:  2,
	}
}

// SetTyposquatBlock controls whether typosquat hits are marked to block
// (Result.Block == true) instead of only flagged as suspicious.
func (d *Detector) SetTyposquatBlock(block bool) {
	d.blockTyposquat = block
}

// Analyze runs all heuristics on a normalized domain name and returns a result.
func (d *Detector) Analyze(domain string) Result {
	// Strip TLD for analysis (focus on the subdomain/SLD parts)
	parts := strings.Split(domain, ".")
	if len(parts) <= 1 {
		return Result{} // bare TLD, not suspicious
	}

	// Analyze the registrable part (everything except the TLD)
	// For "abc123xyz.evil.com", analyze "abc123xyz.evil"
	analysisTarget := strings.Join(parts[:len(parts)-1], ".")
	if len(parts) >= 3 {
		// For deeply nested subdomains, focus on longest non-TLD label
		analysisTarget = longestLabel(parts[:len(parts)-1])
	}

	// Run detectors in order of confidence. Typosquat runs first so a
	// watchlist lookalike is reported as "typosquat" rather than being masked
	// by a generic heuristic. It is a no-op when no brands are configured.
	if r := d.checkTyposquat(domain); r.IsSuspicious {
		return r
	}
	if r := d.checkDGAPattern(analysisTarget, domain); r.IsSuspicious {
		return r
	}
	if r := d.checkEntropy(analysisTarget, domain); r.IsSuspicious {
		return r
	}
	if r := d.checkLength(domain); r.IsSuspicious {
		return r
	}
	if r := d.checkExcessiveSubdomains(domain); r.IsSuspicious {
		return r
	}

	return Result{}
}

// checkEntropy measures Shannon entropy of the domain label.
// Random/DGA domains have high entropy (>3.7 for short labels).
func (d *Detector) checkEntropy(label, domain string) Result {
	if len(label) < 6 {
		return Result{} // too short for meaningful entropy
	}

	entropy := shannonEntropy(label)

	// Adjust threshold based on label length — longer labels naturally have higher entropy
	threshold := d.entropyThreshold
	if len(label) > 20 {
		threshold = 3.5
	}

	if entropy > threshold {
		score := math.Min((entropy-threshold)/(4.5-threshold), 1.0)
		return Result{
			IsSuspicious:    true,
			ThreatScore:     score,
			DetectionMethod: "entropy",
			Reason:          "high entropy domain (randomness score: " + formatFloat(entropy) + ")",
		}
	}
	return Result{}
}

// checkDGAPattern detects domains that match common DGA patterns:
// - Long hex strings (malware C2)
// - Alternating consonant-vowel with digits (algorithmic generation)
// - Base64-like patterns
var (
	// Require 16+ hex chars (shorter ones match too many CDN distribution IDs)
	hexPattern    = regexp.MustCompile(`^[0-9a-f]{16,}$`)
	dgaMixPattern = regexp.MustCompile(`^[a-z]{2,4}\d[a-z]{2,4}\d[a-z]*\d?$`)
	// Require actual base64 indicators (+ or / or trailing =), not just long alphanumeric
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]*[+/=][A-Za-z0-9+/=]{15,}$`)
)

// Known infrastructure TLDs that produce hex-like labels
var infraDomains = map[string]bool{
	"cloudfront.net":    true,
	"amazonaws.com":     true,
	"akamaihd.net":      true,
	"akamaized.net":     true,
	"sentry.io":         true,
	"fastly.net":        true,
	"cloudflare.com":    true,
	"azurewebsites.net": true,
}

func isInfraDomain(domain string) bool {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if infraDomains[suffix] {
			return true
		}
	}
	return false
}

func (d *Detector) checkDGAPattern(label, domain string) Result {
	// Skip known CDN/infrastructure domains
	if isInfraDomain(domain) {
		return Result{}
	}

	lower := strings.ToLower(label)

	if hexPattern.MatchString(lower) {
		return Result{
			IsSuspicious:    true,
			ThreatScore:     0.9,
			DetectionMethod: "dga_hex",
			Reason:          "hexadecimal domain pattern (possible C2 beacon)",
		}
	}

	if dgaMixPattern.MatchString(lower) && len(lower) > 10 {
		return Result{
			IsSuspicious:    true,
			ThreatScore:     0.7,
			DetectionMethod: "dga_pattern",
			Reason:          "algorithmic domain pattern (possible DGA)",
		}
	}

	if base64Pattern.MatchString(label) {
		return Result{
			IsSuspicious:    true,
			ThreatScore:     0.8,
			DetectionMethod: "dga_base64",
			Reason:          "base64-encoded domain pattern (possible data exfiltration)",
		}
	}

	// Check for excessive digit ratio in labels
	digitCount := 0
	for _, c := range lower {
		if unicode.IsDigit(c) {
			digitCount++
		}
	}
	if len(lower) > 8 && float64(digitCount)/float64(len(lower)) > 0.5 {
		return Result{
			IsSuspicious:    true,
			ThreatScore:     0.6,
			DetectionMethod: "dga_digits",
			Reason:          "high digit ratio in domain (possible DGA)",
		}
	}

	return Result{}
}

// checkLength flags very long domains (often used for DNS tunneling/exfiltration).
func (d *Detector) checkLength(domain string) Result {
	if len(domain) > d.lengthThreshold {
		score := math.Min(float64(len(domain)-d.lengthThreshold)/50.0, 1.0)
		return Result{
			IsSuspicious:    true,
			ThreatScore:     score,
			DetectionMethod: "length",
			Reason:          "unusually long domain name (possible DNS tunneling)",
		}
	}
	return Result{}
}

// checkExcessiveSubdomains flags domains with many subdomain levels (>4).
func (d *Detector) checkExcessiveSubdomains(domain string) Result {
	parts := strings.Split(domain, ".")
	if len(parts) > 5 {
		return Result{
			IsSuspicious:    true,
			ThreatScore:     0.5,
			DetectionMethod: "subdomain_depth",
			Reason:          "excessive subdomain depth (possible DNS tunneling)",
		}
	}
	return Result{}
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(utf8.RuneCountInString(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func longestLabel(labels []string) string {
	longest := ""
	for _, l := range labels {
		if len(l) > len(longest) {
			longest = l
		}
	}
	return longest
}

func formatFloat(f float64) string {
	s := fmt.Sprintf("%.2f", f)
	return s
}

// --- Typosquat / homoglyph detection -----------------------------------------

// twoLevelTLDs is a small set of common two-label public suffixes so the
// registrable label (SLD) is extracted correctly (e.g. "foo" in "foo.co.uk").
// It is intentionally not exhaustive; unknown suffixes fall back to the last
// two labels, which is correct for the overwhelming majority of TLDs.
var twoLevelTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.in": true, "co.jp": true, "co.kr": true, "co.za": true,
	"com.au": true, "net.au": true, "org.au": true,
	"com.br": true, "com.cn": true, "com.sg": true, "com.mx": true, "com.tr": true,
}

// confusables maps visually-confusable runes to their Latin ASCII skeleton.
// It covers digit lookalikes, a capital that mimics a lowercase letter, and
// the common Latin-lookalike Cyrillic/Greek letters used in homograph attacks.
// Runes not present here fall through to unicode.ToLower.
var confusables = map[rune]string{
	// digit -> letter lookalikes
	'0': "o", '1': "l", '3': "e", '4': "a", '5': "s",
	// capital that mimics a lowercase letter
	'I': "l",
	// Cyrillic -> Latin (lowercase)
	'а': "a", 'е': "e", 'о': "o", 'р': "p", 'с': "c",
	'х': "x", 'у': "y", 'і': "i", 'ѕ': "s", 'ԁ': "d",
	'к': "k", 'г': "r",
	// Cyrillic capitals -> Latin (lowercase)
	'А': "a", 'Е': "e", 'О': "o", 'Р': "p", 'С': "c",
	'Х': "x", 'В': "b", 'М': "m", 'Н': "h", 'Т': "t",
	// Greek -> Latin (lowercase)
	'ο': "o", 'α': "a", 'ν': "v", 'ρ': "p", 'ι': "i",
	'κ': "k", 'μ': "u",
}

// confusableSkeleton reduces a label to a lowercase ASCII "skeleton" by mapping
// confusable runes to their Latin equivalents. This is what lets "paypa1",
// "paypaI" and the Cyrillic "pаypal" all collapse to "paypal".
func confusableSkeleton(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if repl, ok := confusables[r]; ok {
			b.WriteString(repl)
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// decodePunycodeDomain decodes IDN (xn--) labels to their Unicode form so
// homograph attacks encoded as punycode can be normalized. On any decode error
// the original domain is returned unchanged.
func decodePunycodeDomain(domain string) string {
	if !strings.Contains(domain, "xn--") {
		return domain
	}
	if u, err := idna.Punycode.ToUnicode(domain); err == nil {
		return u
	}
	return domain
}

// registrableParts returns the registrable label (SLD) and public-suffix
// portion of a domain, e.g. ("paypal", "com") or ("foo", "co.uk"). The label
// preserves its original case (needed to catch capital-letter homoglyphs); the
// tld is lowercased. Returns empty strings when there is no registrable label.
func registrableParts(domain string) (label, tld string) {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", ""
	}
	if len(parts) >= 3 {
		lastTwo := strings.ToLower(parts[len(parts)-2] + "." + parts[len(parts)-1])
		if twoLevelTLDs[lastTwo] {
			return parts[len(parts)-3], lastTwo
		}
	}
	return parts[len(parts)-2], strings.ToLower(parts[len(parts)-1])
}

// normalizeBrands turns raw watchlist entries into precomputed brand entries,
// dropping blanks and anything without a registrable label.
func normalizeBrands(brands []string) []brandEntry {
	var out []brandEntry
	for _, raw := range brands {
		b := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(raw)), ".")
		if b == "" {
			continue
		}
		label, tld := registrableParts(b)
		if label == "" || tld == "" {
			continue
		}
		out = append(out, brandEntry{
			domain: label + "." + tld,
			label:  label,
			tld:    tld,
		})
	}
	return out
}

// checkTyposquat flags a domain that is a near-lookalike of a protected brand
// on the watchlist. It decodes punycode, applies confusable/homoglyph
// normalization, and compares the registrable label to each brand using
// Damerau/Levenshtein edit distance. The exact brand (and its subdomains) is
// never flagged. No-op when the watchlist is empty.
func (d *Detector) checkTyposquat(domain string) Result {
	if len(d.brands) == 0 {
		return Result{}
	}
	// Preserve the existing CDN/infrastructure allowlist behaviour.
	if isInfraDomain(domain) {
		return Result{}
	}

	decoded := decodePunycodeDomain(domain)
	label, tld := registrableParts(decoded)
	if label == "" {
		return Result{}
	}
	fullReg := strings.ToLower(label) + "." + tld
	lowerLabel := strings.ToLower(label)
	skel := confusableSkeleton(label)
	if skel == "" {
		return Result{}
	}

	for _, b := range d.brands {
		// Never flag the exact brand itself (or its subdomains, which share the
		// registrable domain).
		if fullReg == b.domain {
			continue
		}

		if skel == b.label {
			// Skeleton collapses onto the brand. If the raw ASCII label already
			// equals the brand label this is just a different TLD (not a
			// lookalike) — skip it. Otherwise it is a confusable/homoglyph.
			if lowerLabel != b.label {
				return d.typosquatResult(domain, b.domain, "homoglyph/confusable lookalike")
			}
			continue
		}

		dist := damerauLevenshtein(skel, b.label)
		if dist >= 1 && dist <= d.typoMaxDistance {
			return d.typosquatResult(domain, b.domain, fmt.Sprintf("edit distance %d from brand label", dist))
		}
	}
	return Result{}
}

func (d *Detector) typosquatResult(domain, brand, why string) Result {
	return Result{
		IsSuspicious:    true,
		ThreatScore:     0.85,
		DetectionMethod: "typosquat",
		Reason:          fmt.Sprintf("lookalike of protected brand %q (%s)", brand, why),
		Block:           d.blockTyposquat,
	}
}

// damerauLevenshtein returns the optimal string alignment (Damerau/Levenshtein)
// edit distance between a and b, counting insertions, deletions, substitutions
// and adjacent transpositions each as a single edit.
func damerauLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := prev2[j-2] + 1; t < curr[j] {
					curr[j] = t
				}
			}
		}
		prev2, prev, curr = prev, curr, prev2
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
