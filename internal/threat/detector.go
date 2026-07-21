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
)

// Result contains the detection output for a domain.
type Result struct {
	IsSuspicious    bool    `json:"is_suspicious"`
	ThreatScore     float64 `json:"threat_score"`     // 0.0 to 1.0
	DetectionMethod string  `json:"detection_method"` // e.g. "entropy", "dga_pattern", "length"
	Reason          string  `json:"reason"`
}

// Detector performs heuristic threat analysis on domain names.
type Detector struct {
	entropyThreshold float64
	lengthThreshold  int
}

// NewDetector creates a detector with sensible defaults.
func NewDetector() *Detector {
	return &Detector{
		entropyThreshold: 3.7, // high entropy = random-looking = suspicious
		lengthThreshold:  50,  // very long domains are often DGA
	}
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

	// Run detectors in order of confidence
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
