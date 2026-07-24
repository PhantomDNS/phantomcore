// SPDX-License-Identifier: GPL-3.0-or-later
package report

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"
)

// RenderText renders a Report as a friendly, non-technical plain-text summary
// suitable for an email body or a printed page.
func RenderText(r Report) string {
	var b strings.Builder

	b.WriteString("HydraDNS Security Report\n")
	b.WriteString(r.PeriodLabel)
	b.WriteString(" (")
	b.WriteString(formatRange(r))
	b.WriteString(")\n\n")

	if r.TotalQueries == 0 {
		fmt.Fprintf(&b, "%s HydraDNS saw no DNS activity for this period, so there is nothing to report yet.\n",
			capitalize(r.PeriodLabel))
		fmt.Fprintf(&b, "\nGenerated %s.\n", r.GeneratedAt.Format("Jan 2, 2006 at 15:04 MST"))
		return b.String()
	}

	// Headline sentence, in plain language.
	fmt.Fprintf(&b, "%s HydraDNS answered %s DNS requests and blocked %s of them (%s%% of all traffic).\n",
		capitalize(r.PeriodLabel),
		humanizeInt(r.TotalQueries),
		humanizeInt(r.BlockedQueries),
		formatPercent(r.BlockRatePercent),
	)
	fmt.Fprintf(&b, "That includes %s ads and trackers and %s malware and phishing attempts stopped before they reached your network.\n",
		humanizeInt(r.AdsAndTrackers),
		humanizeInt(r.ThreatsBlocked),
	)

	if len(r.TopBlockedDomains) > 0 {
		b.WriteString("\nTop blocked domains:\n")
		for i, d := range r.TopBlockedDomains {
			fmt.Fprintf(&b, "  %d. %s — %s times\n", i+1, d.Domain, humanizeInt(d.Count))
		}
	}

	if len(r.TopBlockedCategories) > 0 {
		b.WriteString("\nTop blocked categories:\n")
		for i, c := range r.TopBlockedCategories {
			fmt.Fprintf(&b, "  %d. %s — %s\n", i+1, c.Category, humanizeInt(c.Count))
		}
	}

	if len(r.NotableEvents) > 0 {
		b.WriteString("\nNotable events:\n")
		for _, e := range r.NotableEvents {
			verb := "flagged"
			if e.Blocked {
				verb = "blocked"
			}
			reason := e.Reason
			if reason == "" {
				reason = "suspicious lookup"
			}
			fmt.Fprintf(&b, "  • %s — %s %s (threat score %.2f): %s\n",
				e.Timestamp.Format("Jan 2 15:04"), e.Domain, verb, e.ThreatScore, reason)
		}
	}

	fmt.Fprintf(&b, "\nGenerated %s.\n", r.GeneratedAt.Format("Jan 2, 2006 at 15:04 MST"))
	return b.String()
}

// reportHTMLTemplate is a minimal, self-contained HTML rendering. html/template
// escapes all interpolated values automatically.
var reportHTMLTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"humanize": humanizeInt,
	"percent":  formatPercent,
	"cap":      capitalize,
	"rangeOf":  formatRange,
	"score":    func(f float64) string { return fmt.Sprintf("%.2f", f) },
	"stamp":    func(r Report) string { return r.GeneratedAt.Format("Jan 2, 2006 at 15:04 MST") },
	"evtime":   func(e Event) string { return e.Timestamp.Format("Jan 2 15:04") },
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HydraDNS Security Report</title>
</head>
<body style="font-family: -apple-system, Arial, sans-serif; max-width: 640px; margin: 0 auto; color: #1a1a1a;">
<h1>HydraDNS Security Report</h1>
<p><strong>{{ cap .PeriodLabel }}</strong> ({{ rangeOf . }})</p>
{{- if eq .TotalQueries 0 }}
<p>{{ cap .PeriodLabel }} HydraDNS saw no DNS activity for this period, so there is nothing to report yet.</p>
{{- else }}
<p>{{ cap .PeriodLabel }} HydraDNS answered <strong>{{ humanize .TotalQueries }}</strong> DNS requests and blocked
<strong>{{ humanize .BlockedQueries }}</strong> of them ({{ percent .BlockRatePercent }}% of all traffic).</p>
<p>That includes <strong>{{ humanize .AdsAndTrackers }}</strong> ads and trackers and
<strong>{{ humanize .ThreatsBlocked }}</strong> malware and phishing attempts stopped before they reached your network.</p>
{{- if .TopBlockedDomains }}
<h2>Top blocked domains</h2>
<ol>
{{- range .TopBlockedDomains }}
<li>{{ .Domain }} — {{ humanize .Count }} times</li>
{{- end }}
</ol>
{{- end }}
{{- if .TopBlockedCategories }}
<h2>Top blocked categories</h2>
<ol>
{{- range .TopBlockedCategories }}
<li>{{ .Category }} — {{ humanize .Count }}</li>
{{- end }}
</ol>
{{- end }}
{{- if .NotableEvents }}
<h2>Notable events</h2>
<ul>
{{- range .NotableEvents }}
<li>{{ evtime . }} — {{ .Domain }} {{ if .Blocked }}blocked{{ else }}flagged{{ end }}
(threat score {{ score .ThreatScore }}){{ if .Reason }}: {{ .Reason }}{{ end }}</li>
{{- end }}
</ul>
{{- end }}
{{- end }}
<hr>
<p style="color: #888; font-size: 0.85em;">Generated {{ stamp . }}.</p>
</body>
</html>
`))

// RenderHTML renders a Report as a minimal, self-contained HTML page. All
// values are HTML-escaped by html/template.
func RenderHTML(r Report) string {
	var b strings.Builder
	// The template is static and the data is trusted-shaped; an error here
	// would indicate a programming bug, so fall back to the text rendering.
	if err := reportHTMLTemplate.Execute(&b, r); err != nil {
		return "<pre>" + template.HTMLEscapeString(RenderText(r)) + "</pre>"
	}
	return b.String()
}

// --- small formatting helpers (no external deps) ---

// humanizeInt formats n with thousands separators, e.g. 41300 -> "41,300".
func humanizeInt(n int64) string {
	neg := n < 0
	s := strconv.FormatInt(n, 10)
	if neg {
		s = s[1:]
	}
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}
	var out strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		out.WriteString(s[:pre])
		if len(s) > pre {
			out.WriteByte(',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		out.WriteString(s[i : i+3])
		if i+3 < len(s) {
			out.WriteByte(',')
		}
	}
	if neg {
		return "-" + out.String()
	}
	return out.String()
}

// formatPercent renders a percentage with one decimal place, e.g. "27.3".
func formatPercent(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

// capitalize upper-cases the first rune of s.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// formatRange renders the report window as "Jan 2 – Jan 9, 2006".
func formatRange(r Report) string {
	if r.From.Year() == r.To.Year() {
		return fmt.Sprintf("%s – %s", r.From.Format("Jan 2"), r.To.Format("Jan 2, 2006"))
	}
	return fmt.Sprintf("%s – %s", r.From.Format("Jan 2, 2006"), r.To.Format("Jan 2, 2006"))
}
