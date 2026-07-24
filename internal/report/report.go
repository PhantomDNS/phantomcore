// SPDX-License-Identifier: GPL-3.0-or-later

// Package report builds plain-language period reports (weekly, trial, annual)
// from the DNS query log and statistics stored by HydraDNS. It turns raw
// aggregates into a friendly, non-technical summary that a school admin or SMB
// owner can read at a glance ("This week we blocked 41,300 ads and 218 malware
// attempts").
//
// The aggregation is done by an Aggregator (implemented by the query-log
// repository); this package only shapes and renders the result, so it depends
// on nothing but the standard library.
package report

import (
	"sort"
	"time"
)

// Period classifies the length of a report window.
type Period string

const (
	PeriodWeekly Period = "weekly"
	PeriodTrial  Period = "trial"
	PeriodAnnual Period = "annual"
)

// defaultTopN is how many domains, categories and notable events a report
// surfaces. Kept small so the summary stays readable.
const defaultTopN = 5

// DomainCount is a blocked domain and how often it was blocked in the window.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// CategoryCount is a blocked category and its total block count in the window.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// Event is a notable (suspicious) lookup worth calling out in the report.
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	Domain      string    `json:"domain"`
	ClientIP    string    `json:"client_ip"`
	Reason      string    `json:"reason"`
	ThreatScore float64   `json:"threat_score"`
	Blocked     bool      `json:"blocked"`
}

// Aggregates is the raw, pre-rendered result the Aggregator produces for a
// window. Generate turns it into a Report.
type Aggregates struct {
	TotalQueries         int64
	BlockedQueries       int64
	AllowedQueries       int64
	ThreatsBlocked       int64
	TopBlockedDomains    []DomainCount
	TopBlockedCategories []CategoryCount
	NotableEvents        []Event
}

// Aggregator produces the aggregates for a time window. topN bounds how many
// top domains / categories / events to return. The query-log repository
// implements this interface.
type Aggregator interface {
	Aggregate(from, to time.Time, topN int) (Aggregates, error)
}

// Report is the fully-shaped, render-ready period report.
type Report struct {
	Period      Period    `json:"period"`
	PeriodLabel string    `json:"period_label"` // friendly phrase, e.g. "this week"
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	GeneratedAt time.Time `json:"generated_at"`

	TotalQueries     int64   `json:"total_queries"`
	BlockedQueries   int64   `json:"blocked_queries"`
	AllowedQueries   int64   `json:"allowed_queries"`
	ThreatsBlocked   int64   `json:"threats_blocked"`
	AdsAndTrackers   int64   `json:"ads_and_trackers"` // blocked that were not threats
	BlockRatePercent float64 `json:"block_rate_percent"`

	TopBlockedDomains    []DomainCount   `json:"top_blocked_domains"`
	TopBlockedCategories []CategoryCount `json:"top_blocked_categories"`
	NotableEvents        []Event         `json:"notable_events"`
}

// Generate builds a Report for the window [from, to] using the aggregates from
// repo. An empty window (no queries) yields a valid, zeroed Report rather than
// an error.
func Generate(repo Aggregator, from, to time.Time) (Report, error) {
	if repo == nil {
		return Report{}, errNilRepo
	}

	agg, err := repo.Aggregate(from, to, defaultTopN)
	if err != nil {
		return Report{}, err
	}

	period, label := classifyPeriod(from, to)

	var blockRate float64
	if agg.TotalQueries > 0 {
		blockRate = float64(agg.BlockedQueries) / float64(agg.TotalQueries) * 100
	}

	ads := agg.BlockedQueries - agg.ThreatsBlocked
	if ads < 0 {
		ads = 0
	}

	// Defensive: keep the surfaced lists sorted and bounded even if the
	// Aggregator returned them unsorted.
	domains := append([]DomainCount(nil), agg.TopBlockedDomains...)
	sort.SliceStable(domains, func(i, j int) bool {
		if domains[i].Count != domains[j].Count {
			return domains[i].Count > domains[j].Count
		}
		return domains[i].Domain < domains[j].Domain
	})
	if len(domains) > defaultTopN {
		domains = domains[:defaultTopN]
	}

	categories := append([]CategoryCount(nil), agg.TopBlockedCategories...)
	sort.SliceStable(categories, func(i, j int) bool {
		if categories[i].Count != categories[j].Count {
			return categories[i].Count > categories[j].Count
		}
		return categories[i].Category < categories[j].Category
	})
	if len(categories) > defaultTopN {
		categories = categories[:defaultTopN]
	}

	return Report{
		Period:               period,
		PeriodLabel:          label,
		From:                 from,
		To:                   to,
		GeneratedAt:          time.Now().UTC(),
		TotalQueries:         agg.TotalQueries,
		BlockedQueries:       agg.BlockedQueries,
		AllowedQueries:       agg.AllowedQueries,
		ThreatsBlocked:       agg.ThreatsBlocked,
		AdsAndTrackers:       ads,
		BlockRatePercent:     blockRate,
		TopBlockedDomains:    domains,
		TopBlockedCategories: categories,
		NotableEvents:        agg.NotableEvents,
	}, nil
}

// classifyPeriod maps a window duration to a Period and a friendly phrase.
// The thresholds are deliberately loose: a report window is rarely exact.
func classifyPeriod(from, to time.Time) (Period, string) {
	d := to.Sub(from)
	switch {
	case d <= 8*24*time.Hour:
		return PeriodWeekly, "this week"
	case d <= 45*24*time.Hour:
		return PeriodTrial, "your trial period"
	default:
		return PeriodAnnual, "this year"
	}
}
