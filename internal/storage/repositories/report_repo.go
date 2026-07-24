// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"sort"
	"time"

	"github.com/lopster568/phantomDNS/internal/report"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// Aggregate computes the period aggregates the reporting engine needs from the
// DNS query log for the window [from, to] (inclusive). Blocked-category counts
// are derived by matching blocked domains against the blocklist entries that
// carry a category, so the query log itself does not need a category column.
//
// It satisfies report.Aggregator.
func (r *GormQueryLogRepo) Aggregate(from, to time.Time, topN int) (report.Aggregates, error) {
	if topN <= 0 {
		topN = 5
	}
	var agg report.Aggregates

	// Totals.
	if err := r.db.Model(&models.DNSQuery{}).
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Count(&agg.TotalQueries).Error; err != nil {
		return report.Aggregates{}, err
	}
	if err := r.db.Model(&models.DNSQuery{}).
		Where("action = ? AND timestamp >= ? AND timestamp <= ?", "block", from, to).
		Count(&agg.BlockedQueries).Error; err != nil {
		return report.Aggregates{}, err
	}
	if err := r.db.Model(&models.DNSQuery{}).
		Where("action = ? AND timestamp >= ? AND timestamp <= ?", "allow", from, to).
		Count(&agg.AllowedQueries).Error; err != nil {
		return report.Aggregates{}, err
	}
	// Threats blocked: blocked lookups flagged as suspicious.
	if err := r.db.Model(&models.DNSQuery{}).
		Where("action = ? AND is_suspicious = ? AND timestamp >= ? AND timestamp <= ?", "block", true, from, to).
		Count(&agg.ThreatsBlocked).Error; err != nil {
		return report.Aggregates{}, err
	}

	// Blocked domains with counts (all of them; we roll up categories in Go
	// and slice the top-N for domains).
	type domainRow struct {
		Domain string
		Count  int64
	}
	var blockedRows []domainRow
	if err := r.db.Model(&models.DNSQuery{}).
		Select("domain, count(*) as count").
		Where("action = ? AND timestamp >= ? AND timestamp <= ?", "block", from, to).
		Group("domain").
		Find(&blockedRows).Error; err != nil {
		return report.Aggregates{}, err
	}

	sort.SliceStable(blockedRows, func(i, j int) bool {
		if blockedRows[i].Count != blockedRows[j].Count {
			return blockedRows[i].Count > blockedRows[j].Count
		}
		return blockedRows[i].Domain < blockedRows[j].Domain
	})
	for i, row := range blockedRows {
		if i >= topN {
			break
		}
		agg.TopBlockedDomains = append(agg.TopBlockedDomains, report.DomainCount{
			Domain: row.Domain,
			Count:  row.Count,
		})
	}

	// Categories: map each blocked domain to a blocklist category (if any),
	// then sum block counts per category.
	if len(blockedRows) > 0 {
		domains := make([]string, 0, len(blockedRows))
		for _, row := range blockedRows {
			domains = append(domains, row.Domain)
		}
		var entries []models.BlocklistEntry
		if err := r.db.
			Where("domain IN ? AND category <> ''", domains).
			Find(&entries).Error; err != nil {
			return report.Aggregates{}, err
		}
		catByDomain := make(map[string]string, len(entries))
		for _, e := range entries {
			if _, ok := catByDomain[e.Domain]; !ok {
				catByDomain[e.Domain] = e.Category
			}
		}
		catCounts := make(map[string]int64)
		for _, row := range blockedRows {
			if cat, ok := catByDomain[row.Domain]; ok {
				catCounts[cat] += row.Count
			}
		}
		cats := make([]report.CategoryCount, 0, len(catCounts))
		for cat, cnt := range catCounts {
			cats = append(cats, report.CategoryCount{Category: cat, Count: cnt})
		}
		sort.SliceStable(cats, func(i, j int) bool {
			if cats[i].Count != cats[j].Count {
				return cats[i].Count > cats[j].Count
			}
			return cats[i].Category < cats[j].Category
		})
		if len(cats) > topN {
			cats = cats[:topN]
		}
		agg.TopBlockedCategories = cats
	}

	// Notable events: the highest-scoring suspicious lookups in the window.
	var events []models.DNSQuery
	if err := r.db.
		Where("is_suspicious = ? AND timestamp >= ? AND timestamp <= ?", true, from, to).
		Order("threat_score desc, timestamp desc").
		Limit(topN).
		Find(&events).Error; err != nil {
		return report.Aggregates{}, err
	}
	for _, e := range events {
		reason := e.ThreatReason
		if reason == "" {
			reason = e.DetectionMethod
		}
		agg.NotableEvents = append(agg.NotableEvents, report.Event{
			Timestamp:   e.Timestamp,
			Domain:      e.Domain,
			ClientIP:    e.ClientIP,
			Reason:      reason,
			ThreatScore: e.ThreatScore,
			Blocked:     e.Action == "block",
		})
	}

	return agg, nil
}
