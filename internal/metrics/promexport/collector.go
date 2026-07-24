// SPDX-License-Identifier: GPL-3.0-or-later

// Package promexport bridges the in-process QueryMetrics collected by the DNS
// engine into the Prometheus exposition format. It does not maintain a parallel
// set of counters: the collector reads QueryMetrics.Aggregate() on every scrape,
// so the values exposed on /metrics are exactly the values the engine already
// tracks.
package promexport

import (
	"strconv"

	"github.com/lopster568/phantomDNS/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "hydradns"

// Source is the read-through view the collector needs. It is satisfied by
// *metrics.QueryMetrics, but kept as an interface so the collector can be
// exercised in isolation.
type Source interface {
	Aggregate() metrics.AggregatedMetrics
}

// latencyQuantiles are the percentiles surfaced as gauges, matching the
// p50/p95/p99 already computed for the gRPC LiveQueryMetrics path.
var latencyQuantiles = []float64{0.50, 0.95, 0.99}

// Collector exposes DNS query metrics sourced from the engine's QueryMetrics.
type Collector struct {
	src Source

	queries         *prometheus.Desc
	errors          *prometheus.Desc
	latency         *prometheus.Desc
	queryLogDropped *prometheus.Desc
}

// NewCollector builds a Collector reading from src.
func NewCollector(src Source) *Collector {
	return &Collector{
		src: src,
		queries: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "dns", "queries_window"),
			"Total DNS queries observed within the rolling metrics window.",
			nil, nil,
		),
		errors: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "dns", "query_errors_window"),
			"DNS queries that resulted in an error within the rolling metrics window.",
			nil, nil,
		),
		latency: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "dns", "query_latency_seconds"),
			"Estimated DNS query latency percentiles over the rolling metrics window.",
			[]string{"quantile"}, nil,
		),
		queryLogDropped: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "dns", "querylog_dropped_total"),
			"Cumulative query log rows dropped because the bounded async writer's buffer was full.",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.queries
	ch <- c.errors
	ch <- c.latency
	ch <- c.queryLogDropped
}

// Collect implements prometheus.Collector. It reads a fresh aggregate from the
// engine's QueryMetrics on every scrape.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	agg := c.src.Aggregate()

	ch <- prometheus.MustNewConstMetric(c.queries, prometheus.GaugeValue, float64(agg.Total))
	ch <- prometheus.MustNewConstMetric(c.errors, prometheus.GaugeValue, float64(agg.Errors))
	ch <- prometheus.MustNewConstMetric(c.queryLogDropped, prometheus.CounterValue, float64(agg.QueryLogDropped))

	for _, q := range latencyQuantiles {
		d := metrics.EstimatePercentile(agg.Buckets, q)
		ch <- prometheus.MustNewConstMetric(
			c.latency,
			prometheus.GaugeValue,
			d.Seconds(),
			strconv.FormatFloat(q, 'g', -1, 64),
		)
	}
}
