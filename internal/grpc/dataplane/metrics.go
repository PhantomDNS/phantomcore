// SPDX-License-Identifier: GPL-3.0-or-later
package dataplane

import (
	"context"
	"time"

	"github.com/lopster568/phantomDNS/internal/dnsengine"
	pb "github.com/lopster568/phantomDNS/internal/gen/proto/phantomdns/v1"
	"github.com/lopster568/phantomDNS/internal/metrics"
	"google.golang.org/protobuf/types/known/emptypb"
)

type MetricsService struct {
	pb.UnimplementedDataPlaneMetricsServiceServer

	engine *dnsengine.Engine
}

func NewMetricsService(e *dnsengine.Engine) *MetricsService {
	return &MetricsService{engine: e}
}

func (s *MetricsService) GetLiveQueryMetrics(
	ctx context.Context,
	_ *emptypb.Empty,
) (*pb.LiveQueryMetrics, error) {

	agg := s.engine.Metrics().Aggregate()

	p50 := metrics.EstimatePercentile(agg.Buckets, 0.50)
	p95 := metrics.EstimatePercentile(agg.Buckets, 0.95)
	p99 := metrics.EstimatePercentile(agg.Buckets, 0.99)

	return &pb.LiveQueryMetrics{
		WindowSizeSeconds: uint64(5 * 60),

		TotalQueries: agg.Total,
		ErrorQueries: agg.Errors,

		P50Ms: durationMsToUint64(p50),
		P95Ms: durationMsToUint64(p95),
		P99Ms: durationMsToUint64(p99),
	}, nil
}

// durationMsToUint64 converts a duration (always non-negative here, since it
// comes from metrics.EstimatePercentile) to milliseconds as uint64, guarding
// against a negative value rather than assuming the caller's invariant holds.
func durationMsToUint64(d time.Duration) uint64 {
	ms := d.Milliseconds()
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}
