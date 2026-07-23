// SPDX-License-Identifier: GPL-3.0-or-later
package promexport

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRegistry builds a dedicated Prometheus registry wired to the DNS query
// collector plus the standard Go runtime and process collectors. A dedicated
// registry (rather than the global default) keeps the exposition deterministic
// and avoids duplicate-registration panics across processes/tests.
func NewRegistry(src Source) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		NewCollector(src),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return reg
}

// Handler returns an http.Handler serving the Prometheus exposition for src.
// Mount it at /metrics.
func Handler(src Source) http.Handler {
	return promhttp.HandlerFor(NewRegistry(src), promhttp.HandlerOpts{})
}
