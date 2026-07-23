// SPDX-License-Identifier: GPL-3.0-or-later

// Package telemetry is the REFERENCE IMPLEMENTATION of the LOCAL_ONLY custody
// contract for non-resolution outbound ("phone-home") features.
//
// It performs a representative off-box report. Because that is NOT part of DNS
// resolution or filtering, every outbound path here first consults
// config.AssertLocalOnlyRespected and no-ops when custody mode is engaged.
// New phone-home features (update checks, crash reporting, managed config,
// heartbeats — some of which live on other branches) should follow this exact
// gating pattern.
package telemetry

import (
	"context"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"
)

// SendFunc performs the actual outbound request. It is a field so tests can
// observe whether an outbound attempt was made; in production it POSTs the
// event to the configured telemetry endpoint.
type SendFunc func(ctx context.Context, event string) error

// Reporter is a representative non-resolution outbound feature.
type Reporter struct {
	// send performs the real network call. If nil, Report is a no-op even when
	// custody mode is off.
	send SendFunc
}

// NewReporter builds a Reporter with the given outbound sender.
func NewReporter(send SendFunc) *Reporter {
	return &Reporter{send: send}
}

// Report sends a telemetry event off-box.
//
// It honors the LOCAL_ONLY custody contract: when custody mode is engaged the
// method makes NO outbound request and returns nil (a successful no-op). This
// is the canonical shape every phone-home feature must copy.
func (r *Reporter) Report(ctx context.Context, event string) error {
	if !config.AssertLocalOnlyRespected("telemetry.Report") {
		// Custody mode: do not touch the network.
		return nil
	}
	if r.send == nil {
		logger.Log.Debug("telemetry: no sender configured; skipping report")
		return nil
	}
	return r.send(ctx, event)
}
