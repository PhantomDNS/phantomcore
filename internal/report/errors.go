// SPDX-License-Identifier: GPL-3.0-or-later
package report

import "errors"

// errNilRepo is returned by Generate when no Aggregator is supplied.
var errNilRepo = errors.New("report: nil aggregator")
