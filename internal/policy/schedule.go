// SPDX-License-Identifier: GPL-3.0-or-later
package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// weekdayByName maps lowercase day tokens (short or long form) to time.Weekday.
// Accepting both keeps the API forgiving for hand-written policy JSON and UI
// input alike.
var weekdayByName = map[string]time.Weekday{
	"sun": time.Sunday, "sunday": time.Sunday,
	"mon": time.Monday, "monday": time.Monday,
	"tue": time.Tuesday, "tues": time.Tuesday, "tuesday": time.Tuesday,
	"wed": time.Wednesday, "weds": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thur": time.Thursday, "thurs": time.Thursday, "thursday": time.Thursday,
	"fri": time.Friday, "friday": time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}

// compiledSchedule is the parsed, evaluation-ready form of a policy schedule.
// A nil *compiledSchedule means "always active" — no schedule was configured,
// which is the default (and the unchanged fast path for every existing policy).
type compiledSchedule struct {
	loc       *time.Location // resolved timezone; UTC when unset
	days      [7]bool        // indexed by time.Weekday; only consulted when hasDays
	hasDays   bool
	startMin  int // minutes since local midnight, [0,1440)
	endMin    int
	hasWindow bool
}

// hasSchedule reports whether the policy carries any schedule constraint. When
// false the policy is always active and skips all schedule work.
func (p *Policy) hasSchedule() bool {
	return strings.TrimSpace(p.StartTime) != "" ||
		strings.TrimSpace(p.EndTime) != "" ||
		len(p.ScheduleDays) > 0
}

// parseHHMM parses "HH:MM" into minutes since midnight in [0,1440).
func parseHHMM(s string) (int, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time %q, want HH:MM", s)
	}
	h, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour in time %q", s)
	}
	m, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute in time %q", s)
	}
	return h*60 + m, nil
}

// compileSchedule validates and precomputes a policy's schedule. It returns
// (nil, nil) when the policy has no schedule (always active). A non-nil error
// means the schedule is malformed and the policy should be rejected by callers
// before it is ever persisted or loaded into the engine.
func compileSchedule(p *Policy) (*compiledSchedule, error) {
	if !p.hasSchedule() {
		return nil, nil
	}

	cs := &compiledSchedule{loc: time.UTC}
	if tz := strings.TrimSpace(p.Timezone); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("invalid timezone %q: %w", tz, err)
		}
		cs.loc = loc
	}

	for _, d := range p.ScheduleDays {
		key := strings.ToLower(strings.TrimSpace(d))
		if key == "" {
			continue
		}
		wd, ok := weekdayByName[key]
		if !ok {
			return nil, fmt.Errorf("invalid day of week %q", d)
		}
		cs.days[wd] = true
		cs.hasDays = true
	}

	// A time window needs both bounds; one without the other is ambiguous.
	start := strings.TrimSpace(p.StartTime)
	end := strings.TrimSpace(p.EndTime)
	if (start == "") != (end == "") {
		return nil, fmt.Errorf("schedule requires both start_time and end_time")
	}
	if start != "" {
		sm, err := parseHHMM(start)
		if err != nil {
			return nil, err
		}
		em, err := parseHHMM(end)
		if err != nil {
			return nil, err
		}
		if sm == em {
			return nil, fmt.Errorf("start_time and end_time must differ")
		}
		cs.startMin = sm
		cs.endMin = em
		cs.hasWindow = true
	}

	return cs, nil
}

// active reports whether the schedule permits the policy at the given instant.
// A nil schedule (no configuration) is always active. The instant is converted
// into the schedule's timezone before the day-of-week and time-window checks,
// and day-of-week is evaluated at that local instant.
func (s *compiledSchedule) active(now time.Time) bool {
	if s == nil {
		return true
	}
	t := now.In(s.loc)

	if s.hasDays && !s.days[t.Weekday()] {
		return false
	}

	if s.hasWindow {
		cur := t.Hour()*60 + t.Minute()
		if s.startMin <= s.endMin {
			// Same-day window, active on [start, end).
			if cur < s.startMin || cur >= s.endMin {
				return false
			}
		} else {
			// Window crosses midnight, e.g. 22:00–06:00. Active when the
			// current minute is at/after start OR strictly before end.
			if cur < s.startMin && cur >= s.endMin {
				return false
			}
		}
	}

	return true
}
