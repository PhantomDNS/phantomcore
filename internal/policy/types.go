package policy

import "time"

type Action int

const (
	ActionAllow Action = iota
	ActionDeny
	ActionRedirect
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "block"
	case ActionRedirect:
		return "redirect"
	default:
		return "unknown"
	}
}

type Policy struct {
	ID          string   `json:"id" gorm:"primaryKey;size:64"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Redirect    string   `json:"redirect_ip"` // optional redirect IP
	Source      string   `json:"source"`      // "local"|"external"|"system"
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
	Action      string   `json:"action"`           // BLOCK|ALLOW|LOG_ONLY|REDIRECT
	Domains     []string `gorm:"-" json:"domains"` // stored in separate table or JSON
	Regexes     []string `gorm:"-" json:"regexes"`

	// Optional schedule (I-038). When all schedule fields are empty the policy
	// is always active — the unchanged behaviour for every existing policy.
	// When set, the policy only matches while the current time falls inside the
	// window. ScheduleDays are day tokens ("mon".."sun", short or long form);
	// an empty list means every day. StartTime/EndTime are local "HH:MM" bounds
	// (both required together); Timezone is an IANA name (empty = UTC).
	ScheduleDays []string `gorm:"-" json:"schedule_days,omitempty"`
	StartTime    string   `gorm:"-" json:"start_time,omitempty"`
	EndTime      string   `gorm:"-" json:"end_time,omitempty"`
	Timezone     string   `gorm:"-" json:"timezone,omitempty"`

	// sched is the precomputed schedule, populated when a snapshot is built.
	// nil means always active. Unexported so gorm and encoding/json ignore it.
	sched *compiledSchedule

	// ClientCIDRs optionally scopes a policy to specific clients by IP/CIDR.
	// Empty means the policy is unscoped and applies to all clients (I-014).
	// Entries may be single IPs ("192.168.1.10") or CIDRs ("10.0.0.0/24"),
	// IPv4 or IPv6. MAC-based scoping is intentionally left out of this first
	// cut (it needs a client inventory).
	ClientCIDRs []string `gorm:"-" json:"client_cidrs"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Decision is the result of evaluating a query.
type Decision struct {
	Action     Action
	PolicyID   string
	Category   string
	RedirectIP string
}
