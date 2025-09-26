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
		return "deny"
	case ActionRedirect:
		return "redirect"
	default:
		return "unknown"
	}
}

// Policy represents a single policy rule.
type Policy struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Category  string   `json:"category"`
	Action    string   `json:"action"`      // "BLOCK", "ALLOW", "REDIRECT"
	Redirect  string   `json:"redirect_ip"` // optional
	Priority  int      `json:"priority"`
	Source    string   `json:"source"`
	Domains   []string `json:"domains"`
	Regexes   []string `json:"regexes"`
	Groups    []string `json:"groups"`
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
