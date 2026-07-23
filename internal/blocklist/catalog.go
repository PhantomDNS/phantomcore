// SPDX-License-Identifier: GPL-3.0-or-later
package blocklist

import "strings"

// Category types, used only for grouping/display in the UI.
const (
	CategoryTypeSecurity = "security"
	CategoryTypeContent  = "content"
)

// Feed is a single curated community source that belongs to a category. When a
// category is enabled, every one of its feeds is fetched/parsed through the existing
// blocklist engine and the resulting domains are deduped across feeds.
type Feed struct {
	Name   string
	URL    string
	Format string // "hosts" or "domains" — must match a registered parser
}

// CategoryDef is a named toggle that aggregates one or more curated feeds. Categories
// are additive and default to OFF: nothing is fetched until the category is enabled.
type CategoryDef struct {
	Name        string
	Description string
	Type        string // CategoryTypeSecurity | CategoryTypeContent
	Feeds       []Feed
}

// CollectionDef (I-052) is an app/service bundle: a small, curated set of domains that
// can be blocked as one toggle (e.g. block "TikTok" or "Instagram"). It is modeled the
// same way as a category — a named toggle backed by an aggregated blocklist source — but
// its domains are curated inline rather than fetched from a remote feed.
type CollectionDef struct {
	Name        string
	App         string
	Description string
	Domains     []string
}

// Catalog holds the built-in categories and collections. It is a value (not global
// mutable state) so tests can substitute feeds pointing at local httptest servers.
type Catalog struct {
	Categories  []CategoryDef
	Collections []CollectionDef
}

// Category looks up a category definition by name (case-insensitive).
func (c *Catalog) Category(name string) (CategoryDef, bool) {
	for _, def := range c.Categories {
		if strings.EqualFold(def.Name, name) {
			return def, true
		}
	}
	return CategoryDef{}, false
}

// Collection looks up a collection definition by name (case-insensitive).
func (c *Catalog) Collection(name string) (CollectionDef, bool) {
	for _, def := range c.Collections {
		if strings.EqualFold(def.Name, name) {
			return def, true
		}
	}
	return CollectionDef{}, false
}

// CategorySourceID is the deterministic blocklist-source ID under which a category's
// aggregated, deduped domains are stored. Namespacing keeps them from colliding with
// user-created blocklist sources.
func CategorySourceID(name string) string {
	return "category:" + strings.ToLower(name)
}

// CollectionSourceID is the deterministic blocklist-source ID for a collection bundle.
func CollectionSourceID(name string) string {
	return "collection:" + strings.ToLower(name)
}

// DefaultCatalog returns the built-in category and collection catalog: curated
// community feeds (OISD, URLhaus, ThreatFox, Hagezi, abuse.ch) grouped into security
// and content categories, plus a set of per-app collections.
func DefaultCatalog() *Catalog {
	return &Catalog{
		Categories: []CategoryDef{
			{
				Name:        "ads",
				Description: "Advertising networks and ad-serving domains.",
				Type:        CategoryTypeContent,
				Feeds: []Feed{
					{Name: "OISD Small", URL: "https://small.oisd.nl/domainswild", Format: "domains"},
					{Name: "Hagezi Pro", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt", Format: "hosts"},
				},
			},
			{
				Name:        "trackers",
				Description: "Analytics, telemetry, and cross-site tracking domains.",
				Type:        CategoryTypeContent,
				Feeds: []Feed{
					{Name: "Hagezi Pro", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt", Format: "hosts"},
				},
			},
			{
				Name:        "malware",
				Description: "Domains distributing malware and malicious payloads.",
				Type:        CategoryTypeSecurity,
				Feeds: []Feed{
					{Name: "URLhaus", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", Format: "hosts"},
					{Name: "Hagezi TIF", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt", Format: "hosts"},
				},
			},
			{
				Name:        "phishing",
				Description: "Phishing and credential-harvesting domains.",
				Type:        CategoryTypeSecurity,
				Feeds: []Feed{
					{Name: "OISD NSFW-free Phishing", URL: "https://phishing.army/download/phishing_army_blocklist_extended.txt", Format: "domains"},
				},
			},
			{
				Name:        "c2",
				Description: "Command-and-control (C2) and botnet infrastructure.",
				Type:        CategoryTypeSecurity,
				Feeds: []Feed{
					{Name: "ThreatFox", URL: "https://threatfox.abuse.ch/downloads/hostfile/", Format: "hosts"},
				},
			},
			{
				Name:        "cryptomining",
				Description: "In-browser cryptomining and coin-hijacking domains.",
				Type:        CategoryTypeSecurity,
				Feeds: []Feed{
					{Name: "Hagezi Cryptojacking", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.crypto.txt", Format: "domains"},
				},
			},
			{
				Name:        "adult",
				Description: "Adult and pornographic content.",
				Type:        CategoryTypeContent,
				Feeds: []Feed{
					{Name: "OISD NSFW", URL: "https://nsfw.oisd.nl/domainswild", Format: "domains"},
				},
			},
			{
				Name:        "gambling",
				Description: "Online gambling and betting domains.",
				Type:        CategoryTypeContent,
				Feeds: []Feed{
					{Name: "Hagezi Gambling", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/gambling.txt", Format: "domains"},
				},
			},
			{
				Name:        "piracy",
				Description: "Piracy, warez, and illegal streaming domains.",
				Type:        CategoryTypeContent,
				Feeds: []Feed{
					{Name: "Hagezi Piracy", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/piracy.txt", Format: "domains"},
				},
			},
		},
		Collections: []CollectionDef{
			{
				Name:        "tiktok",
				App:         "TikTok",
				Description: "Block TikTok and its content/telemetry domains.",
				Domains: []string{
					"tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",
					"musical.ly", "tiktokcdn-us.com",
				},
			},
			{
				Name:        "instagram",
				App:         "Instagram",
				Description: "Block Instagram domains.",
				Domains: []string{
					"instagram.com", "cdninstagram.com", "instagr.am",
				},
			},
			{
				Name:        "facebook",
				App:         "Facebook",
				Description: "Block Facebook / Meta domains.",
				Domains: []string{
					"facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "facebook.net",
				},
			},
			{
				Name:        "youtube",
				App:         "YouTube",
				Description: "Block YouTube domains.",
				Domains: []string{
					"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
				},
			},
			{
				Name:        "snapchat",
				App:         "Snapchat",
				Description: "Block Snapchat domains.",
				Domains: []string{
					"snapchat.com", "sc-cdn.net", "snap.com",
				},
			},
		},
	}
}
