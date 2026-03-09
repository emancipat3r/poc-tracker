package models

import (
	"encoding/json"
	"time"
)

type Source struct {
	ID            int       `db:"id" json:"id"`
	Name          string    `db:"name" json:"name"`
	Type          string    `db:"type" json:"type"`
	URL           string    `db:"url" json:"url"`
	LastFetchedAt time.Time `db:"last_fetched_at" json:"last_fetched_at"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}

type CVE struct {
	ID                 string           `db:"id" json:"id"`
	SourceID           *int             `db:"source_id" json:"source_id"`
	Title              string           `db:"title" json:"title"`
	Description        string           `db:"description" json:"description"`
	Severity           string           `db:"severity" json:"severity"`
	CVSSScore          *float64         `db:"cvss_score" json:"cvss_score"`
	PublishedAt        *time.Time       `db:"published_at" json:"published_at"`
	PublishedDate      *time.Time       `db:"published_date" json:"published_date"`
	IsKev              bool             `db:"is_kev" json:"is_kev"`
	EpssScore          *float64         `db:"epss_score" json:"epss_score"`
	EpssPercentile     *float64         `db:"epss_percentile" json:"epss_percentile"`
	InTheWildExploited bool             `db:"inthewild_exploited" json:"inthewild_exploited"`
	InTheWildLastSeen  *time.Time       `db:"inthewild_last_seen" json:"inthewild_last_seen"`
	Cisa0Day           bool             `db:"cisa_0day" json:"cisa_0day"`
	HasNucleiTemplate  bool             `db:"has_nuclei_template" json:"has_nuclei_template"`
	HasMetasploitMod   bool             `db:"has_metasploit_module" json:"has_metasploit_module"`
	HasExploitDBEntry  bool             `db:"has_exploitdb_entry" json:"has_exploitdb_entry"`
	HypeScore          float64          `db:"hype_score" json:"hype_score"`
	MediaMentions      *json.RawMessage `db:"media_mentions" json:"media_mentions"`
	RedditMentions     *json.RawMessage `db:"reddit_mentions" json:"reddit_mentions"`
	EnrichedAt         *time.Time       `db:"enriched_at" json:"enriched_at"`
	PoCs               []PoC            `json:"pocs"`
	UpdatedAt          time.Time        `db:"updated_at" json:"updated_at"`
	CreatedAt          time.Time        `db:"created_at" json:"created_at"`
}

type CVEListResponse struct {
	CVEs  []CVE `json:"cves"`
	Total int   `json:"total"`
}

type PoC struct {
	ID             int              `db:"id" json:"id"`
	CVEID          string           `db:"cve_id" json:"cve_id"`
	URL            string           `db:"url" json:"url"`
	Description    string           `db:"description" json:"description"`
	Source         string           `db:"source" json:"source"`
	TrustTier      int              `db:"trust_tier" json:"trust_tier"`
	TrustScore     *float64         `db:"trust_score" json:"trust_score"`
	Signals        *json.RawMessage `db:"signals" json:"signals"`
	FlaggedMalware bool             `db:"flagged_malware" json:"flagged_malware"`
	CreatedAt      time.Time        `db:"created_at" json:"created_at"`
}

type PoCBlacklist struct {
	ID          int       `db:"id" json:"id"`
	GithubUser  *string   `db:"github_user" json:"github_user"`
	RepoPattern *string   `db:"repo_pattern" json:"repo_pattern"`
	Reason      *string   `db:"reason" json:"reason"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}
