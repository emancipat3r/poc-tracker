package models

import (
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
	ID          string    `db:"id" json:"id"`
	SourceID    *int      `db:"source_id" json:"source_id"`
	Title       string    `db:"title" json:"title"`
	Description string    `db:"description" json:"description"`
	Severity    string    `db:"severity" json:"severity"`
	CVSSScore    *float64   `db:"cvss_score" json:"cvss_score"`
	PublishedAt  *time.Time  `db:"published_at" json:"published_at"`
	PublishedDate *time.Time `db:"published_date" json:"published_date"`
	IsKev        bool       `db:"is_kev" json:"is_kev"`
	PocURL       *string    `db:"poc_url" json:"poc_url"`
	PoCs         []PoC      `json:"pocs"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

type CVEListResponse struct {
	CVEs  []CVE `json:"cves"`
	Total int   `json:"total"`
}

type PoC struct {
	ID          int       `db:"id" json:"id"`
	CVEID       string    `db:"cve_id" json:"cve_id"`
	URL         string    `db:"url" json:"url"`
	Description string    `db:"description" json:"description"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}
