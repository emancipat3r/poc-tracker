package ingester

import (
	"log"
	"time"
	"strings"

	"github.com/mmcdole/gofeed"
	"github.com/emancipat3r/poc-tracker/backend/db"
	"github.com/emancipat3r/poc-tracker/backend/models"
)

func FetchRSSFeeds() {
	var sources []models.Source
	err := db.DB.Select(&sources, "SELECT * FROM sources WHERE type = 'rss'")
	if err != nil {
		log.Printf("Error fetching RSS sources: %v", err)
		return
	}

	fp := gofeed.NewParser()
	for _, source := range sources {
		log.Printf("Fetching RSS feed for source: %s", source.URL)
		feed, err := fp.ParseURL(source.URL)
		if err != nil {
			log.Printf("Failed to parse feed %s: %v", source.URL, err)
			continue
		}

		for _, item := range feed.Items {
			// Try to extract CVE ID from title or description. Usually, title contains it.
			title := item.Title
			desc := item.Description
			var cveID string
			if strings.Contains(title, "CVE-") {
				// Naive extraction
				parts := strings.Split(title, " ")
				for _, p := range parts {
					if strings.HasPrefix(p, "CVE-") {
						cveID = p
						break
					}
				}
			}

			if cveID == "" {
				continue
			}

			severity := "UNKNOWN"
			var cvssScore *float64

			publishedTime := time.Now()
			if item.PublishedParsed != nil {
				publishedTime = *item.PublishedParsed
			} else if item.UpdatedParsed != nil {
				publishedTime = *item.UpdatedParsed
			}

			_, err = db.DB.Exec(`
				INSERT INTO cves (id, source_id, title, description, severity, cvss_score, published_at, updated_at) 
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (id) DO UPDATE 
				SET title = EXCLUDED.title, description = EXCLUDED.description, updated_at = EXCLUDED.updated_at
			`, cveID, source.ID, title, desc, severity, cvssScore, publishedTime, time.Now())

			if err != nil {
				log.Printf("Failed to insert CVE %s: %v", cveID, err)
			}
		}

		// Update last fetched at
		_, _ = db.DB.Exec("UPDATE sources SET last_fetched_at = $1 WHERE id = $2", time.Now(), source.ID)
	}
}
