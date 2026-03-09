package ingester

import (
	"encoding/json"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"github.com/emancipat3r/poc-tracker/backend/db"
)

// securityFeeds defines the security news outlets to monitor.
// weight is applied in hype score calculation.
var securityFeeds = []struct {
	URL    string
	Outlet string
	Weight int
}{
	{"https://www.bleepingcomputer.com/feed/", "bleepingcomputer", 3},
	{"https://feeds.feedburner.com/TheHackersNews", "thehackernews", 3},
	{"https://www.darkreading.com/rss.xml", "darkreading", 2},
	{"https://www.securityweek.com/feed/", "securityweek", 2},
	{"https://therecord.media/feed", "therecord", 2},
}

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

type mediaMentions map[string][]mediaMention

type mediaMention struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	Published string `json:"published"`
}

// FetchRSSFeeds parses the security news RSS feeds, extracts CVE mentions from
// article titles and descriptions, and stores them as media_mentions signals.
func FetchRSSFeeds() {
	log.Println("Starting security news RSS ingestion...")

	fp := gofeed.NewParser()
	// cveHits accumulates all mentions across feeds: cveID -> outlet -> []mention
	cveHits := make(map[string]mediaMentions)

	for _, feed := range securityFeeds {
		log.Printf("RSS: fetching %s (%s)", feed.Outlet, feed.URL)
		parsed, err := fp.ParseURL(feed.URL)
		if err != nil {
			log.Printf("RSS: failed to parse %s: %v", feed.URL, err)
			continue
		}

		for _, item := range parsed.Items {
			text := item.Title + " " + item.Description + " " + item.Content
			cveIDs := uniqueStrings(cvePattern.FindAllString(text, -1))

			published := ""
			if item.PublishedParsed != nil {
				published = item.PublishedParsed.Format(time.RFC3339)
			} else if item.UpdatedParsed != nil {
				published = item.UpdatedParsed.Format(time.RFC3339)
			}

			mention := mediaMention{
				Title:     item.Title,
				URL:       item.Link,
				Published: published,
			}

			for _, cveID := range cveIDs {
				cveID = strings.ToUpper(cveID)
				if _, ok := cveHits[cveID]; !ok {
					cveHits[cveID] = make(mediaMentions)
				}
				cveHits[cveID][feed.Outlet] = append(cveHits[cveID][feed.Outlet], mention)
			}
		}
	}

	// Persist media_mentions for each CVE we've seen mentioned
	updated := 0
	for cveID, mentions := range cveHits {
		mentionsJSON, err := json.Marshal(mentions)
		if err != nil {
			continue
		}

		// Ensure the CVE exists (create a stub if not)
		db.DB.Exec(`
			INSERT INTO cves (id, severity) VALUES ($1, 'UNKNOWN')
			ON CONFLICT (id) DO NOTHING
		`, cveID)

		db.DB.Exec(`
			UPDATE cves SET media_mentions = $1::jsonb WHERE id = $2
		`, string(mentionsJSON), cveID)
		updated++
	}

	log.Printf("RSS ingestion complete. Updated media mentions for %d CVEs.", updated)
}

func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
