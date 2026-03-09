package ingester

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

type redditSearchResponse struct {
	Data struct {
		Children []struct {
			Data struct {
				Title      string  `json:"title"`
				URL        string  `json:"url"`
				Permalink  string  `json:"permalink"`
				Ups        int     `json:"ups"`
				Subreddit  string  `json:"subreddit"`
				CreatedUTC float64 `json:"created_utc"`
			} `json:"data"`
		} `json:"children"`
	} `json:"data"`
}

type redditMention struct {
	Title      string `json:"title"`
	URL        string `json:"url"`
	Subreddit  string `json:"subreddit"`
	Upvotes    int    `json:"upvotes"`
	CreatedUTC int64  `json:"created_utc"`
}

// FetchRedditMentions searches Reddit for CVE mentions across security subreddits
// and stores them as hype signals on the CVE record.
func FetchRedditMentions() {
	log.Println("Starting Reddit mention ingestion...")

	// Target the most actionable CVEs: recently enriched, with PoCs or KEV status
	var cveIDs []string
	err := db.DB.Select(&cveIDs, `
		SELECT id FROM cves
		WHERE id LIKE 'CVE-%'
		  AND (is_kev = true OR EXISTS (SELECT 1 FROM pocs WHERE pocs.cve_id = cves.id))
		  AND (reddit_mentions IS NULL OR reddit_mentions::text = '[]')
		ORDER BY created_at DESC
		LIMIT 50
	`)
	if err != nil {
		log.Printf("Reddit: failed to query CVEs: %v", err)
		return
	}
	if len(cveIDs) == 0 {
		log.Println("Reddit: no CVEs to search.")
		return
	}

	client := &http.Client{Timeout: 15 * time.Second}
	found := 0

	for _, cveID := range cveIDs {
		url := fmt.Sprintf(
			"https://www.reddit.com/r/netsec+cybersecurity+blueteamsec/search.json?q=%s&sort=top&t=week&limit=10",
			cveID,
		)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		// Reddit requires a descriptive User-Agent for API access
		req.Header.Set("User-Agent", "poc-tracker:v1.0 (security research tool)")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Reddit: request failed for %s: %v", cveID, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var result redditSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		if len(result.Data.Children) == 0 {
			// Store empty array so we don't keep querying
			db.DB.Exec(`UPDATE cves SET reddit_mentions = '[]'::jsonb WHERE id = $1`, cveID)
			continue
		}

		var mentions []redditMention
		for _, child := range result.Data.Children {
			d := child.Data
			mentions = append(mentions, redditMention{
				Title:      d.Title,
				URL:        "https://reddit.com" + d.Permalink,
				Subreddit:  d.Subreddit,
				Upvotes:    d.Ups,
				CreatedUTC: int64(d.CreatedUTC),
			})
		}

		mentionsJSON, err := json.Marshal(mentions)
		if err != nil {
			continue
		}

		db.DB.Exec(`UPDATE cves SET reddit_mentions = $1::jsonb WHERE id = $2`, string(mentionsJSON), cveID)
		found += len(mentions)
	}

	log.Printf("Reddit ingestion complete. Found %d mentions across %d CVEs.", found, len(cveIDs))
}
