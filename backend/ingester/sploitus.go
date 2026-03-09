package ingester

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

type sploitusResponse struct {
	Exploits []struct {
		Href  string `json:"href"`
		Title string `json:"title"`
	} `json:"exploits"`
}

// FetchSploitusPocs searches Sploitus for the most recent CVEs that don't yet
// have a Sploitus-sourced PoC. Results are stored as trust_tier 1.
func FetchSploitusPocs() {
	log.Println("Starting Sploitus PoC ingestion...")

	var cveIDs []string
	err := db.DB.Select(&cveIDs, `
		SELECT id FROM cves
		WHERE id LIKE 'CVE-%'
		  AND NOT EXISTS (SELECT 1 FROM pocs WHERE pocs.cve_id = cves.id AND source = 'sploitus')
		ORDER BY created_at DESC
		LIMIT 100
	`)
	if err != nil {
		log.Printf("Sploitus: failed to query CVEs: %v", err)
		return
	}
	if len(cveIDs) == 0 {
		log.Println("Sploitus: no CVEs to search.")
		return
	}

	client := &http.Client{Timeout: 15 * time.Second}
	found := 0

	for _, cveID := range cveIDs {
		payload, _ := json.Marshal(map[string]interface{}{
			"type":   "exploits",
			"sort":   "default",
			"query":  cveID,
			"title":  false,
			"offset": 0,
		})

		req, err := http.NewRequest("POST", "https://sploitus.com/search", bytes.NewBuffer(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Sploitus: request failed for %s: %v", cveID, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var result sploitusResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, exploit := range result.Exploits {
			if exploit.Href == "" {
				continue
			}
			db.DB.Exec(`
				INSERT INTO pocs (cve_id, url, description, source, trust_tier, trust_score)
				VALUES ($1, $2, $3, 'sploitus', 1, 10)
				ON CONFLICT (cve_id, url) DO NOTHING
			`, cveID, exploit.Href, exploit.Title)
			found++
		}

		// If we found exploits, update has_exploitdb_entry flag if appropriate
		if len(result.Exploits) > 0 {
			for _, exploit := range result.Exploits {
				if isExploitDB(exploit.Href) {
					db.DB.Exec(`UPDATE cves SET has_exploitdb_entry = true WHERE id = $1`, cveID)
					break
				}
			}
		}
	}

	log.Printf("Sploitus ingestion complete. Found %d new exploits.", found)
}

func isExploitDB(url string) bool {
	return len(url) > 0 && (strings.Contains(url, "exploit-db.com") || strings.Contains(url, "exploitdb.com"))
}
