package ingester

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

type KEVFeed struct {
	Vulnerabilities []KEVVulnerability `json:"vulnerabilities"`
}

type KEVVulnerability struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
}

func FetchKEVFeed() {
	log.Println("Fetching CISA KEV feed...")
	resp, err := http.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		log.Printf("Failed to fetch KEV feed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("KEV feed returned status: %d", resp.StatusCode)
		return
	}

	var feed KEVFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		log.Printf("Failed to decode KEV feed: %v", err)
		return
	}

	for _, v := range feed.Vulnerabilities {
		publishedDate, _ := time.Parse("2006-01-02", v.DateAdded)

		_, err := db.DB.Exec(`
			INSERT INTO cves (id, title, description, is_kev, published_date, severity)
			VALUES ($1, $2, $3, $4, $5, 'UNKNOWN')
			ON CONFLICT (id) DO UPDATE
			SET is_kev = true,
				title = COALESCE(NULLIF(cves.title, ''), EXCLUDED.title),
				description = COALESCE(NULLIF(cves.description, ''), EXCLUDED.description),
				published_date = COALESCE(cves.published_date, EXCLUDED.published_date)
		`, v.CveID, v.VulnerabilityName, v.ShortDescription, true, publishedDate)
		
		if err != nil {
			log.Printf("Failed to insert/update KEV CVE %s: %v", v.CveID, err)
		}
	}
	log.Println("KEV feed ingestion complete.")
}
