package ingester

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

type EPSSResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

func FetchEPSSScores() {
	log.Println("Starting EPSS score ingestion...")
	var cveIDs []string
	
	// Fetch EPSS for CVEs roughly every 24h or if they dont have one yet
	err := db.DB.Select(&cveIDs, "SELECT id FROM cves WHERE epss_score IS NULL OR updated_at < NOW() - INTERVAL '1 day'")
	if err != nil {
		log.Printf("Failed to fetch CVEs for EPSS: %v", err)
		return
	}

	for i := 0; i < len(cveIDs); i += 100 {
		end := i + 100
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]
		
		url := "https://api.first.org/data/v1/epss?cve=" + strings.Join(batch, ",")
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Failed to fetch EPSS API: %v", err)
			continue
		}
		
		var epssResp EPSSResponse
		if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, data := range epssResp.Data {
			epssScore, _ := strconv.ParseFloat(data.EPSS, 64)
			epssPercentile, _ := strconv.ParseFloat(data.Percentile, 64)
			db.DB.Exec(`
				UPDATE cves 
				SET epss_score = $1, epss_percentile = $2 
				WHERE id = $3
			`, epssScore, epssPercentile, data.CVE)
		}
	}
	log.Println("EPSS ingestion complete.")
}
