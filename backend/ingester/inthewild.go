package ingester

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

type InTheWildRecord struct {
	ID             string `json:"id"`
	EarliestReport string `json:"earliestReport"`
}

func FetchInTheWild() {
	log.Println("Starting InTheWild ingestion...")
	resp, err := http.Get("https://inthewild.io/api/exploited")
	if err != nil {
		log.Printf("Failed to fetch InTheWild API: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("InTheWild API returned status: %d", resp.StatusCode)
		return
	}

	var records []InTheWildRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		log.Printf("Failed to decode InTheWild response: %v", err)
		return
	}

	for _, record := range records {
		var lastSeen time.Time
		if record.EarliestReport != "" {
			t, err := time.Parse(time.RFC3339, record.EarliestReport)
			if err == nil {
				lastSeen = t
			}
		}

		_, err := db.DB.Exec(`
			INSERT INTO cves (id, inthewild_exploited, inthewild_last_seen, severity) 
			VALUES ($1, true, $2, 'UNKNOWN')
			ON CONFLICT (id) DO UPDATE 
			SET inthewild_exploited = true,
			    inthewild_last_seen = COALESCE(EXCLUDED.inthewild_last_seen, cves.inthewild_last_seen)
		`, record.ID, lastSeen)
		
		if err != nil {
			log.Printf("Failed to insert/update InTheWild record for %s: %v", record.ID, err)
		}
	}
	log.Println("InTheWild ingestion complete.")
}
