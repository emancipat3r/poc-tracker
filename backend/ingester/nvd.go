package ingester

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Published string `json:"published"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func FetchNVDUpdates() {
	log.Println("Starting NVD ingestion...")
	
	// Fetch last 1 days of updates from NVD to stay under sync limits without pagination
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000")
	end := now.Format("2006-01-02T15:04:05.000")
	
	client := &http.Client{Timeout: 30 * time.Second}
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=" + start + "%2B00:00&lastModEndDate=" + end + "%2B00:00"
	
	req, _ := http.NewRequest("GET", url, nil)
	// Add a generic User-Agent to avoid blocks if necessary
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch NVD API: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("NVD API returned status: %d", resp.StatusCode)
		return
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		log.Printf("Failed to decode NVD response: %v", err)
		return
	}

	for _, vuln := range nvdResp.Vulnerabilities {
		cve := vuln.CVE
		var description string
		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		var cvssScore float64
		var severity string = "UNKNOWN"
		if len(cve.Metrics.CvssMetricV31) > 0 {
			cvssScore = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(cve.Metrics.CvssMetricV30) > 0 {
			cvssScore = cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
		}

		publishedTime, err := time.Parse(time.RFC3339, cve.Published)
		if err != nil {
			publishedTime = time.Now() // simple fallback
		}

		_, err = db.DB.Exec(`
			INSERT INTO cves (id, title, description, severity, cvss_score, published_date) 
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (id) DO UPDATE 
			SET description = COALESCE(EXCLUDED.description, cves.description),
			    severity = EXCLUDED.severity,
			    cvss_score = EXCLUDED.cvss_score,
			    published_date = EXCLUDED.published_date
		`, cve.ID, cve.ID, description, severity, cvssScore, publishedTime)

		if err != nil {
			log.Printf("Failed to insert NVD CVE %s: %v", cve.ID, err)
			continue
		}

		// Also grab references and add them if they seem poc-related
		for _, ref := range cve.References {
			lowerRef := strings.ToLower(ref.URL)
			if strings.Contains(lowerRef, "exploit") || strings.Contains(lowerRef, "poc") || strings.Contains(lowerRef, "github.com") {
				db.DB.Exec(`
					INSERT INTO pocs (cve_id, url, description, source, trust_tier)
					VALUES ($1, $2, $3, 'nvd-reference', 1)
					ON CONFLICT (cve_id, url) DO NOTHING
				`, cve.ID, ref.URL, "Official NVD Reference")
			}
		}
	}
	log.Println("NVD ingestion complete.")
}
