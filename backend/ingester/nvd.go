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

	processNVDVulnerabilities(nvdResp.Vulnerabilities)
	log.Println("NVD ingestion complete.")
}

// enrichCVEsFromNVD fetches NVD data for specific CVE IDs that need enrichment
// This is called after other ingesters (like Trickest) create CVE placeholders
func enrichCVEsFromNVD(cveIDs []string) {
	if len(cveIDs) == 0 {
		return
	}

	log.Printf("Enriching %d CVEs from NVD...", len(cveIDs))

	// First, check which CVEs actually need enrichment (no description or severity is UNKNOWN)
	var cveIDsToEnrich []string
	for _, cveID := range cveIDs {
		var description string
		var severity string
		err := db.DB.QueryRow(`
			SELECT COALESCE(description, ''), COALESCE(severity, 'UNKNOWN')
			FROM cves WHERE id = $1
		`, cveID).Scan(&description, &severity)

		if err != nil || description == "" || severity == "UNKNOWN" {
			cveIDsToEnrich = append(cveIDsToEnrich, cveID)
		}
	}

	if len(cveIDsToEnrich) == 0 {
		log.Println("All CVEs already enriched, skipping NVD fetch.")
		return
	}

	// Deduplicate
	seen := make(map[string]bool)
	var uniqueCVEs []string
	for _, id := range cveIDsToEnrich {
		if !seen[id] {
			seen[id] = true
			uniqueCVEs = append(uniqueCVEs, id)
		}
	}

	log.Printf("Fetching NVD data for %d unique CVEs needing enrichment...", len(uniqueCVEs))

	client := &http.Client{Timeout: 60 * time.Second}

	// NVD API allows fetching by cveId parameter, process in batches
	// Rate limit: 5 requests per 30 seconds without API key
	batchSize := 1 // One CVE per request to stay safe with rate limits
	enriched := 0

	for i := 0; i < len(uniqueCVEs); i += batchSize {
		if i > 0 && i%5 == 0 {
			// Rate limit: wait 30 seconds every 5 requests
			log.Printf("NVD rate limit pause... enriched %d/%d CVEs", enriched, len(uniqueCVEs))
			time.Sleep(6 * time.Second)
		}

		cveID := uniqueCVEs[i]
		url := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to fetch NVD for %s: %v", cveID, err)
			continue
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			log.Printf("NVD rate limited, pausing for 30 seconds...")
			resp.Body.Close()
			time.Sleep(30 * time.Second)
			i-- // Retry this CVE
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("NVD API returned status %d for %s", resp.StatusCode, cveID)
			resp.Body.Close()
			continue
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			log.Printf("Failed to decode NVD response for %s: %v", cveID, err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		processNVDVulnerabilities(nvdResp.Vulnerabilities)
		enriched++
	}

	log.Printf("NVD enrichment complete. Enriched %d CVEs.", enriched)
}

// processNVDVulnerabilities handles the common logic of inserting/updating CVEs from NVD data
func processNVDVulnerabilities(vulnerabilities []struct {
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
}) {
	for _, vuln := range vulnerabilities {
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
			SET title = CASE WHEN cves.title = cves.id OR cves.title = '' OR cves.title IS NULL THEN EXCLUDED.title ELSE cves.title END,
			    description = CASE WHEN cves.description = '' OR cves.description IS NULL THEN EXCLUDED.description ELSE EXCLUDED.description END,
			    severity = CASE WHEN EXCLUDED.severity != 'UNKNOWN' THEN EXCLUDED.severity ELSE cves.severity END,
			    cvss_score = CASE WHEN EXCLUDED.cvss_score > 0 THEN EXCLUDED.cvss_score ELSE cves.cvss_score END,
			    published_date = COALESCE(EXCLUDED.published_date, cves.published_date)
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
}
