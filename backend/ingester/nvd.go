package ingester

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

// Non-PoC domains that appear in NVD references but are vendor/advisory sites
var nvdNonPoCDomains = []string{
	"chromium.googlesource.com",
	"git.kernel.org",
	"bugzilla.",
	"bugs.",
	"support.",
	"security.",
	"lists.",
	"advisories.",
	"advisory.",
	"access.redhat.com",
	"ubuntu.com/security",
	"oracle.com/security",
	"msrc.microsoft.com",
	"portal.msrc.microsoft.com",
}

// Regex for GitHub repo paths that likely contain actual exploit code
var githubCodePathRe = regexp.MustCompile(`github\.com/[^/]+/[^/]+/(blob|tree)/`)

// classifyNVDReference returns (trust_tier, is_poc).
// Tier 1 = confirmed exploit DB (exploit-db, packetstorm).
// Tier 2 = likely PoC (GitHub repos with code paths, or URLs with "exploit"/"poc" in path).
// Returns (0, false) if the URL is not a PoC reference.
func classifyNVDReference(rawURL string) (int, bool) {
	lower := strings.ToLower(rawURL)

	// Skip known non-PoC domains
	for _, domain := range nvdNonPoCDomains {
		if strings.Contains(lower, domain) {
			return 0, false
		}
	}

	// Tier 1: known exploit databases
	if strings.Contains(lower, "exploit-db.com") || strings.Contains(lower, "packetstormsecurity.com") {
		return 1, true
	}

	// GitHub URLs: only if they point to actual code (blob/tree paths)
	if strings.Contains(lower, "github.com") {
		// Skip patch commits, issues, pull requests, advisories
		if strings.Contains(lower, "/commit/") ||
			strings.Contains(lower, "/issues/") ||
			strings.Contains(lower, "/pull/") ||
			strings.Contains(lower, "/advisories/") ||
			strings.Contains(lower, "/security/") ||
			strings.Contains(lower, "/releases/") {
			return 0, false
		}
		// Match blob/tree paths (actual code)
		if githubCodePathRe.MatchString(lower) {
			return 2, true
		}
		// GitHub repo root with "poc" or "exploit" in the path → Tier 2
		if strings.Contains(lower, "poc") || strings.Contains(lower, "exploit") {
			return 2, true
		}
		// Generic github.com link — not a PoC
		return 0, false
	}

	// Non-GitHub URLs with exploit/PoC keywords in path → Tier 2
	if strings.Contains(lower, "/exploit") || strings.Contains(lower, "/poc") {
		return 2, true
	}

	return 0, false
}

type nvdCVSSV3Data struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdCVSSV2Metric struct {
	CvssData     struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type nvdVulnerability struct {
	CVE struct {
		ID      string `json:"id"`
		Metrics struct {
			CvssMetricV31 []struct {
				CvssData nvdCVSSV3Data `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CvssMetricV30 []struct {
				CvssData nvdCVSSV3Data `json:"cvssData"`
			} `json:"cvssMetricV30"`
			CvssMetricV2 []nvdCVSSV2Metric `json:"cvssMetricV2"`
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
}

type NVDResponse struct {
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

func FetchNVDUpdates() {
	log.Println("Starting NVD ingestion...")

	now := time.Now().UTC()
	end := now.Format("2006-01-02T15:04:05.000")

	// Load last successful end time from checkpoint to avoid gaps
	start := now.Add(-2 * time.Hour).Format("2006-01-02T15:04:05.000")
	var checkpoint json.RawMessage
	db.DB.QueryRow(`SELECT checkpoint FROM sync_state WHERE source_name = 'nvd'`).Scan(&checkpoint)
	if len(checkpoint) > 0 {
		var cp map[string]string
		if json.Unmarshal(checkpoint, &cp) == nil {
			if lastEnd, ok := cp["last_mod_end"]; ok {
				// Parse and subtract 10 min overlap buffer to catch edge-case stragglers
				if t, err := time.Parse("2006-01-02T15:04:05.000", lastEnd); err == nil {
					start = t.Add(-10 * time.Minute).Format("2006-01-02T15:04:05.000")
				}
			}
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=" + start + "%2B00:00&lastModEndDate=" + end + "%2B00:00"

	req, _ := http.NewRequest("GET", url, nil)
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

	// Save checkpoint so next run starts from this end time
	cpJSON, _ := json.Marshal(map[string]string{"last_mod_end": end})
	db.DB.Exec(`
		INSERT INTO sync_state (source_name, checkpoint)
		VALUES ('nvd', $1)
		ON CONFLICT (source_name) DO UPDATE SET checkpoint = $1
	`, string(cpJSON))

	log.Println("NVD ingestion complete.")
}

// EnrichPendingCVEs queries the database for CVEs with enriched_at IS NULL
// and fetches NVD data for them. Called as step 7 in the coordinator cycle.
func EnrichPendingCVEs() {
	var cveIDs []string
	err := db.DB.Select(&cveIDs, `
		SELECT id FROM cves
		WHERE enriched_at IS NULL AND id LIKE 'CVE-%'
		ORDER BY created_at DESC
		LIMIT 200
	`)
	if err != nil {
		log.Printf("Failed to query pending CVEs for enrichment: %v", err)
		return
	}
	if len(cveIDs) == 0 {
		log.Println("No CVEs pending NVD enrichment.")
		return
	}
	log.Printf("Found %d CVEs pending NVD enrichment.", len(cveIDs))
	enrichCVEsFromNVD(cveIDs)
}

// EnrichSingleCVE fetches NVD data for one CVE immediately (on-demand endpoint).
func EnrichSingleCVE(cveID string) error {
	enrichCVEsFromNVD([]string{cveID})
	return nil
}

// enrichCVEsFromNVD fetches NVD data for specific CVE IDs that lack enriched_at.
func enrichCVEsFromNVD(cveIDs []string) {
	if len(cveIDs) == 0 {
		return
	}

	// Deduplicate and filter to only unenriched CVEs
	seen := make(map[string]bool)
	var uniqueCVEs []string
	for _, id := range cveIDs {
		if seen[id] {
			continue
		}
		seen[id] = true

		var count int
		db.DB.QueryRow(`SELECT COUNT(*) FROM cves WHERE id = $1 AND enriched_at IS NULL`, id).Scan(&count)
		if count > 0 {
			uniqueCVEs = append(uniqueCVEs, id)
		}
	}

	if len(uniqueCVEs) == 0 {
		log.Println("All queued CVEs already enriched, skipping NVD fetch.")
		return
	}

	log.Printf("Fetching NVD data for %d CVEs needing enrichment...", len(uniqueCVEs))

	client := &http.Client{Timeout: 60 * time.Second}
	enriched := 0

	for i, cveID := range uniqueCVEs {
		if i > 0 {
			// Rate limit: 5 requests per 30 seconds without API key
			time.Sleep(650 * time.Millisecond)
		}

		url := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to fetch NVD for %s: %v", cveID, err)
			continue
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			log.Printf("NVD rate limited on %s, pausing for 30 seconds...", cveID)
			resp.Body.Close()
			time.Sleep(30 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("NVD API returned status %d for %s", resp.StatusCode, cveID)
			resp.Body.Close()
			// Still mark as attempted so we don't retry indefinitely
			db.DB.Exec(`UPDATE cves SET enriched_at = NOW() WHERE id = $1`, cveID)
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
		// Mark as enriched so we don't re-fetch on next cycle
		db.DB.Exec(`UPDATE cves SET enriched_at = NOW() WHERE id = $1`, cveID)
		enriched++
	}

	log.Printf("NVD enrichment complete. Enriched %d/%d CVEs.", enriched, len(uniqueCVEs))
}

// processNVDVulnerabilities handles inserting/updating CVEs from NVD data.
func processNVDVulnerabilities(vulnerabilities []nvdVulnerability) {
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
		severity := "UNKNOWN"

		if len(cve.Metrics.CvssMetricV31) > 0 {
			cvssScore = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(cve.Metrics.CvssMetricV30) > 0 {
			cvssScore = cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
		} else if len(cve.Metrics.CvssMetricV2) > 0 {
			cvssScore = cve.Metrics.CvssMetricV2[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV2[0].BaseSeverity
		}

		publishedTime, err := time.Parse(time.RFC3339, cve.Published)
		if err != nil {
			publishedTime, err = time.Parse("2006-01-02T15:04:05.000", cve.Published)
			if err != nil {
				publishedTime = time.Time{}
			}
		}

		_, err = db.DB.Exec(`
			INSERT INTO cves (id, title, description, severity, cvss_score, published_date, enriched_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())
			ON CONFLICT (id) DO UPDATE
			SET title = CASE WHEN cves.title = cves.id OR cves.title = '' OR cves.title IS NULL THEN EXCLUDED.title ELSE cves.title END,
			    description = CASE WHEN cves.description = '' OR cves.description IS NULL THEN EXCLUDED.description ELSE EXCLUDED.description END,
			    severity = CASE WHEN EXCLUDED.severity != 'UNKNOWN' THEN EXCLUDED.severity ELSE cves.severity END,
			    cvss_score = CASE WHEN EXCLUDED.cvss_score > 0 THEN EXCLUDED.cvss_score ELSE cves.cvss_score END,
			    published_date = COALESCE(EXCLUDED.published_date, cves.published_date),
			    enriched_at = NOW()
		`, cve.ID, cve.ID, description, severity, cvssScore, publishedTime)

		if err != nil {
			log.Printf("Failed to insert NVD CVE %s: %v", cve.ID, err)
			continue
		}

		// Add references that look PoC-related
		for _, ref := range cve.References {
			tier, isPoc := classifyNVDReference(ref.URL)
			if isPoc {
				db.DB.Exec(`
					INSERT INTO pocs (cve_id, url, description, source, trust_tier)
					VALUES ($1, $2, $3, 'nvd-reference', $4)
					ON CONFLICT (cve_id, url) DO NOTHING
				`, cve.ID, ref.URL, "NVD Reference", tier)
			}
		}
	}
}
