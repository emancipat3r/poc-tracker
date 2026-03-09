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

type GitHubSearchResponse struct {
	Items []GitHubRepo `json:"items"`
}

type GitHubRepo struct {
	Name            string `json:"name"`
	FullName        string `json:"full_name"`
	Description     string `json:"description"`
	HtmlURL         string `json:"html_url"`
	StargazersCount int    `json:"stargazers_count"`
	ForksCount      int    `json:"forks_count"`
	Owner           struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
}

// scamKeywords that lower trust if found in the repo name or description.
var scamKeywords = []string{
	"botnet", "malware", "rat ", " rat", "stealer", "ransomware",
	"crypter", "loader", "trojan", "infostealer", "keylogger",
}

// massRepoPattern matches owners that run mass CVE-themed repo farms.
var massRepoPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)

func FetchGitHubAdvisories() {
	log.Println("Fetching GitHub PoCs...")

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET",
		"https://api.github.com/search/repositories?q=CVE+PoC+exploit&sort=updated&order=desc&per_page=30",
		nil)
	req.Header.Set("User-Agent", "poc-tracker/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("GitHub: failed to search: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("GitHub: search returned status %d", resp.StatusCode)
		return
	}

	var searchResp GitHubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		log.Printf("GitHub: failed to decode response: %v", err)
		return
	}

	cveRegex := regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)

	for _, repo := range searchResp.Items {
		// Sleep between repos to respect 10 req/min GitHub rate limit
		time.Sleep(6500 * time.Millisecond)

		cveID := extractCVEID(cveRegex, repo.Name, repo.Description)
		if cveID == "" {
			continue
		}

		trustScore, flaggedMalware := computeGitHubTrust(repo, cveID)

		signals, _ := json.Marshal(map[string]interface{}{
			"stars":           repo.StargazersCount,
			"forks":           repo.ForksCount,
			"owner":           repo.Owner.Login,
			"owner_type":      repo.Owner.Type,
			"flagged_malware": flaggedMalware,
		})

		// Ensure CVE record exists
		db.DB.Exec(`
			INSERT INTO cves (id, severity) VALUES ($1, 'UNKNOWN')
			ON CONFLICT (id) DO NOTHING
		`, cveID)

		// Insert PoC as Tier 3 (unvetted GitHub search)
		db.DB.Exec(`
			INSERT INTO pocs (cve_id, url, description, source, trust_tier, trust_score, signals, flagged_malware)
			VALUES ($1, $2, $3, 'github-search', 3, $4, $5, $6)
			ON CONFLICT (cve_id, url) DO UPDATE
			SET trust_score = EXCLUDED.trust_score,
			    signals = EXCLUDED.signals,
			    flagged_malware = EXCLUDED.flagged_malware
		`, cveID, repo.HtmlURL, repo.Description, trustScore, string(signals), flaggedMalware)
	}

	log.Println("GitHub PoC ingestion complete.")
}

func extractCVEID(re *regexp.Regexp, name, description string) string {
	if m := re.FindStringSubmatch(name); len(m) > 1 {
		return strings.ToUpper(m[1])
	}
	if m := re.FindStringSubmatch(description); len(m) > 1 {
		return strings.ToUpper(m[1])
	}
	return ""
}

// computeGitHubTrust returns a trust score and malware flag for a GitHub repo.
func computeGitHubTrust(repo GitHubRepo, cveID string) (float64, bool) {
	var score float64
	flaggedMalware := false

	// --- Blacklist check (hard negative) ---
	var blacklisted int
	db.DB.QueryRow(`SELECT COUNT(*) FROM poc_blacklist WHERE github_user = $1`, repo.Owner.Login).Scan(&blacklisted)
	if blacklisted > 0 {
		flaggedMalware = true
		score -= 10
	}

	// --- Positive signals ---
	if repo.StargazersCount > 5 {
		score += 5
	} else if repo.StargazersCount == 0 {
		score -= 2
	}
	if repo.ForksCount > 2 {
		score += 3
	}
	if repo.Owner.Type == "Organization" {
		score += 2
	}

	// CVE exists in NVD (enriched_at IS NOT NULL means NVD knows about it)
	var nvdKnown int
	db.DB.QueryRow(`SELECT COUNT(*) FROM cves WHERE id = $1 AND enriched_at IS NOT NULL`, cveID).Scan(&nvdKnown)
	if nvdKnown > 0 {
		score += 2
	} else {
		// CVE not in NVD: suspicious
		score -= 3
	}

	// Found in multiple aggregators (Trickest already has it)
	var trickestHas int
	db.DB.QueryRow(`SELECT COUNT(*) FROM pocs WHERE cve_id = $1 AND source = 'trickest'`, cveID).Scan(&trickestHas)
	if trickestHas > 0 {
		score += 3
	}

	// Also on Sploitus
	var sploitusHas int
	db.DB.QueryRow(`SELECT COUNT(*) FROM pocs WHERE cve_id = $1 AND source = 'sploitus'`, cveID).Scan(&sploitusHas)
	if sploitusHas > 0 {
		score += 3
	}

	// --- Negative signals ---
	combined := strings.ToLower(repo.Name + " " + repo.Description)
	for _, kw := range scamKeywords {
		if strings.Contains(combined, kw) {
			flaggedMalware = true
			score -= 5
			break
		}
	}

	// Mass CVE repo pattern: owner has many repos all named CVE-YYYY-NNNN
	// (We detect this heuristically: if repo name itself matches the pattern exactly,
	// it's more likely a single-purpose scam repo with no real content)
	if massRepoPattern.MatchString(repo.Name) {
		score -= 2
	}

	return score, flaggedMalware
}
