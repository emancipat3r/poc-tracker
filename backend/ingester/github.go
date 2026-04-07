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
	log.Println("Fetching GitHub PoCs for known CVEs...")

	// Query DB for recent CVEs that don't yet have a github-search PoC
	var cveIDs []string
	err := db.DB.Select(&cveIDs, `
		SELECT c.id FROM cves c
		WHERE c.id LIKE 'CVE-%'
		  AND c.created_at > NOW() - INTERVAL '90 days'
		  AND NOT EXISTS (
			SELECT 1 FROM pocs p WHERE p.cve_id = c.id AND p.source = 'github-search'
		  )
		ORDER BY c.created_at DESC
		LIMIT 50
	`)
	if err != nil {
		log.Printf("GitHub: failed to query CVEs: %v", err)
		return
	}
	if len(cveIDs) == 0 {
		log.Println("GitHub: no CVEs need PoC search.")
		return
	}
	log.Printf("GitHub: searching for PoCs for %d CVEs", len(cveIDs))

	client := &http.Client{Timeout: 30 * time.Second}
	cveRegex := regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)
	found := 0

	for i, cveID := range cveIDs {
		if i > 0 {
			// GitHub search API: 10 requests/min unauthenticated
			time.Sleep(6500 * time.Millisecond)
		}

		// Search for this specific CVE ID in repo names and descriptions
		searchURL := "https://api.github.com/search/repositories?q=" + cveID + "+in:name,description&sort=updated&order=desc&per_page=10"
		req, _ := http.NewRequest("GET", searchURL, nil)
		req.Header.Set("User-Agent", "poc-tracker/1.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("GitHub: failed to search for %s: %v", cveID, err)
			continue
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			log.Printf("GitHub: rate limited, stopping early after %d CVEs", i)
			resp.Body.Close()
			break
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("GitHub: search for %s returned status %d", cveID, resp.StatusCode)
			resp.Body.Close()
			continue
		}

		var searchResp GitHubSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
			log.Printf("GitHub: failed to decode response for %s: %v", cveID, err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, repo := range searchResp.Items {
			// Verify the repo actually references this CVE
			extractedID := extractCVEID(cveRegex, repo.Name, repo.Description)
			if extractedID != cveID {
				continue
			}

			trustScore, flaggedMalware := computeGitHubTrust(repo, cveID, client)

			signals, _ := json.Marshal(map[string]interface{}{
				"stars":           repo.StargazersCount,
				"forks":           repo.ForksCount,
				"owner":           repo.Owner.Login,
				"owner_type":      repo.Owner.Type,
				"flagged_malware": flaggedMalware,
			})

			db.DB.Exec(`
				INSERT INTO pocs (cve_id, url, description, source, trust_tier, trust_score, signals, flagged_malware)
				VALUES ($1, $2, $3, 'github-search', 3, $4, $5, $6)
				ON CONFLICT (cve_id, url) DO UPDATE
				SET trust_score = EXCLUDED.trust_score,
				    signals = EXCLUDED.signals,
				    flagged_malware = EXCLUDED.flagged_malware
			`, cveID, repo.HtmlURL, repo.Description, trustScore, string(signals), flaggedMalware)
			found++
		}
	}

	log.Printf("GitHub PoC ingestion complete. Found %d PoCs across %d CVEs.", found, len(cveIDs))
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

// codeFileExtensions are file extensions that indicate real exploit/PoC code.
var codeFileExtensions = map[string]bool{
	".py": true, ".c": true, ".go": true, ".rb": true, ".sh": true,
	".js": true, ".ts": true, ".java": true, ".cpp": true, ".rs": true,
	".pl": true, ".ps1": true, ".php": true, ".lua": true, ".zig": true,
}

// computeGitHubTrust returns a trust score and malware flag for a GitHub repo.
// The client parameter is used for additional API calls (file listing, account age).
func computeGitHubTrust(repo GitHubRepo, cveID string, client *http.Client) (float64, bool) {
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

	// Mass CVE repo pattern
	if massRepoPattern.MatchString(repo.Name) {
		score -= 2
	}

	// --- File extension check (Webrat detection) ---
	// Malware repos typically contain only a README and a password-protected ZIP.
	// Real PoCs have actual code files (.py, .c, .go, etc.)
	hasCodeFile := checkRepoHasCodeFiles(client, repo.FullName)
	if hasCodeFile {
		score += 4
	} else {
		score -= 5
		flaggedMalware = true
	}

	// --- Account age check (Webrat detection) ---
	// Fresh accounts (<30 days) are a strong malware signal.
	accountAgeDays := getAccountAgeDays(client, repo.Owner.Login)
	if accountAgeDays >= 0 {
		if accountAgeDays < 30 {
			score -= 6
			flaggedMalware = true
		} else if accountAgeDays < 90 {
			score -= 2
		} else if accountAgeDays > 365 {
			score += 2
		}
	}

	return score, flaggedMalware
}

// checkRepoHasCodeFiles checks if a GitHub repo contains any actual code files
// (not just README + ZIP). Returns true if code files found.
func checkRepoHasCodeFiles(client *http.Client, fullName string) bool {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+fullName+"/contents", nil)
	if err != nil {
		return true // fail open — don't penalize on API errors
	}
	req.Header.Set("User-Agent", "poc-tracker/1.0")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return true
	}
	defer resp.Body.Close()

	var contents []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&contents); err != nil {
		return true
	}

	for _, entry := range contents {
		if entry.Type == "dir" {
			// Directories suggest real project structure
			return true
		}
		lower := strings.ToLower(entry.Name)
		dotIdx := strings.LastIndex(lower, ".")
		if dotIdx >= 0 {
			ext := lower[dotIdx:]
			if codeFileExtensions[ext] {
				return true
			}
		}
	}
	return false
}

// getAccountAgeDays returns how many days old a GitHub account is.
// Returns -1 on error (caller should skip the check).
func getAccountAgeDays(client *http.Client, username string) int {
	req, err := http.NewRequest("GET", "https://api.github.com/users/"+username, nil)
	if err != nil {
		return -1
	}
	req.Header.Set("User-Agent", "poc-tracker/1.0")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return -1
	}
	defer resp.Body.Close()

	var user struct {
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return -1
	}

	return int(time.Since(user.CreatedAt).Hours() / 24)
}
