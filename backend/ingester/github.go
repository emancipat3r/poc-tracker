package ingester

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

var (
	coreRateLimitExhausted atomic.Bool
	coreRateLimitReset     atomic.Int64 // Unix timestamp
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
var massRepoPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+(?:[-_].*)?$`)

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
		LIMIT 8
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

	// --- Account age & CVE mass count checks (Webrat detection) ---
	meta := getGitHubUserMetadata(client, repo.Owner.Login)
	if meta.AccountAgeDays >= 0 {
		if meta.AccountAgeDays < 30 {
			score -= 6
			flaggedMalware = true
		} else if meta.AccountAgeDays < 90 {
			score -= 2
		} else if meta.AccountAgeDays > 365 {
			score += 2
		}
	}

	if meta.CveRepoCount >= 20 {
		score -= 5
		flaggedMalware = true
	} else if meta.CveRepoCount < 4 {
		score += 1
	}

	return score, flaggedMalware
}

func checkRateLimit(resp *http.Response) {
	remStr := resp.Header.Get("X-RateLimit-Remaining")
	resStr := resp.Header.Get("X-RateLimit-Reset")
	
	if remStr != "" {
		if rem, err := strconv.Atoi(remStr); err == nil && rem < 10 {
			coreRateLimitExhausted.Store(true)
			if reset, err := strconv.ParseInt(resStr, 10, 64); err == nil {
				coreRateLimitReset.Store(reset)
			}
		}
	} else if resp.StatusCode == 403 || resp.StatusCode == 429 {
		coreRateLimitExhausted.Store(true)
		if resStr != "" {
			if reset, err := strconv.ParseInt(resStr, 10, 64); err == nil {
				coreRateLimitReset.Store(reset)
			}
		} else {
			// fallback if reset isn't provided
			coreRateLimitReset.Store(time.Now().Unix() + 3600)
		}
	}
}

func isCoreAPIExhausted() bool {
	if coreRateLimitExhausted.Load() {
		if time.Now().Unix() > coreRateLimitReset.Load() {
			coreRateLimitExhausted.Store(false)
			return false
		}
		return true
	}
	return false
}

// checkRepoHasCodeFiles checks if a GitHub repo contains any actual code files
// by making a single call to the recursed git trees endpoint.
func checkRepoHasCodeFiles(client *http.Client, fullName string) bool {
	if isCoreAPIExhausted() {
		return true // fail open
	}

	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+fullName+"/git/trees/HEAD?recursive=1", nil)
	if err != nil {
		return true 
	}
	req.Header.Set("User-Agent", "poc-tracker/1.0")

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return true
	}
	defer resp.Body.Close()
	checkRateLimit(resp)

	if resp.StatusCode != http.StatusOK {
		// Possibly HEAD doesn't exist or isn't default. Return true to fail open.
		return true
	}

	var contents struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&contents); err != nil {
		return true
	}

	for _, entry := range contents.Tree {
		if entry.Type == "blob" {
			lower := strings.ToLower(entry.Path)
			dotIdx := strings.LastIndex(lower, ".")
			if dotIdx >= 0 {
				ext := lower[dotIdx:]
				if codeFileExtensions[ext] {
					return true
				}
			}
		}
	}
	return false
}

type githubUserMeta struct {
	AccountAgeDays int
	CveRepoCount   int
}

// getGitHubUserMetadata returns cached/fresh data about a given user.
func getGitHubUserMetadata(client *http.Client, username string) githubUserMeta {
	meta := githubUserMeta{AccountAgeDays: -1, CveRepoCount: 0}
	var cachedAge time.Time
	var cachedFetchedAt time.Time
	var cachedCount int

	err := db.DB.QueryRow(`
		SELECT account_created_at, cve_repo_count, fetched_at 
		FROM github_user_cache 
		WHERE login = $1
	`, username).Scan(&cachedAge, &cachedCount, &cachedFetchedAt)

	ageStale := err != nil || cachedAge.IsZero()
	countStale := err != nil || time.Since(cachedFetchedAt).Hours() > 24*7

	if !ageStale {
		meta.AccountAgeDays = int(time.Since(cachedAge).Hours() / 24)
	}
	meta.CveRepoCount = cachedCount

	if !ageStale && !countStale {
		return meta
	}

	var created time.Time
	if ageStale {
		if !isCoreAPIExhausted() {
			req, _ := http.NewRequest("GET", "https://api.github.com/users/"+username, nil)
			req.Header.Set("User-Agent", "poc-tracker/1.0")
			if resp, err := client.Do(req); err == nil {
				defer resp.Body.Close()
				checkRateLimit(resp)
				if resp.StatusCode == http.StatusOK {
					var user struct {
						CreatedAt time.Time `json:"created_at"`
					}
					if json.NewDecoder(resp.Body).Decode(&user) == nil {
						created = user.CreatedAt
						if !created.IsZero() {
							meta.AccountAgeDays = int(time.Since(created).Hours() / 24)
						}
					}
				}
			}
		}
	} else {
		created = cachedAge
	}

	if countStale {
		searchURL := "https://api.github.com/search/repositories?q=user:" + username + "+CVE-+in:name&per_page=1"
		req, _ := http.NewRequest("GET", searchURL, nil)
		req.Header.Set("User-Agent", "poc-tracker/1.0")
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var res struct {
					TotalCount int `json:"total_count"`
				}
				if json.NewDecoder(resp.Body).Decode(&res) == nil {
					meta.CveRepoCount = res.TotalCount
				}
			}
		}
	}

	// Wait to save until created is initialized to something, or save what we have if count was updated.
	db.DB.Exec(`
		INSERT INTO github_user_cache (login, account_created_at, cve_repo_count, fetched_at)
		VALUES ($1, NULLIF($2::timestamp with time zone, '0001-01-01 00:00:00+00'::timestamp with time zone), $3, NOW())
		ON CONFLICT (login) DO UPDATE
		SET account_created_at = COALESCE(EXCLUDED.account_created_at, github_user_cache.account_created_at),
		    cve_repo_count = EXCLUDED.cve_repo_count,
		    fetched_at = NOW()
	`, username, created, meta.CveRepoCount)

	return meta
}
