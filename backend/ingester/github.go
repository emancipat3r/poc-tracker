package ingester

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"

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

func FetchGitHubAdvisories() {
	log.Println("Fetching GitHub PoCs...")
	resp, err := http.Get("https://api.github.com/search/repositories?q=CVE+OR+PoC&sort=updated&order=desc")
	if err != nil {
		log.Printf("Failed to search GitHub: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("GitHub search returned status: %d", resp.StatusCode)
		return
	}

	var searchResp GitHubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		log.Printf("Failed to decode GitHub response: %v", err)
		return
	}

	cveRegex := regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)

	for _, repo := range searchResp.Items {
		cveID := ""
		
		matches := cveRegex.FindStringSubmatch(repo.Name)
		if len(matches) > 1 {
			cveID = strings.ToUpper(matches[1])
		} else {
			matches = cveRegex.FindStringSubmatch(repo.Description)
			if len(matches) > 1 {
				cveID = strings.ToUpper(matches[1])
			}
		}

		if cveID != "" {
			// Phase 2: Trust Scoring
			var flaggedMalware bool
			var trustScore float64 = 0.0
			
			// Check blacklist
			var blacklisted int
			db.DB.Get(&blacklisted, "SELECT count(*) FROM poc_blacklist WHERE github_user = $1", repo.Owner.Login)
			if blacklisted > 0 {
				flaggedMalware = true
				trustScore -= 10.0
			}

			if repo.StargazersCount > 5 {
				trustScore += 5.0
			} else if repo.StargazersCount == 0 {
				trustScore -= 2.0
			}

			if repo.ForksCount > 2 {
				trustScore += 3.0
			}

			if repo.Owner.Type == "Organization" {
				trustScore += 2.0
			}
			
			// Detect obvious scams via regex on name/description
			descLower := strings.ToLower(repo.Description)
			if strings.Contains(descLower, "botnet") || strings.Contains(descLower, "malware") || strings.Contains(descLower, "rat") {
				flaggedMalware = true
				trustScore -= 5.0
			}

			// Generate signals JSON
			signalsBytes, _ := json.Marshal(map[string]interface{}{
				"stars": repo.StargazersCount,
				"forks": repo.ForksCount,
				"owner": repo.Owner.Login,
			})

			_, err := db.DB.Exec(`
				INSERT INTO cves (id, title, description, severity) 
				VALUES ($1, $2, $3, 'UNKNOWN')
				ON CONFLICT (id) DO UPDATE 
				SET title = COALESCE(cves.title, EXCLUDED.title),
				    description = COALESCE(cves.description, EXCLUDED.description)
			`, cveID, repo.Name, repo.Description)
			
			if err != nil {
				log.Printf("Failed to insert/update GitHub PoC for %s: %v", cveID, err)
			}
            
            // Insert into pocs table as Tier 3
            _, err = db.DB.Exec(`
                INSERT INTO pocs (cve_id, url, description, source, trust_tier, trust_score, signals, flagged_malware)
                VALUES ($1, $2, $3, 'github-search', 3, $4, $5, $6)
                ON CONFLICT (cve_id, url) DO NOTHING
            `, cveID, repo.HtmlURL, repo.Description, trustScore, string(signalsBytes), flaggedMalware)

            if err != nil {
                log.Printf("Failed to insert into pocs table for %s: %v", cveID, err)
            }
		}
	}
	log.Println("GitHub PoC ingestion complete.")
}
