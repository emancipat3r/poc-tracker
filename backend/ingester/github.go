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
	Name        string `json:"name"`
	Description string `json:"description"`
	HtmlURL     string `json:"html_url"`
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
            
            // Insert into pocs table
            _, err = db.DB.Exec(`
                INSERT INTO pocs (cve_id, url, description)
                VALUES ($1, $2, $3)
                ON CONFLICT (cve_id, url) DO NOTHING
            `, cveID, repo.HtmlURL, repo.Description)

            if err != nil {
                log.Printf("Failed to insert into pocs table for %s: %v", cveID, err)
            }
			
			if err != nil {
				log.Printf("Failed to insert/update GitHub PoC for %s: %v", cveID, err)
			}
		}
	}
	log.Println("GitHub PoC ingestion complete.")
}
