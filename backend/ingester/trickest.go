package ingester

import (
	"bufio"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

const trickestRepoURL = "https://github.com/trickest/cve.git"
const trickestCloneDir = "/tmp/trickest-cve"

func IngestTrickestPocs() {
	log.Println("Starting Trickest PoC ingestion...")

	// 1. Clone or pull repo
	if _, err := os.Stat(trickestCloneDir); os.IsNotExist(err) {
		cmd := exec.Command("git", "clone", "--depth", "1", trickestRepoURL, trickestCloneDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Failed to clone trickest repo: %v\nOutput: %s", err, string(out))
			return
		}
	} else {
		cmd := exec.Command("git", "-C", trickestCloneDir, "pull")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Failed to pull trickest repo: %v\nOutput: %s", err, string(out))
			return
		}
	}

	// 2. Parse blacklist.txt
	parseBlacklist(filepath.Join(trickestCloneDir, "blacklist.txt"))

	// 3. Process CVE folders
	urlRegex := regexp.MustCompile(`https?://[^\s)\]"']+`)
	
	err := filepath.Walk(trickestCloneDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".md") && strings.HasPrefix(info.Name(), "CVE-") {
			cveID := strings.TrimSuffix(info.Name(), ".md")
			
			// Read file content
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			
			// Find all URLs
			urls := urlRegex.FindAllString(string(content), -1)
			
			for _, u := range urls {
				if strings.Contains(u, "trickest") || strings.Contains(u, "shields.io") || strings.Contains(u, "nvd.nist.gov") {
					continue
				}
				
				// Optional: Just make sure CVE placeholder exists
				db.DB.Exec(`
					INSERT INTO cves (id, title, description, severity)
					VALUES ($1, 'Trickest Discovery', 'Discovered via Trickest aggregator.', 'UNKNOWN')
					ON CONFLICT (id) DO NOTHING
				`, cveID)
				
				// Insert or ignore
				db.DB.Exec(`
					INSERT INTO pocs (cve_id, url, description, source, trust_tier)
					VALUES ($1, $2, $3, 'trickest', 2)
					ON CONFLICT (cve_id, url) DO NOTHING
				`, cveID, u, "Discovered via trickest/cve aggregator")
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Error walking trickest directory: %v", err)
	}

	log.Println("Trickest PoC ingestion complete.")
}

func parseBlacklist(blacklistPath string) {
	file, err := os.Open(blacklistPath)
	if err != nil {
		log.Printf("Failed to open trickest blacklist: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		user := strings.TrimSpace(scanner.Text())
		if user == "" || strings.HasPrefix(user, "#") {
			continue
		}
		
		db.DB.Exec(`
			INSERT INTO poc_blacklist (github_user, reason)
			VALUES ($1, 'Trickest Blacklist')
			ON CONFLICT (github_user) DO NOTHING
		`, user)
	}
}
