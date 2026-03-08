package ingester

import (
	"bufio"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

const trickestRepoURL = "https://github.com/trickest/cve.git"
const trickestCloneDir = "/tmp/trickest-cve"

// Only process CVEs from the last N years
const trickestYearsToProcess = 3

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

	// 3. Get year directories and sort in reverse chronological order
	currentYear := time.Now().Year()
	minYear := currentYear - trickestYearsToProcess + 1

	entries, err := os.ReadDir(trickestCloneDir)
	if err != nil {
		log.Printf("Failed to read trickest directory: %v", err)
		return
	}

	var yearDirs []int
	for _, entry := range entries {
		if entry.IsDir() {
			year, err := strconv.Atoi(entry.Name())
			if err == nil && year >= minYear && year <= currentYear {
				yearDirs = append(yearDirs, year)
			}
		}
	}

	// Sort years descending (2026, 2025, 2024...)
	sort.Sort(sort.Reverse(sort.IntSlice(yearDirs)))

	log.Printf("Processing Trickest CVEs for years: %v", yearDirs)

	// 4. Process CVE folders in reverse chronological order
	urlRegex := regexp.MustCompile(`https?://[^\s)\]"']+`)
	var cveIDsToEnrich []string

	for _, year := range yearDirs {
		yearPath := filepath.Join(trickestCloneDir, strconv.Itoa(year))

		err := filepath.Walk(yearPath, func(path string, info os.FileInfo, err error) error {
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

				// Filter valid URLs first
				var validURLs []string
				for _, u := range urls {
					if strings.Contains(u, "trickest") || strings.Contains(u, "shields.io") || strings.Contains(u, "nvd.nist.gov") {
						continue
					}
					validURLs = append(validURLs, u)
				}

				if len(validURLs) == 0 {
					return nil
				}

				// Always create CVE first (if not exists) before inserting PoCs
				_, err = db.DB.Exec(`
					INSERT INTO cves (id, title, severity)
					VALUES ($1, $2, 'UNKNOWN')
					ON CONFLICT (id) DO NOTHING
				`, cveID, cveID)
				if err != nil {
					log.Printf("Failed to create CVE %s: %v", cveID, err)
					return nil
				}

				// Now insert PoCs
				for _, u := range validURLs {
					db.DB.Exec(`
						INSERT INTO pocs (cve_id, url, description, source, trust_tier)
						VALUES ($1, $2, $3, 'trickest', 2)
						ON CONFLICT (cve_id, url) DO NOTHING
					`, cveID, u, "Discovered via trickest/cve aggregator")
				}

				// Queue for NVD enrichment
				cveIDsToEnrich = append(cveIDsToEnrich, cveID)
			}
			return nil
		})

		if err != nil {
			log.Printf("Error walking trickest year %d directory: %v", year, err)
		}
	}

	log.Printf("Trickest PoC ingestion complete. Queued %d CVEs for NVD enrichment.", len(cveIDsToEnrich))

	// 5. Enrich CVEs with NVD data (batch process to avoid rate limits)
	if len(cveIDsToEnrich) > 0 {
		enrichCVEsFromNVD(cveIDsToEnrich)
	}
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
