package ingester

import (
	"bufio"
	"encoding/json"
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
	isFirstRun := false
	if _, err := os.Stat(trickestCloneDir); os.IsNotExist(err) {
		isFirstRun = true
		cmd := exec.Command("git", "clone", trickestRepoURL, trickestCloneDir)
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

	// 3. Get current HEAD hash
	headBytes, err := exec.Command("git", "-C", trickestCloneDir, "rev-parse", "HEAD").Output()
	if err != nil {
		log.Printf("Failed to get trickest HEAD: %v", err)
		return
	}
	currentHead := strings.TrimSpace(string(headBytes))

	// 4. Load last checkpoint
	var lastHash string
	var checkpoint json.RawMessage
	db.DB.QueryRow(`SELECT checkpoint FROM sync_state WHERE source_name = 'trickest'`).Scan(&checkpoint)
	if len(checkpoint) > 0 {
		var cp map[string]string
		if json.Unmarshal(checkpoint, &cp) == nil {
			lastHash = cp["last_commit"]
		}
	}

	// 5. Determine which files to process
	urlRegex := regexp.MustCompile(`https?://[^\s)\]"']+`)
	var filesToProcess []string

	if !isFirstRun && lastHash != "" && lastHash != currentHead {
		// Incremental: only process changed/added .md files since last sync
		diffCmd := exec.Command("git", "-C", trickestCloneDir, "diff", "--name-only", lastHash+".."+currentHead)
		diffOut, err := diffCmd.Output()
		if err != nil {
			log.Printf("Trickest: git diff failed (hash may be too old), falling back to full walk: %v", err)
			filesToProcess = trickestFullWalk()
		} else {
			for _, line := range strings.Split(strings.TrimSpace(string(diffOut)), "\n") {
				if strings.HasSuffix(line, ".md") && strings.Contains(line, "CVE-") {
					fullPath := filepath.Join(trickestCloneDir, line)
					if _, err := os.Stat(fullPath); err == nil {
						filesToProcess = append(filesToProcess, fullPath)
					}
				}
			}
			log.Printf("Trickest: incremental mode, %d changed files since last sync", len(filesToProcess))
		}
	} else if lastHash == currentHead && !isFirstRun {
		log.Println("Trickest: no new commits since last sync, skipping.")
		return
	} else {
		// First run or no checkpoint: full walk
		filesToProcess = trickestFullWalk()
	}

	// 6. Process files
	processed := 0
	for _, path := range filesToProcess {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}

		cveID := strings.TrimSuffix(info.Name(), ".md")
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		urls := urlRegex.FindAllString(string(content), -1)
		var validURLs []string
		for _, u := range urls {
			if strings.Contains(u, "trickest") || strings.Contains(u, "shields.io") || strings.Contains(u, "nvd.nist.gov") {
				continue
			}
			validURLs = append(validURLs, u)
		}
		if len(validURLs) == 0 {
			continue
		}

		db.DB.Exec(`
			INSERT INTO cves (id, title, severity)
			VALUES ($1, $2, 'UNKNOWN')
			ON CONFLICT (id) DO NOTHING
		`, cveID, cveID)

		for _, u := range validURLs {
			db.DB.Exec(`
				INSERT INTO pocs (cve_id, url, description, source, trust_tier)
				VALUES ($1, $2, $3, 'trickest', 2)
				ON CONFLICT (cve_id, url) DO NOTHING
			`, cveID, u, "Discovered via trickest/cve aggregator")
		}
		processed++
	}

	// 7. Save checkpoint
	cpJSON, _ := json.Marshal(map[string]string{"last_commit": currentHead})
	db.DB.Exec(`
		INSERT INTO sync_state (source_name, checkpoint)
		VALUES ('trickest', $1)
		ON CONFLICT (source_name) DO UPDATE SET checkpoint = $1
	`, string(cpJSON))

	log.Printf("Trickest PoC ingestion complete. Processed %d CVE files.", processed)
}

// trickestFullWalk returns all CVE .md file paths from the last N years.
func trickestFullWalk() []string {
	currentYear := time.Now().Year()
	minYear := currentYear - trickestYearsToProcess + 1

	entries, err := os.ReadDir(trickestCloneDir)
	if err != nil {
		log.Printf("Failed to read trickest directory: %v", err)
		return nil
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
	sort.Sort(sort.Reverse(sort.IntSlice(yearDirs)))

	var files []string
	for _, year := range yearDirs {
		yearPath := filepath.Join(trickestCloneDir, strconv.Itoa(year))
		filepath.Walk(yearPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(info.Name(), ".md") && strings.HasPrefix(info.Name(), "CVE-") {
				files = append(files, path)
			}
			return nil
		})
	}

	log.Printf("Trickest: full walk found %d CVE files", len(files))
	return files
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
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}

		// Blacklist entries may be "user/repo" format — extract just the username
		user := entry
		if idx := strings.Index(entry, "/"); idx > 0 {
			user = entry[:idx]
		}

		db.DB.Exec(`
			INSERT INTO poc_blacklist (github_user, reason)
			VALUES ($1, 'Trickest Blacklist')
			ON CONFLICT (github_user) DO NOTHING
		`, user)
	}
}
