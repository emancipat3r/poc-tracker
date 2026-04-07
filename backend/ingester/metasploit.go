package ingester

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

const metasploitRepoURL = "https://github.com/rapid7/metasploit-framework.git"
const metasploitCloneDir = "/tmp/metasploit-framework"

// IngestMetasploitModules clones/pulls the metasploit-framework repo (sparse checkout
// of modules/exploits only) and marks CVEs that have Metasploit modules → Tier 1.
func IngestMetasploitModules() {
	log.Println("Starting Metasploit modules ingestion...")

	// 1. Clone (sparse) or pull — only need modules/exploits to save disk space
	isFirstRun := false
	if _, err := os.Stat(metasploitCloneDir); os.IsNotExist(err) {
		isFirstRun = true
		if err := sparseCloneMetasploit(); err != nil {
			log.Printf("Failed to clone metasploit-framework: %v", err)
			return
		}
	} else {
		cmd := exec.Command("git", "-C", metasploitCloneDir, "pull")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Failed to pull metasploit-framework: %v\nOutput: %s", err, string(out))
			return
		}
	}

	// 2. Get current HEAD
	headBytes, err := exec.Command("git", "-C", metasploitCloneDir, "rev-parse", "HEAD").Output()
	if err != nil {
		log.Printf("Failed to get metasploit HEAD: %v", err)
		return
	}
	currentHead := strings.TrimSpace(string(headBytes))

	// 3. Load checkpoint
	var lastHash string
	var checkpoint json.RawMessage
	db.DB.QueryRow(`SELECT checkpoint FROM sync_state WHERE source_name = 'metasploit'`).Scan(&checkpoint)
	if len(checkpoint) > 0 {
		var cp map[string]string
		if json.Unmarshal(checkpoint, &cp) == nil {
			lastHash = cp["last_commit"]
		}
	}

	// 4. Determine files to process
	var filesToProcess []string
	exploitsDir := filepath.Join(metasploitCloneDir, "modules", "exploits")

	if !isFirstRun && lastHash != "" && lastHash != currentHead {
		diffCmd := exec.Command("git", "-C", metasploitCloneDir, "diff", "--name-only", lastHash+".."+currentHead)
		diffOut, err := diffCmd.Output()
		if err != nil {
			log.Printf("Metasploit: git diff failed, falling back to full walk: %v", err)
			filesToProcess = metasploitFullWalk(exploitsDir)
		} else {
			for _, line := range strings.Split(strings.TrimSpace(string(diffOut)), "\n") {
				if strings.HasPrefix(line, "modules/exploits/") && strings.HasSuffix(line, ".rb") {
					fullPath := filepath.Join(metasploitCloneDir, line)
					if _, err := os.Stat(fullPath); err == nil {
						filesToProcess = append(filesToProcess, fullPath)
					}
				}
			}
			log.Printf("Metasploit: incremental mode, %d changed exploit modules since last sync", len(filesToProcess))
		}
	} else if lastHash == currentHead && !isFirstRun {
		log.Println("Metasploit: no new commits since last sync, skipping.")
		return
	} else {
		filesToProcess = metasploitFullWalk(exploitsDir)
	}

	// 5. Process modules — extract CVE IDs from Ruby source
	processed := 0

	for _, path := range filesToProcess {
		cveIDs := extractCVEIDsFromMetasploitModule(path)
		for _, cveID := range cveIDs {
			// Ensure CVE exists
			db.DB.Exec(`
				INSERT INTO cves (id, title, severity)
				VALUES ($1, $2, 'UNKNOWN')
				ON CONFLICT (id) DO NOTHING
			`, cveID, cveID)

			// Mark has_metasploit_module
			db.DB.Exec(`UPDATE cves SET has_metasploit_module = true WHERE id = $1`, cveID)

			// Build GitHub URL to the module file
			relPath, _ := filepath.Rel(metasploitCloneDir, path)
			moduleURL := "https://github.com/rapid7/metasploit-framework/blob/master/" + relPath

			db.DB.Exec(`
				INSERT INTO pocs (cve_id, url, description, source, trust_tier, trust_score)
				VALUES ($1, $2, 'Metasploit exploit module', 'metasploit', 1, 10)
				ON CONFLICT (cve_id, url) DO NOTHING
			`, cveID, moduleURL)
		}
		if len(cveIDs) > 0 {
			processed++
		}
	}

	// 6. Save checkpoint
	cpJSON, _ := json.Marshal(map[string]string{"last_commit": currentHead})
	db.DB.Exec(`
		INSERT INTO sync_state (source_name, checkpoint)
		VALUES ('metasploit', $1)
		ON CONFLICT (source_name) DO UPDATE SET checkpoint = $1
	`, string(cpJSON))

	log.Printf("Metasploit modules ingestion complete. Processed %d modules.", processed)
}

// sparseCloneMetasploit does a sparse checkout of only modules/exploits to save
// disk and bandwidth (~100MB vs ~2GB for the full repo).
func sparseCloneMetasploit() error {
	// Initialize sparse clone
	cmd := exec.Command("git", "clone", "--filter=blob:none", "--sparse", metasploitRepoURL, metasploitCloneDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("clone failed: %v\nOutput: %s", err, string(out))
	}

	// Set sparse-checkout to only modules/exploits
	cmd = exec.Command("git", "-C", metasploitCloneDir, "sparse-checkout", "set", "modules/exploits")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sparse-checkout failed: %v\nOutput: %s", err, string(out))
	}

	return nil
}

// extractCVEIDsFromMetasploitModule scans a Ruby module file for CVE references.
// Metasploit uses the format: ['CVE', '2024-1234'] in the references array.
func extractCVEIDsFromMetasploitModule(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Match both ['CVE', '2024-1234'] and direct CVE-2024-1234 patterns
	msfCVERegex := regexp.MustCompile(`['"]CVE['"],\s*['"](\d{4}-\d{4,})['"]`)
	directCVERegex := regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Metasploit-style reference
		for _, m := range msfCVERegex.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				seen["CVE-"+m[1]] = true
			}
		}

		// Direct CVE ID reference
		for _, m := range directCVERegex.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				seen[strings.ToUpper(m[1])] = true
			}
		}
	}

	var result []string
	for id := range seen {
		result = append(result, id)
	}
	return result
}

// metasploitFullWalk returns all .rb files under the exploits directory.
func metasploitFullWalk(exploitsDir string) []string {
	var files []string

	filepath.Walk(exploitsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".rb") {
			files = append(files, path)
		}
		return nil
	})

	log.Printf("Metasploit: full walk found %d exploit modules", len(files))
	return files
}
