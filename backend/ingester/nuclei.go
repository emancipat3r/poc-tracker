package ingester

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

const nucleiRepoURL = "https://github.com/projectdiscovery/nuclei-templates.git"
const nucleiCloneDir = "/tmp/nuclei-templates"

// IngestNucleiTemplates clones/pulls the nuclei-templates repo and marks CVEs
// that have detection templates. Templates are high-quality, vetted → Tier 1.
func IngestNucleiTemplates() {
	log.Println("Starting Nuclei templates ingestion...")

	// 1. Clone or pull
	isFirstRun := false
	if _, err := os.Stat(nucleiCloneDir); os.IsNotExist(err) {
		isFirstRun = true
		cmd := exec.Command("git", "clone", "--depth", "100", nucleiRepoURL, nucleiCloneDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Failed to clone nuclei-templates: %v\nOutput: %s", err, string(out))
			return
		}
	} else {
		cmd := exec.Command("git", "-C", nucleiCloneDir, "pull")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Failed to pull nuclei-templates: %v\nOutput: %s", err, string(out))
			return
		}
	}

	// 2. Get current HEAD
	headBytes, err := exec.Command("git", "-C", nucleiCloneDir, "rev-parse", "HEAD").Output()
	if err != nil {
		log.Printf("Failed to get nuclei-templates HEAD: %v", err)
		return
	}
	currentHead := strings.TrimSpace(string(headBytes))

	// 3. Load checkpoint
	var lastHash string
	var checkpoint json.RawMessage
	db.DB.QueryRow(`SELECT checkpoint FROM sync_state WHERE source_name = 'nuclei'`).Scan(&checkpoint)
	if len(checkpoint) > 0 {
		var cp map[string]string
		if json.Unmarshal(checkpoint, &cp) == nil {
			lastHash = cp["last_commit"]
		}
	}

	// 4. Determine files to process
	var filesToProcess []string

	if !isFirstRun && lastHash != "" && lastHash != currentHead {
		diffCmd := exec.Command("git", "-C", nucleiCloneDir, "diff", "--name-only", lastHash+".."+currentHead)
		diffOut, err := diffCmd.Output()
		if err != nil {
			log.Printf("Nuclei: git diff failed, falling back to full walk: %v", err)
			filesToProcess = nucleiFullWalk()
		} else {
			for _, line := range strings.Split(strings.TrimSpace(string(diffOut)), "\n") {
				if isNucleiCVETemplate(line) {
					fullPath := filepath.Join(nucleiCloneDir, line)
					if _, err := os.Stat(fullPath); err == nil {
						filesToProcess = append(filesToProcess, fullPath)
					}
				}
			}
			log.Printf("Nuclei: incremental mode, %d changed CVE templates since last sync", len(filesToProcess))
		}
	} else if lastHash == currentHead && !isFirstRun {
		log.Println("Nuclei: no new commits since last sync, skipping.")
		return
	} else {
		filesToProcess = nucleiFullWalk()
	}

	// 5. Process templates — extract CVE IDs and mark has_nuclei_template
	cveIDRegex := regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)
	processed := 0

	for _, path := range filesToProcess {
		cveIDs := extractCVEIDsFromNucleiTemplate(path, cveIDRegex)
		for _, cveID := range cveIDs {
			// Ensure CVE exists
			db.DB.Exec(`
				INSERT INTO cves (id, title, severity)
				VALUES ($1, $2, 'UNKNOWN')
				ON CONFLICT (id) DO NOTHING
			`, cveID, cveID)

			// Mark has_nuclei_template
			db.DB.Exec(`UPDATE cves SET has_nuclei_template = true WHERE id = $1`, cveID)

			// Build a GitHub URL to the template file for the PoC entry
			relPath, _ := filepath.Rel(nucleiCloneDir, path)
			templateURL := "https://github.com/projectdiscovery/nuclei-templates/blob/main/" + relPath

			db.DB.Exec(`
				INSERT INTO pocs (cve_id, url, description, source, trust_tier, trust_score)
				VALUES ($1, $2, 'Nuclei detection template', 'nuclei', 1, 10)
				ON CONFLICT (cve_id, url) DO NOTHING
			`, cveID, templateURL)
		}
		if len(cveIDs) > 0 {
			processed++
		}
	}

	// 6. Save checkpoint
	cpJSON, _ := json.Marshal(map[string]string{"last_commit": currentHead})
	db.DB.Exec(`
		INSERT INTO sync_state (source_name, checkpoint)
		VALUES ('nuclei', $1)
		ON CONFLICT (source_name) DO UPDATE SET checkpoint = $1
	`, string(cpJSON))

	log.Printf("Nuclei templates ingestion complete. Processed %d templates.", processed)
}

// isNucleiCVETemplate checks if a file path looks like a CVE template.
// Nuclei templates are in paths like: http/cves/2024/CVE-2024-1234.yaml
func isNucleiCVETemplate(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "cve") && (strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"))
}

// extractCVEIDsFromNucleiTemplate reads a YAML template and extracts CVE IDs
// from the filename and the classification/cve-id fields.
func extractCVEIDsFromNucleiTemplate(path string, cveRegex *regexp.Regexp) []string {
	seen := make(map[string]bool)

	// Extract from filename
	base := filepath.Base(path)
	for _, m := range cveRegex.FindAllString(base, -1) {
		seen[strings.ToUpper(m)] = true
	}

	// Also scan file content for CVE IDs in metadata (cve-id field)
	f, err := os.Open(path)
	if err != nil {
		goto done
	}
	func() {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		lineCount := 0
		for scanner.Scan() {
			lineCount++
			if lineCount > 50 { // Only scan metadata header
				break
			}
			line := scanner.Text()
			if strings.Contains(line, "cve-id") || strings.Contains(line, "CVE-") {
				for _, m := range cveRegex.FindAllString(line, -1) {
					seen[strings.ToUpper(m)] = true
				}
			}
		}
	}()

done:
	var result []string
	for id := range seen {
		result = append(result, id)
	}
	return result
}

// nucleiFullWalk returns all CVE template file paths from the repo.
func nucleiFullWalk() []string {
	var files []string

	filepath.Walk(nucleiCloneDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip .git directory
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if !info.IsDir() && isNucleiCVETemplate(path) {
			files = append(files, path)
		}
		return nil
	})

	log.Printf("Nuclei: full walk found %d CVE templates", len(files))
	return files
}
