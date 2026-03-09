package ingester

import (
	"bufio"
	"compress/gzip"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

type epssRow struct {
	cveID      string
	score      float64
	percentile float64
}

// FetchEPSSScores downloads the daily bulk EPSS CSV from FIRST.org/Cyentia,
// parses it, and updates epss_score / epss_percentile for all known CVEs.
func FetchEPSSScores() {
	log.Println("Starting EPSS bulk score ingestion...")

	client := &http.Client{Timeout: 120 * time.Second}
	req, _ := http.NewRequest("GET", "https://epss.cyentia.com/epss_scores-current.csv.gz", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("EPSS: failed to download bulk CSV: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("EPSS: server returned status %d", resp.StatusCode)
		return
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		log.Printf("EPSS: failed to open gzip reader: %v", err)
		return
	}
	defer gz.Close()

	// Build a set of CVE IDs we care about to skip rows we don't track
	var knownCVEs []string
	if err := db.DB.Select(&knownCVEs, "SELECT id FROM cves WHERE id LIKE 'CVE-%'"); err != nil {
		log.Printf("EPSS: failed to load known CVE IDs: %v", err)
		return
	}
	known := make(map[string]bool, len(knownCVEs))
	for _, id := range knownCVEs {
		known[id] = true
	}

	var batch []epssRow
	scanner := bufio.NewScanner(gz)
	linesRead := 0

	for scanner.Scan() {
		line := scanner.Text()
		linesRead++

		// Skip comment and header lines
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "cve") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		cveID := strings.TrimSpace(parts[0])
		if !known[cveID] {
			continue
		}

		score, err1 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
		if err1 != nil || err2 != nil {
			continue
		}

		batch = append(batch, epssRow{cveID, score, pct})

		if len(batch) >= 500 {
			flushEPSSBatch(batch)
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		flushEPSSBatch(batch)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("EPSS: scanner error: %v", err)
	}

	log.Printf("EPSS ingestion complete. Scanned %d lines.", linesRead)
}

func flushEPSSBatch(rows []epssRow) {
	for _, r := range rows {
		db.DB.Exec(`
			UPDATE cves SET epss_score = $1, epss_percentile = $2 WHERE id = $3
		`, r.score, r.percentile, r.cveID)
	}
}
