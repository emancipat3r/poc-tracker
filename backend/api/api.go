package api

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/emancipat3r/poc-tracker/backend/db"
	"github.com/emancipat3r/poc-tracker/backend/ingester"
	"github.com/emancipat3r/poc-tracker/backend/models"

	"github.com/jmoiron/sqlx"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()
	
	// Add simple CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	api := r.Group("/api")
	{
		api.GET("/cves", GetCVEs)
		api.GET("/cves/:id", GetCVEByID)
		api.POST("/cves/:id/enrich", EnrichCVE)
		api.GET("/sources", GetSources)
		api.POST("/sync/trigger", TriggerSync)
		api.GET("/sync/status", GetSyncStatus)
		api.POST("/pocs/:id/flag", FlagPoC)
	}

	return r
}

func GetCVEs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	search := c.Query("search")
	severity := c.Query("severity")
	isKev := c.Query("is_kev")
	hasPoc := c.Query("has_poc")
	isWeaponized := c.Query("is_weaponized")
	sortDir := c.DefaultQuery("sort", "desc")
	
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc"
	}
	
	offset := (page - 1) * limit

	// Build shared WHERE clause (reused for both data query and count)
	where := " WHERE 1=1"
	args := []interface{}{}
	argId := 1

	if search != "" {
		where += " AND (title ILIKE $" + strconv.Itoa(argId) + " OR id ILIKE $" + strconv.Itoa(argId) + ")"
		args = append(args, "%"+search+"%")
		argId++
	}
	if severity != "" {
		where += " AND severity = $" + strconv.Itoa(argId)
		args = append(args, severity)
		argId++
	}
	if isKev == "true" {
		where += " AND is_kev = true"
	}
	if hasPoc == "true" {
		where += " AND EXISTS (SELECT 1 FROM pocs WHERE pocs.cve_id = cves.id)"
	}
	if isWeaponized == "true" {
		where += ` AND (
			hype_score > 30
			OR is_kev = true
			OR epss_score > 0.1
			OR inthewild_exploited = true
			OR EXISTS (SELECT 1 FROM pocs WHERE pocs.cve_id = cves.id AND trust_tier IN (1, 2))
		)`
	}

	// Accurate filtered count
	var total int
	if err := db.DB.Get(&total, "SELECT COUNT(*) FROM cves"+where, args...); err != nil {
		log.Printf("Count query error: %v", err)
		total = 0
	}

	// Data query: same WHERE + ORDER + pagination
	// Sort priority:
	//   1. Actual publish date (enriched CVEs)         — NULLS LAST
	//   2. Year extracted from CVE ID (e.g. CVE-2024-) — NULLS LAST
	//   3. Sequence number from CVE ID (e.g. -12345)   — NULLS LAST (newer = higher number)
	//   4. DB insertion time as final tiebreaker
	dataQuery := "SELECT * FROM cves" + where + ` ORDER BY
		COALESCE(published_date, published_at) ` + sortDir + ` NULLS LAST,
		CAST(NULLIF(SPLIT_PART(id, '-', 2), '') AS INTEGER) ` + sortDir + ` NULLS LAST,
		CAST(NULLIF(SPLIT_PART(id, '-', 3), '') AS INTEGER) ` + sortDir + ` NULLS LAST,
		created_at ` + sortDir + `
		LIMIT $` + strconv.Itoa(argId) + ` OFFSET $` + strconv.Itoa(argId+1)
	pageArgs := append(args, limit, offset)

	var cves []models.CVE
	if err := db.DB.Select(&cves, dataQuery, pageArgs...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch PoCs for all returned CVEs in one query
	if len(cves) > 0 {
		var cveIDs []string
		cveMap := make(map[string]*models.CVE)
		for i := range cves {
			cves[i].PoCs = []models.PoC{}
			cveIDs = append(cveIDs, cves[i].ID)
			cveMap[cves[i].ID] = &cves[i]
		}

		queryPocs, argsPocs, err := sqlx.In("SELECT * FROM pocs WHERE cve_id IN (?) AND flagged_malware = false ORDER BY trust_tier ASC", cveIDs)
		if err != nil {
			log.Printf("Error building PoC query: %v", err)
		} else {
			queryPocs = db.DB.Rebind(queryPocs)
			var pocs []models.PoC
			if err := db.DB.Select(&pocs, queryPocs, argsPocs...); err != nil {
				log.Printf("Error fetching PoCs: %v", err)
			} else {
				for _, poc := range pocs {
					if cve, ok := cveMap[poc.CVEID]; ok {
						cve.PoCs = append(cve.PoCs, poc)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, models.CVEListResponse{
		CVEs:  cves,
		Total: total,
	})
}

func GetCVEByID(c *gin.Context) {
	id := c.Param("id")
	var cve models.CVE
	if err := db.DB.Get(&cve, "SELECT * FROM cves WHERE id = $1", id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CVE not found"})
		return
	}
	var pocs []models.PoC
	db.DB.Select(&pocs, "SELECT * FROM pocs WHERE cve_id = $1 ORDER BY trust_tier ASC, trust_score DESC", id)
	if pocs == nil {
		cve.PoCs = []models.PoC{}
	} else {
		cve.PoCs = pocs
	}
	c.JSON(http.StatusOK, cve)
}

func GetSources(c *gin.Context) {
	var sources []models.Source
	err := db.DB.Select(&sources, "SELECT * FROM sources")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sources)
}

// TriggerSync queues a background sync. Accepts optional JSON body {"source":"nvd"}.
// Returns 202 Accepted immediately; sync runs async.
func TriggerSync(c *gin.Context) {
	var body struct {
		Source string `json:"source"`
	}
	c.ShouldBindJSON(&body) // ignore error — body is optional

	queued := ingester.TriggerSync(body.Source)
	if !queued {
		c.JSON(http.StatusAccepted, gin.H{"status": "already_queued", "message": "A sync is already pending."})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "queued", "source": body.Source})
}

// GetSyncStatus returns current sync state for all sources.
func GetSyncStatus(c *gin.Context) {
	rows, err := db.DB.Queryx("SELECT source_name, last_sync_at, last_sync_status, next_sync_at FROM sync_state ORDER BY source_name")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type SyncEntry struct {
		SourceName      string     `db:"source_name" json:"source_name"`
		LastSyncAt      *time.Time `db:"last_sync_at" json:"last_sync_at"`
		LastSyncStatus  string     `db:"last_sync_status" json:"last_sync_status"`
		NextSyncAt      *time.Time `db:"next_sync_at" json:"next_sync_at"`
	}

	var entries []SyncEntry
	for rows.Next() {
		var e SyncEntry
		if err := rows.StructScan(&e); err != nil {
			log.Printf("Error scanning sync_state row: %v", err)
			continue
		}
		entries = append(entries, e)
	}

	c.JSON(http.StatusOK, gin.H{
		"running": ingester.IsSyncRunning(),
		"sources": entries,
	})
}

// FlagPoC marks a PoC as potential malware and blacklists the GitHub repo owner.
func FlagPoC(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poc id"})
		return
	}

	// Fetch the PoC to get its URL and signals
	var poc models.PoC
	if err := db.DB.Get(&poc, "SELECT * FROM pocs WHERE id = $1", id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
		return
	}

	// Mark as malware
	db.DB.Exec("UPDATE pocs SET flagged_malware = true WHERE id = $1", id)

	// Extract GitHub owner from URL and blacklist them
	owner := extractGitHubOwner(poc.URL)
	if owner != "" {
		db.DB.Exec(`
			INSERT INTO poc_blacklist (github_user, reason)
			VALUES ($1, 'Flagged via UI as potential malware')
			ON CONFLICT (github_user) DO NOTHING
		`, owner)
		log.Printf("Blacklisted GitHub user %q (PoC ID %d flagged as malware)", owner, id)
	}

	c.JSON(http.StatusOK, gin.H{"status": "flagged", "poc_id": id, "blacklisted_user": owner})
}

// extractGitHubOwner parses a GitHub URL and returns the repo owner login.
func extractGitHubOwner(rawURL string) string {
	// Expected: https://github.com/{owner}/{repo}
	const prefix = "https://github.com/"
	if len(rawURL) <= len(prefix) {
		return ""
	}
	if rawURL[:len(prefix)] != prefix {
		return ""
	}
	rest := rawURL[len(prefix):]
	slash := 0
	for i, ch := range rest {
		if ch == '/' {
			slash = i
			break
		}
	}
	if slash == 0 {
		return rest // no slash found, entire path is owner
	}
	return rest[:slash]
}

// EnrichCVE triggers on-demand NVD enrichment for a single CVE.
func EnrichCVE(c *gin.Context) {
	id := c.Param("id")

	// Verify the CVE exists
	var count int
	if err := db.DB.Get(&count, "SELECT COUNT(*) FROM cves WHERE id = $1", id); err != nil || count == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "CVE not found"})
		return
	}

	// Clear enriched_at so the enricher will re-fetch
	db.DB.Exec("UPDATE cves SET enriched_at = NULL WHERE id = $1", id)

	go ingester.EnrichSingleCVE(id)

	// Return the current (pre-enrichment) record; client can poll for updates
	var cve models.CVE
	db.DB.Get(&cve, "SELECT * FROM cves WHERE id = $1", id)
	var pocs []models.PoC
	db.DB.Select(&pocs, "SELECT * FROM pocs WHERE cve_id = $1", id)
	if pocs == nil {
		cve.PoCs = []models.PoC{}
	} else {
		cve.PoCs = pocs
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Enrichment started. Refresh in a few seconds.",
		"cve":     cve,
	})
}
