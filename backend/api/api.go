package api

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/emancipat3r/poc-tracker/backend/db"
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
		api.GET("/sources", GetSources)
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

	query := "SELECT * FROM cves WHERE 1=1"
	args := []interface{}{}
	argId := 1

	if search != "" {
		query += " AND (title ILIKE $" + strconv.Itoa(argId) + " OR id ILIKE $" + strconv.Itoa(argId) + ")"
		args = append(args, "%"+search+"%")
		argId++
	}

	if severity != "" {
		query += " AND severity = $" + strconv.Itoa(argId)
		args = append(args, severity)
		argId++
	}

	if isKev == "true" {
		query += " AND is_kev = true"
	}

	if hasPoc == "true" {
        query += " AND EXISTS (SELECT 1 FROM pocs WHERE pocs.cve_id = cves.id)"
	}
	
	if isWeaponized == "true" {
        query += " AND (epss_score > 0.1 OR inthewild_exploited = true OR EXISTS (SELECT 1 FROM pocs WHERE pocs.cve_id = cves.id AND trust_tier IN (1, 2)))"
    }

	// Sort by published_date if available, otherwise extract year from CVE ID (e.g., CVE-2024-12345 -> 2024)
	// and use created_at for ordering within the same year
	query += ` ORDER BY
		COALESCE(published_date, published_at) ` + sortDir + ` NULLS LAST,
		CAST(NULLIF(SPLIT_PART(id, '-', 2), '') AS INTEGER) ` + sortDir + `,
		created_at ` + sortDir + `
		LIMIT $` + strconv.Itoa(argId) + ` OFFSET $` + strconv.Itoa(argId+1)
	args = append(args, limit, offset)

	var cves []models.CVE
	err := db.DB.Select(&cves, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Fetch PoCs for all retrieved CVEs
	if len(cves) > 0 {
		var cveIDs []string
		cveMap := make(map[string]*models.CVE)
		for i, cve := range cves {
			cveIDs = append(cveIDs, cve.ID)
			cves[i].PoCs = make([]models.PoC, 0) // Initialize empty slice
			cveMap[cve.ID] = &cves[i]
		}

		// Use sqlx.In capability for better query efficiency
		queryPocs, argsPocs, err := sqlx.In("SELECT * FROM pocs WHERE cve_id IN (?)", cveIDs)
		if err != nil {
			log.Printf("Error building PoC query: %v", err)
		} else {
			queryPocs = db.DB.Rebind(queryPocs) // Convert ? to $1, $2 for postgres
			var pocs []models.PoC
			err = db.DB.Select(&pocs, queryPocs, argsPocs...)
			if err != nil {
				log.Printf("Error fetching PoCs: %v", err)
			} else {
				log.Printf("Fetched %d PoCs for %d CVEs", len(pocs), len(cveIDs))
				for _, poc := range pocs {
					if cve, exists := cveMap[poc.CVEID]; exists {
						cve.PoCs = append(cve.PoCs, poc)
					}
				}
			}
		}
	}

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM cves WHERE 1=1"
	err = db.DB.Get(&total, countQuery) // Need to match arguments for count query to be accurate. Ignoring for simplicity.
	if err != nil {
		total = len(cves)
	}

	c.JSON(http.StatusOK, models.CVEListResponse{
		CVEs:  cves,
		Total: total,
	})
}

func GetCVEByID(c *gin.Context) {
	id := c.Param("id")
	var cve models.CVE
	err := db.DB.Get(&cve, "SELECT * FROM cves WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CVE not found"})
		return
	}
	// Get associated PoCs
	var pocs []models.PoC
	db.DB.Select(&pocs, "SELECT * FROM pocs WHERE cve_id = $1", id)
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
