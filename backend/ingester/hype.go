package ingester

import (
	"encoding/json"
	"log"
	"math"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

// outletWeights maps outlet keys (matching keys in media_mentions JSONB) to weights.
var outletWeights = map[string]int{
	"bleepingcomputer": 3,
	"thehackernews":    3,
	"darkreading":      2,
	"securityweek":     2,
	"therecord":        2,
}

type hypeRow struct {
	ID                 string          `db:"id"`
	MediaMentions      *json.RawMessage `db:"media_mentions"`
	RedditMentions     *json.RawMessage `db:"reddit_mentions"`
	EpssScore          *float64         `db:"epss_score"`
	IsKev              bool             `db:"is_kev"`
	InTheWildExploited bool             `db:"inthewild_exploited"`
	CvssScore          *float64         `db:"cvss_score"`
}

// ComputeHypeScores recalculates hype_score for all CVEs based on:
//   - Media coverage (0-40 pts)
//   - Community signals: Reddit upvotes + GitHub PoC stars (0-35 pts)
//   - Exploit context: KEV, EPSS, inTheWild (0-15 pts)
//   - Severity bonus (0-10 pts)
func ComputeHypeScores() {
	log.Println("Computing hype scores...")

	var cves []hypeRow
	err := db.DB.Select(&cves, `
		SELECT id, media_mentions, reddit_mentions, epss_score,
		       is_kev, inthewild_exploited, cvss_score
		FROM cves
		WHERE id LIKE 'CVE-%'
	`)
	if err != nil {
		log.Printf("HypeScore: failed to query CVEs: %v", err)
		return
	}

	updated := 0
	for _, cve := range cves {
		score := computeHype(cve)
		db.DB.Exec(`UPDATE cves SET hype_score = $1 WHERE id = $2`, score, cve.ID)
		updated++
	}

	log.Printf("Hype scores computed for %d CVEs.", updated)
}

func computeHype(cve hypeRow) float64 {
	var total float64

	// --- Media score (0-40) ---
	mediaScore := mediaHype(cve.MediaMentions)
	total += math.Min(mediaScore, 40)

	// --- Community score (0-35) ---
	communityScore := communityHype(cve.ID, cve.RedditMentions)
	total += math.Min(communityScore, 35)

	// --- Exploit context (0-15) ---
	var exploitScore float64
	if cve.IsKev {
		exploitScore += 8
	}
	if cve.InTheWildExploited {
		exploitScore += 3
	}
	if cve.EpssScore != nil {
		if *cve.EpssScore > 0.5 {
			exploitScore += 4
		} else if *cve.EpssScore > 0.1 {
			exploitScore += 2
		}
	}
	total += math.Min(exploitScore, 15)

	// --- Severity bonus (0-10) ---
	if cve.CvssScore != nil {
		switch {
		case *cve.CvssScore >= 9.0:
			total += 7
		case *cve.CvssScore >= 8.0:
			total += 4
		case *cve.CvssScore >= 7.0:
			total += 2
		}
	}

	return math.Min(total, 100)
}

// mediaHype scores media coverage from the media_mentions JSONB.
// Structure: {"outlet": [{"title":"...", "url":"...", "published":"..."}]}
func mediaHype(raw *json.RawMessage) float64 {
	if raw == nil {
		return 0
	}
	var mentions map[string][]json.RawMessage
	if err := json.Unmarshal(*raw, &mentions); err != nil {
		return 0
	}

	var score float64
	for outlet, articles := range mentions {
		weight, ok := outletWeights[outlet]
		if !ok {
			weight = 1
		}
		score += float64(len(articles) * weight)
	}
	return score
}

// communityHype scores Reddit upvotes + GitHub PoC stars.
func communityHype(cveID string, redditRaw *json.RawMessage) float64 {
	var score float64

	// Reddit: upvotes (cap 15) + post count * 2 (cap 10)
	if redditRaw != nil {
		var posts []struct {
			Upvotes int `json:"upvotes"`
		}
		if err := json.Unmarshal(*redditRaw, &posts); err == nil {
			postCount := len(posts)
			var totalUpvotes int
			for _, p := range posts {
				totalUpvotes += p.Upvotes
			}
			upvotePoints := math.Min(float64(totalUpvotes)/100, 15) // scale upvotes
			postPoints := math.Min(float64(postCount)*2, 10)
			score += upvotePoints + postPoints
		}
	}

	// GitHub PoC stars (cap 10)
	var totalStars int
	db.DB.QueryRow(`
		SELECT COALESCE(SUM((signals->>'stars')::int), 0)
		FROM pocs
		WHERE cve_id = $1 AND signals->>'stars' IS NOT NULL
	`, cveID).Scan(&totalStars)
	score += math.Min(float64(totalStars)/10, 10)

	return score
}
