package ingester

import (
	"log"
	"sync"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/db"
)

var (
	triggerCh  = make(chan string, 5)
	syncMu     sync.Mutex
	syncActive bool
)

// StartSyncCoordinator runs an initial sync cycle, then ticks every 60 minutes.
// Workers execute sequentially within each cycle to avoid overlapping rate limits.
func StartSyncCoordinator() {
	// Startup cleanup for orphaned running workers from previous crashed runs
	_, err := db.DB.Exec(`UPDATE sync_state SET last_sync_status = 'error', current_run_started_at = NULL WHERE last_sync_status = 'running'`)
	if err != nil {
		log.Printf("Failed to clean up orphaned sync statuses: %v", err)
	}

	go func() {
		log.Println("Sync coordinator starting initial cycle...")
		runSyncCycle("")

		ticker := time.NewTicker(60 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case source := <-triggerCh:
				log.Printf("Sync triggered for source: %q", source)
				runSyncCycle(source)
			case <-ticker.C:
				log.Println("Hourly sync tick.")
				runSyncCycle("")
			}
		}
	}()
}

// TriggerSync queues a sync for the given source (empty = full sync).
// Returns false if the queue is full (sync already pending).
func TriggerSync(source string) bool {
	select {
	case triggerCh <- source:
		return true
	default:
		return false
	}
}

// IsSyncRunning reports whether a sync cycle is currently executing.
func IsSyncRunning() bool {
	syncMu.Lock()
	defer syncMu.Unlock()
	return syncActive
}

// runSyncCycle executes workers sequentially. If source is non-empty, only
// that source runs; otherwise all sources run in order.
func runSyncCycle(source string) {
	syncMu.Lock()
	if syncActive {
		syncMu.Unlock()
		log.Println("Sync already running, skipping cycle.")
		return
	}
	syncActive = true
	syncMu.Unlock()

	defer func() {
		syncMu.Lock()
		syncActive = false
		syncMu.Unlock()
	}()

	log.Printf("Starting sync cycle (source=%q)...", source)

	run := func(name string, fn func()) {
		if source != "" && source != name {
			return
		}
		setSyncStatus(name, "running")
		start := time.Now()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Worker %q panicked: %v", name, r)
				setSyncStatus(name, "error")
			}
		}()
		fn()
		log.Printf("Worker %q completed in %s", name, time.Since(start).Round(time.Second))
		setSyncStatus(name, "success")
	}

	// Worker execution order (sequential):
	// 1. Fetch new CVEs from primary sources
	run("nvd", FetchNVDUpdates)
	run("kev", FetchKEVFeed)
	// 2. Vetted PoC aggregators (Tier 1-2) — run before GitHub so trust scoring can cross-reference
	run("trickest", IngestTrickestPocs)
	run("nuclei", IngestNucleiTemplates)
	run("metasploit", IngestMetasploitModules)
	run("sploitus", FetchSploitusPocs)
	// 3. Unvetted search (Tier 3) — benefits from knowing which CVEs already have vetted PoCs
	run("github", FetchGitHubAdvisories)
	// 4. Signals & enrichment
	run("rss", FetchRSSFeeds)
	run("reddit", FetchRedditMentions)
	run("nvd-enrich", EnrichPendingCVEs)
	run("epss", FetchEPSSScores)
	run("inthewild", FetchInTheWild)
	run("hype", ComputeHypeScores)

	log.Println("Sync cycle complete.")
}

func setSyncStatus(source, status string) {
	var query string
	if status == "running" {
		query = `
			INSERT INTO sync_state (source_name, current_run_started_at, last_sync_status)
			VALUES ($1, NOW(), $2)
			ON CONFLICT (source_name) DO UPDATE
			SET current_run_started_at = NOW(),
			    last_sync_status = $2
		`
	} else {
		query = `
			INSERT INTO sync_state (source_name, last_sync_at, last_sync_status, current_run_started_at)
			VALUES ($1, NOW(), $2, NULL)
			ON CONFLICT (source_name) DO UPDATE
			SET last_sync_at = NOW(),
			    last_sync_status = $2,
			    current_run_started_at = NULL
		`
	}
	_, err := db.DB.Exec(query, source, status)
	if err != nil {
		log.Printf("Failed to update sync_state for %q: %v", source, err)
	}
}
