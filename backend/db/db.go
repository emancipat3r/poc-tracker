package db

import (
	"fmt"
	"log"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var DB *sqlx.DB

func InitDB() error {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		return err
	}

	DB = db
	log.Println("Connected to PostgreSQL successfully")

	if err := RunMigrations(); err != nil {
		return fmt.Errorf("migrations failed: %w", err)
	}

	return nil
}

// RunMigrations applies schema additions idempotently so existing databases
// pick up new columns/tables without requiring a full teardown.
func RunMigrations() error {
	migrations := []string{
		// CHUNK 2: enriched_at for skipping re-enrichment
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS enriched_at TIMESTAMP WITH TIME ZONE`,
		// CHUNK 3/5: scoring columns
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS hype_score FLOAT DEFAULT 0`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS media_mentions JSONB DEFAULT '{}'`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS reddit_mentions JSONB DEFAULT '[]'`,
		// CHUNK 5: additional flag columns (most already in init.sql, these are safety additions)
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS inthewild_exploited BOOLEAN DEFAULT false`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS inthewild_last_seen TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS has_nuclei_template BOOLEAN DEFAULT false`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS has_metasploit_module BOOLEAN DEFAULT false`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS has_exploitdb_entry BOOLEAN DEFAULT false`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_score FLOAT`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_percentile FLOAT`,
		// CHUNK 2: sync state table
		`CREATE TABLE IF NOT EXISTS sync_state (
			source_name TEXT PRIMARY KEY,
			last_sync_at TIMESTAMP WITH TIME ZONE,
			last_sync_status TEXT DEFAULT 'never',
			next_sync_at TIMESTAMP WITH TIME ZONE,
			checkpoint JSONB DEFAULT '{}'
		)`,
		// CHUNK 5: pocs table additions
		`ALTER TABLE pocs ADD COLUMN IF NOT EXISTS flagged_malware BOOLEAN DEFAULT false`,
		// CHUNK 6: consolidate published_at → published_date, then drop published_at
		`UPDATE cves SET published_date = published_at WHERE published_date IS NULL AND published_at IS NOT NULL`,
		`ALTER TABLE cves DROP COLUMN IF EXISTS published_at`,
		// CHUNK 7: github user caching and tracking current run starts
		`CREATE TABLE IF NOT EXISTS github_user_cache (
			login VARCHAR(255) PRIMARY KEY,
			account_created_at TIMESTAMP WITH TIME ZONE,
			cve_repo_count INT DEFAULT 0,
			fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		)`,
		`ALTER TABLE sync_state ADD COLUMN IF NOT EXISTS current_run_started_at TIMESTAMP WITH TIME ZONE`,
	}

	for _, m := range migrations {
		if _, err := DB.Exec(m); err != nil {
			log.Printf("Migration warning: %v", err)
		}
	}

	log.Println("Database migrations applied.")
	return nil
}
