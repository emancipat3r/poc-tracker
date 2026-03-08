package main

import (
	"log"
	"time"

	"github.com/emancipat3r/poc-tracker/backend/api"
	"github.com/emancipat3r/poc-tracker/backend/db"
	"github.com/emancipat3r/poc-tracker/backend/ingester"
)

func main() {
	// Wait a bit for DB to be ready in docker compose
	time.Sleep(2 * time.Second)
	
	if err := db.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Start ingestion workers
	go func() {
		for {
			log.Println("Running ingestion cycle...")
			ingester.FetchRSSFeeds()
			ingester.FetchGitHubAdvisories()
			ingester.FetchKEVFeed()
			time.Sleep(30 * time.Minute) // Fetch every 30 minutes
		}
	}()

	r := api.SetupRouter()
	log.Println("Starting API server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
