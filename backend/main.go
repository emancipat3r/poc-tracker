package main

import (
	"log"

	"github.com/emancipat3r/poc-tracker/backend/api"
	"github.com/emancipat3r/poc-tracker/backend/db"
	"github.com/emancipat3r/poc-tracker/backend/ingester"
)

func main() {
	if err := db.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Start stateful sync coordinator: runs initial cycle immediately,
	// then ticks every 60 minutes. Workers run sequentially within each cycle.
	ingester.StartSyncCoordinator()

	r := api.SetupRouter()
	log.Println("Starting API server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
