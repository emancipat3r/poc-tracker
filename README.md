# OSINT CVE Tracker

A fully containerized full-stack application for tracking Common Vulnerabilities and Exposures (CVEs), featuring specific streams for the latest GitHub Proof-of-Concepts (PoCs), CISA's Known Exploited Vulnerabilities (KEV), and EPSS / In-The-Wild exploitability indicators.

## Architecture

- **Backend**: Go (Golang), Gin, sqlx, PostgreSQL
- **Frontend**: React, TypeScript, Vite (Vanilla CSS w/ Glassmorphism design system)
- **Infrastructure**: Docker Compose

## Features

- **Multi-Tier PoC Ingestion**:
  - **Tier 1**: Official references (NVD APIs).
  - **Tier 2**: Vetted aggregators (`trickest/cve`).
  - **Tier 3 (Discovery)**: GitHub Search API with automated trust scoring and malware filtering (flagging common scam patterns and blacklisted authors).
- **In-The-Wild & EPSS Scoring**: Integrates Exploit Prediction Scoring System (FIRST.org) and `inthewild.io` to provide real-world exploitation probabilities, allowing you to filter for strictly "Actionable / Weaponized" targets.
- **Trending/Exploited (KEV)**: Actively monitors the CISA JSON feed to flag and track actively exploited vulnerabilities.
- **Automated Feed Ingestion**: Background routines automatically ingest external security RSS feeds and sync them into the PostgreSQL database.
- **Search & Filter**: Quickly find CVEs by ID, Title, or Severity using the REST API or the dashboard.

## Getting Started

### Prerequisites
- Docker and Docker Compose installed on your system.

### Running the Application

1. **Clone the repository and enter the directory**
   ```bash
   git clone <repository-url>
   cd poc-tracker
   ```

2. **Start the application**
   ```bash
   docker compose up -d --build
   ```
   *This single command will spin up the PostgreSQL database, compile the Go backend, and bundle the React frontend.*

3. **Access the Tracking Dashboard**
   - Navigate to **[http://localhost:3000](http://localhost:3000)** in your browser.
   - The API is available at `http://localhost:8080`.

## API Endpoints

- `GET /api/cves` - List CVEs (Query params: `page`, `limit`, `search`, `severity`, `is_kev`, `has_poc`, `is_weaponized`)
- `GET /api/cves/:id` - Get specific CVE by ID
- `GET /api/sources` - List tracked sources

## License

See the `LICENSE` file for more details.
