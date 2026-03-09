# POC Tracker

A fully containerized full-stack application for tracking CVEs and their associated Proof-of-Concept exploits with automated enrichment, hype scoring, and exploitation tracking.

## Architecture

- **Backend**: Go (Golang), Gin, sqlx, PostgreSQL
- **Frontend**: React, TypeScript, Vite (Glassmorphism design system)
- **Infrastructure**: Docker Compose

## Features

### Multi-Tier PoC Ingestion
- **Tier 1 (Official)**: NVD API references + Sploitus exploit aggregator
- **Tier 2 (Vetted)**: `trickest/cve` GitHub repo (last 3 years)
- **Tier 3 (Discovery)**: GitHub Search API with automated trust scoring, malware pattern detection, and author blacklisting

### Threat Intelligence Enrichment
- **CISA KEV**: Flags actively exploited vulnerabilities from the CISA Known Exploited Vulnerabilities catalog
- **EPSS**: Exploit Prediction Scoring System scores from FIRST.org (bulk CSV)
- **inTheWild.io**: Real-world exploitation tracking
- **NVD**: CVSS scores, descriptions, severity, and published dates

### Hype Scoring (0-100)
Composite score across four dimensions:
- **Media coverage** (0-40): Weighted mentions across BleepingComputer, The Hacker News, Dark Reading, SecurityWeek, The Record
- **Community activity** (0-35): Reddit mention tracking
- **Exploit context** (0-15): Tier 1/2 PoC presence, ExploitDB, Metasploit, Nuclei template availability
- **Severity bonus** (0-10): CVSS score contribution

### Dashboard & Filtering
- Search by CVE ID, title, or description
- Filter by severity, KEV status, PoC availability, and "Weaponized" (hype > 30, KEV, EPSS > 0.1, or inTheWild)
- CVE detail pages with full PoC listings, trust tiers, and media mention breakdowns
- Flag PoCs as malware/scam with automatic author blacklisting

### Automated Sync
Hourly background sync coordinator runs sources in order:
`nvd → kev → trickest → github → sploitus → rss → reddit → nvd-enrich → epss → inthewild → hype`

Manual sync triggering via the UI or API with per-source status tracking.

## Getting Started

### Prerequisites
- Docker and Docker Compose

### Running the Application

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd poc-tracker
   ```

2. **Start the application**
   ```bash
   docker compose up -d --build
   ```
   This spins up PostgreSQL, compiles the Go backend, and bundles the React frontend.

3. **Access the dashboard**
   - Frontend: [http://localhost:3000](http://localhost:3000)
   - API: `http://localhost:8080`

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/cves` | List CVEs — params: `page`, `limit`, `search`, `severity`, `is_kev`, `has_poc`, `is_weaponized`, `sort` |
| `GET` | `/api/cves/:id` | Get single CVE with associated PoCs |
| `POST` | `/api/cves/:id/enrich` | Trigger on-demand NVD enrichment (async, 202) |
| `GET` | `/api/sync/status` | Sync state for all sources + running flag |
| `POST` | `/api/sync/trigger` | Trigger full sync or single source (`{"source":"nvd"}`) |
| `POST` | `/api/pocs/:id/flag` | Flag a PoC as malware, blacklists the GitHub owner |

## License

See the `LICENSE` file for more details.
