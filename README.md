# PoC Tracker

A fully containerized full-stack application for tracking CVEs and their associated Proof-of-Concept exploits with automated enrichment, hype scoring, and exploitation tracking.

## Architecture

- **Backend**: Go (Golang), Gin, sqlx, PostgreSQL
- **Frontend**: React, TypeScript, Vite (Glassmorphism design system)
- **Infrastructure**: Docker Compose

## Features

### Multi-Tier PoC Ingestion
- **Tier 1 (Official)**: Exploit-DB, PacketStorm (via Sploitus), Nuclei detection templates, Metasploit exploit modules
- **Tier 2 (Vetted)**: `trickest/cve` GitHub repo (last 3 years), NVD references with actual code paths
- **Tier 3 (Discovery)**: GitHub Search API targeting known CVEs, with automated trust scoring, malware pattern detection, and author blacklisting

### GitHub Trust Scoring
Multi-signal scoring to detect malware campaigns (e.g., Webrat):
- **File extension check**: Flags repos containing only README + ZIP (no `.py`, `.c`, `.go`, etc.)
- **Account age check**: Flags GitHub accounts less than 30 days old
- **Cross-source validation**: Bonus for CVEs already seen in Trickest, Sploitus, or NVD
- **Blacklist check**: Automatic blacklisting of flagged users across all future syncs
- **Scam keyword detection**: Catches repos with malware-related keywords

### Threat Intelligence Enrichment
- **CISA KEV**: Flags actively exploited vulnerabilities
- **EPSS**: Exploit Prediction Scoring System scores from FIRST.org (daily bulk CSV, skips redundant hourly fetches)
- **inTheWild.io**: Real-world exploitation tracking
- **NVD**: CVSS scores, descriptions, severity, published dates (with overlap-safe checkpoint tracking)

### Hype Scoring (0-100)
Composite score across four dimensions:
- **Media coverage** (0-40): Weighted mentions across BleepingComputer, The Hacker News, Dark Reading, SecurityWeek, The Record
- **Community activity** (0-35): Reddit mention tracking (auto-refreshes stale data after 7 days)
- **Exploit context** (0-15): KEV, EPSS, inTheWild flags
- **Severity bonus** (0-10): CVSS score contribution

### Dashboard & Filtering
- Search by CVE ID, title, or description
- Filter by severity, KEV status, PoC availability, and "Weaponized" (hype > 30, KEV, EPSS > 0.1, inTheWild, or Tier 1-2 PoC)
- CVE detail pages with full PoC listings, trust tiers, and media mention breakdowns
- Flag PoCs as malware with automatic author blacklisting

### Automated Sync
Hourly background sync coordinator runs sources sequentially:

```
nvd -> kev -> trickest -> nuclei -> metasploit -> sploitus -> github -> rss -> reddit -> nvd-enrich -> epss -> inthewild -> hype
```

- Incremental processing via checkpoint tracking (Trickest, Nuclei, Metasploit use git diff; NVD uses timestamp overlap)
- Manual sync triggering via the UI or API with per-source status tracking

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
   - API: http://localhost:8080/api/cves

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/cves` | List CVEs with filters: `page`, `limit`, `search`, `severity`, `is_kev`, `has_poc`, `is_weaponized`, `sort` |
| `GET` | `/api/cves/:id` | Single CVE with all associated PoCs |
| `POST` | `/api/cves/:id/enrich` | Trigger on-demand NVD enrichment (async, 202) |
| `GET` | `/api/sync/status` | Sync state for all sources + running flag |
| `POST` | `/api/sync/trigger` | Trigger full or single-source sync (`{"source":"nvd"}`) |
| `POST` | `/api/pocs/:id/flag` | Flag PoC as malware, blacklists the GitHub owner |

## Data Sources

| Source | Provides | Trust Tier |
|--------|----------|------------|
| NVD | CVE metadata, CVSS, descriptions, reference URLs | 1-2 (per URL) |
| CISA KEV | Known exploited vulnerability flags | Flag (`is_kev`) |
| Trickest | Curated CVE-to-PoC mappings | 2 |
| Nuclei | Detection templates (projectdiscovery/nuclei-templates) | 1 |
| Metasploit | Exploit modules (rapid7/metasploit-framework) | 1 |
| Sploitus | Exploit search aggregator | 1 |
| GitHub | CVE-specific repository search | 3 (scored) |
| Reddit | Mentions across r/netsec, r/cybersecurity, r/blueteamsec | Hype signal |
| RSS | Security news feeds | Hype signal |
| EPSS | Exploit prediction probability scores | Hype signal |
| inTheWild | Active exploitation tracking | Flag (`inthewild_exploited`) |

## Project Structure

```
backend/
  main.go                   Entry point, starts sync coordinator
  api/api.go                Gin router + all handlers
  db/db.go                  DB init + idempotent migrations
  db/init.sql               Full schema for fresh installs
  models/models.go          CVE, PoC, Source structs
  ingester/
    coordinator.go          Hourly sync loop with sequential workers
    nvd.go                  NVD fetch + enrichment + checkpoint tracking
    kev.go                  CISA KEV feed
    trickest.go             Trickest CVE repo (incremental via git diff)
    nuclei.go               Nuclei templates (incremental via git diff)
    metasploit.go           Metasploit modules (sparse checkout + git diff)
    sploitus.go             Sploitus search (rate limited)
    github.go               GitHub PoC search + trust scoring
    reddit.go               Reddit mentions (refreshes stale data)
    rss.go                  Security RSS feeds
    epss.go                 EPSS bulk scores (daily skip logic)
    hype.go                 Hype score computation (batched updates)
    inthewild.go            inTheWild.io tracking
frontend/
  src/
    App.tsx                 Main list view with tabs and filters
    CVEDetail.tsx           /cve/:id detail page
    SyncStatus.tsx          Header sync status widget
    main.tsx                BrowserRouter + routes
```

## License

MIT
