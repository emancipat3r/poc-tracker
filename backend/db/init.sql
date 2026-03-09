CREATE TABLE IF NOT EXISTS sources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    url VARCHAR(255) NOT NULL,
    last_fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id VARCHAR(50) PRIMARY KEY,
    source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
    title TEXT,
    description TEXT,
    severity VARCHAR(50) DEFAULT 'UNKNOWN',
    cvss_score NUMERIC(4, 2),
    published_at TIMESTAMP WITH TIME ZONE,
    published_date TIMESTAMP WITH TIME ZONE,
    is_kev BOOLEAN DEFAULT false,
    epss_score FLOAT,
    epss_percentile FLOAT,
    inthewild_exploited BOOLEAN DEFAULT false,
    inthewild_last_seen TIMESTAMP WITH TIME ZONE,
    cisa_0day BOOLEAN DEFAULT false,
    has_nuclei_template BOOLEAN DEFAULT false,
    has_metasploit_module BOOLEAN DEFAULT false,
    has_exploitdb_entry BOOLEAN DEFAULT false,
    hype_score FLOAT DEFAULT 0,
    media_mentions JSONB DEFAULT '{}',
    reddit_mentions JSONB DEFAULT '[]',
    enriched_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pocs (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) REFERENCES cves(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    description TEXT,
    source VARCHAR(50) NOT NULL DEFAULT 'unknown',
    trust_tier INT NOT NULL DEFAULT 3,
    trust_score FLOAT DEFAULT 0,
    signals JSONB DEFAULT '{}',
    flagged_malware BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cve_id, url)
);

CREATE TABLE IF NOT EXISTS poc_blacklist (
    id SERIAL PRIMARY KEY,
    github_user VARCHAR(255) UNIQUE,
    repo_pattern VARCHAR(255),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sync_state (
    source_name TEXT PRIMARY KEY,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_sync_status TEXT DEFAULT 'never',
    next_sync_at TIMESTAMP WITH TIME ZONE,
    checkpoint JSONB DEFAULT '{}'
);

-- Seed some initial sources
INSERT INTO sources (name, type, url) VALUES
('NVD RSS Recent', 'rss', 'https://cve.circl.lu/api/last'),
('GitHub Security Advisories', 'github', 'advisories')
ON CONFLICT DO NOTHING;
