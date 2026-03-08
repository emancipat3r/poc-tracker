import { useEffect, useState } from 'react';
import { Search, AlertTriangle, ShieldCheck, Activity, Flame, Clock, ChevronDown, ChevronUp, ExternalLink, Code } from 'lucide-react';
import { format } from 'date-fns';

interface CVE {
  id: string;
  source_id: number;
  title: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  published_at: string;
  published_date: string | null;
  is_kev: boolean;
  epss_score: number | null;
  epss_percentile: number | null;
  inthewild_exploited: boolean;
  pocs: { 
    url: string; 
    description: string;
    source: string;
    trust_tier: number;
    trust_score: number | null;
    flagged_malware: boolean;
  }[];
  updated_at: string;
}

interface CVEListResponse {
  cves: CVE[];
  total: number;
}

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

function App() {
  const [activeTab, setActiveTab] = useState<'LATEST' | 'KEV' | 'ACTIONABLE'>('LATEST');
  const [cves, setCves] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [hasPocFilter, setHasPocFilter] = useState(false);
  const [total, setTotal] = useState(0);
  const [expandedCves, setExpandedCves] = useState<Set<string>>(new Set());

  const toggleExpanded = (cveId: string) => {
    setExpandedCves(prev => {
      const newSet = new Set(prev);
      if (newSet.has(cveId)) {
        newSet.delete(cveId);
      } else {
        newSet.add(cveId);
      }
      return newSet;
    });
  };

  const fetchCVEs = async () => {
    setLoading(true);
    try {
      const url = new URL(`${API_URL}/api/cves`);
      if (search) url.searchParams.append('search', search);
      if (severityFilter) url.searchParams.append('severity', severityFilter);
      url.searchParams.append('sort', sortOrder);
      if (hasPocFilter) url.searchParams.append('has_poc', 'true');
      
      if (activeTab === 'KEV') {
        url.searchParams.append('is_kev', 'true');
        url.searchParams.append('has_poc', 'true');
      } else if (activeTab === 'ACTIONABLE') {
        url.searchParams.append('is_weaponized', 'true');
      }
      
      const res = await fetch(url.toString());
      if (!res.ok) throw new Error('Failed to fetch CVEs');
      
      const data: CVEListResponse = await res.json();
      setCves(data.cves || []);
      setTotal(data.total || 0);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      fetchCVEs();
    }, 500);
    return () => clearTimeout(delayDebounceFn);
  }, [search, severityFilter, activeTab, sortOrder, hasPocFilter]);

  const getSeverityBadgeClass = (severity: string) => {
    const s = (severity || 'UNKNOWN').toLowerCase();
    return `badge severity-${s}`;
  };

  return (
    <div className="app-container">
      <header className="header animate-fade-in">
        <h1 className="header-title">
          <Activity size={32} color="#6366f1" />
          OSINT CVE Tracker
        </h1>
        <div className="badge" style={{ background: 'rgba(99,102,241,0.2)', color: '#6366f1' }}>
          {total} Vulnerabilities Monitored
        </div>
      </header>

      <div className="tabs-container animate-fade-in" style={{ marginBottom: '2rem', display: 'flex', gap: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
        <button 
          className={`glass-button ${activeTab === 'LATEST' ? 'primary' : ''}`}
          onClick={() => setActiveTab('LATEST')}
        >
          <Clock size={18} /> Latest PoCs
        </button>
        <button 
          className={`glass-button ${activeTab === 'KEV' ? 'primary' : ''}`}
          onClick={() => setActiveTab('KEV')}
          style={{ ...(activeTab === 'KEV' ? { background: 'var(--severity-critical)', borderColor: 'var(--severity-critical)' } : {}) }}
        >
          <Flame size={18} /> Trending/Exploited (KEV)
        </button>
        <button 
          className={`glass-button ${activeTab === 'ACTIONABLE' ? 'primary' : ''}`}
          onClick={() => setActiveTab('ACTIONABLE')}
          style={{ ...(activeTab === 'ACTIONABLE' ? { background: 'var(--severity-high)', borderColor: 'var(--severity-high)' } : {}) }}
        >
          <Activity size={18} /> Actionable / Weaponized
        </button>
      </div>

      <div className="filters-bar animate-fade-in" style={{ animationDelay: '0.1s' }}>
        <div className="filter-group">
          <div style={{ position: 'relative' }}>
            <Search size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
            <input 
              type="text" 
              placeholder="Search by CVE ID or Title..." 
              className="glass-input"
              style={{ paddingLeft: '40px' }}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
        <div className="filter-group" style={{ flex: '0 0 250px' }}>
          <select 
            className="glass-input" 
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </div>
        <div className="filter-group" style={{ flex: '0 0 200px' }}>
          <select 
            className="glass-input" 
            value={sortOrder}
            onChange={(e) => setSortOrder(e.target.value as 'desc' | 'asc')}
          >
            <option value="desc">Most Recent</option>
            <option value="asc">Least Recent</option>
          </select>
        </div>
        <div className="filter-group" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)' }}>
          <input 
            type="checkbox" 
            id="hasPoc" 
            checked={hasPocFilter} 
            onChange={(e) => setHasPocFilter(e.target.checked)} 
            style={{ width: '16px', height: '16px', cursor: 'pointer', accentColor: 'var(--accent-color)' }}
          />
          <label htmlFor="hasPoc" style={{ cursor: 'pointer', userSelect: 'none' }}>Has PoCs Only</label>
        </div>
      </div>

      {loading ? (
        <div className="loader"></div>
      ) : cves.length === 0 ? (
        <div className="empty-state animate-fade-in">
          <ShieldCheck size={64} />
          <h2>No matching CVEs found.</h2>
          <p>Try adjusting your search filters.</p>
        </div>
      ) : (
        <div className="cve-grid">
          {cves.map((cve, i) => {
            const isExpanded = expandedCves.has(cve.id);
            const pocCount = cve.pocs?.length || 0;

            return (
              <div
                key={cve.id}
                className={`glass-panel cve-card animate-fade-in ${isExpanded ? 'expanded' : ''}`}
                style={{
                  animationDelay: `${0.1 + min(i * 0.05, 0.5)}s`,
                  cursor: 'pointer'
                }}
                onClick={() => toggleExpanded(cve.id)}
              >
                {/* Card Header - Always Visible */}
                <div className="cve-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className="cve-id">{cve.id}</span>
                    <span className={getSeverityBadgeClass(cve.severity)}>
                      {cve.severity || 'UNKNOWN'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {pocCount > 0 && (
                      <span style={{
                        background: 'var(--accent-color)',
                        color: '#fff',
                        padding: '4px 10px',
                        borderRadius: '12px',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}>
                        <Code size={12} />
                        {pocCount} PoC{pocCount > 1 ? 's' : ''}
                      </span>
                    )}
                    {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                  </div>
                </div>

                {/* Summary Row - Always Visible */}
                <div className="cve-summary" style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '8px',
                  fontSize: '0.8rem',
                  color: 'var(--text-secondary)'
                }}>
                  <span>
                    {cve.published_date ? format(new Date(cve.published_date), 'MMM dd, yyyy') : 'Date unknown'}
                  </span>
                  {cve.cvss_score && <span>CVSS: {cve.cvss_score}</span>}
                  {cve.epss_score && <span>EPSS: {(cve.epss_score * 100).toFixed(1)}%</span>}
                  {cve.is_kev && <span style={{ color: 'var(--severity-critical)' }}>KEV</span>}
                  {cve.inthewild_exploited && (
                    <span style={{ color: 'var(--severity-critical)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Flame size={12} /> In The Wild
                    </span>
                  )}
                </div>

                {/* Expanded Content */}
                {isExpanded && (
                  <div className="cve-expanded" style={{
                    marginTop: '1rem',
                    paddingTop: '1rem',
                    borderTop: '1px solid var(--border-color)',
                    animation: 'fadeIn 0.2s ease'
                  }}>
                    {/* Description */}
                    <div style={{ marginBottom: '1rem' }}>
                      <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>Description</h4>
                      <p style={{ fontSize: '0.9rem', lineHeight: '1.5' }}>
                        {cve.description && !cve.description.includes('Discovered via')
                          ? cve.description
                          : 'No description available yet. NVD enrichment may be pending.'}
                      </p>
                    </div>

                    {/* External Links */}
                    <div style={{ marginBottom: '1rem' }}>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          padding: '6px 12px',
                          background: 'rgba(255,255,255,0.05)',
                          border: '1px solid var(--border-color)',
                          borderRadius: '6px',
                          color: 'var(--accent-color)',
                          textDecoration: 'none',
                          fontSize: '0.85rem'
                        }}
                      >
                        <ExternalLink size={14} /> View on NVD
                      </a>
                    </div>

                    {/* PoCs Section */}
                    <div>
                      <h4 style={{
                        fontSize: '0.85rem',
                        color: 'var(--text-secondary)',
                        marginBottom: '0.75rem',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <Code size={16} />
                        Proof of Concepts ({pocCount})
                      </h4>

                      {pocCount === 0 ? (
                        <div style={{
                          padding: '1.5rem',
                          background: 'rgba(0,0,0,0.2)',
                          borderRadius: '8px',
                          textAlign: 'center',
                          color: 'var(--text-secondary)'
                        }}>
                          <Search size={24} style={{ marginBottom: '8px', opacity: 0.5 }} />
                          <p>No PoCs discovered yet for this CVE.</p>
                          <p style={{ fontSize: '0.8rem', marginTop: '4px' }}>Check back later - ingestors run every 30 minutes.</p>
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          {cve.pocs.map((poc, idx) => {
                            const isMalware = poc.flagged_malware;
                            const tierColor = poc.trust_tier === 1 ? 'var(--severity-low)' : poc.trust_tier === 2 ? '#eab308' : 'var(--severity-high)';
                            const tierLabel = poc.trust_tier === 1 ? 'Official' : poc.trust_tier === 2 ? 'Vetted' : 'Unvetted';

                            // Extract display name from URL
                            let displayName = poc.url;
                            let hostname = '';
                            try {
                              const urlObj = new URL(poc.url);
                              hostname = urlObj.hostname;
                              if (urlObj.hostname.includes('github.com')) {
                                const parts = urlObj.pathname.split('/').filter(Boolean);
                                displayName = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : urlObj.pathname;
                              } else {
                                displayName = urlObj.pathname.length > 40
                                  ? urlObj.pathname.slice(0, 40) + '...'
                                  : urlObj.pathname;
                              }
                            } catch { /* keep original */ }

                            return (
                              <div
                                key={idx}
                                onClick={(e) => e.stopPropagation()}
                                style={{
                                  display: 'flex',
                                  flexDirection: 'column',
                                  gap: '8px',
                                  background: isMalware ? 'rgba(239,68,68,0.1)' : 'rgba(99,102,241,0.05)',
                                  padding: '12px',
                                  borderRadius: '8px',
                                  border: `1px solid ${isMalware ? 'rgba(239,68,68,0.3)' : 'rgba(99,102,241,0.2)'}`
                                }}
                              >
                                {isMalware && (
                                  <div style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '6px',
                                    color: 'var(--severity-critical)',
                                    fontWeight: '600',
                                    fontSize: '0.8rem'
                                  }}>
                                    <AlertTriangle size={14} />
                                    POTENTIAL MALWARE - USE CAUTION
                                  </div>
                                )}

                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                  <span style={{
                                    color: tierColor,
                                    fontWeight: '600',
                                    background: `${tierColor}15`,
                                    padding: '4px 10px',
                                    borderRadius: '4px',
                                    fontSize: '0.75rem',
                                    border: `1px solid ${tierColor}40`
                                  }}>{tierLabel}</span>
                                  <span style={{
                                    color: 'var(--text-secondary)',
                                    fontSize: '0.75rem',
                                    background: 'rgba(255,255,255,0.05)',
                                    padding: '4px 10px',
                                    borderRadius: '4px'
                                  }}>via {poc.source}</span>
                                  {poc.trust_score !== null && (
                                    <span style={{
                                      fontSize: '0.75rem',
                                      color: poc.trust_score > 0 ? 'var(--severity-low)' : 'var(--severity-high)',
                                      fontWeight: '500'
                                    }}>
                                      Trust: {poc.trust_score > 0 ? '+' : ''}{poc.trust_score}
                                    </span>
                                  )}
                                </div>

                                <div style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'space-between',
                                  gap: '12px'
                                }}>
                                  <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontSize: '0.9rem', fontWeight: '500', marginBottom: '2px' }}>
                                      {displayName}
                                    </div>
                                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                                      {hostname}
                                    </div>
                                  </div>
                                  <a
                                    href={poc.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    style={{
                                      display: 'flex',
                                      alignItems: 'center',
                                      gap: '6px',
                                      padding: '10px 16px',
                                      background: isMalware ? 'var(--severity-critical)' : 'var(--accent-color)',
                                      color: '#fff',
                                      borderRadius: '6px',
                                      textDecoration: 'none',
                                      fontSize: '0.85rem',
                                      fontWeight: '600',
                                      whiteSpace: 'nowrap'
                                    }}
                                  >
                                    <ExternalLink size={14} />
                                    Open
                                  </a>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// Math.min utility for style above
const min = (a: number, b: number) => a < b ? a : b;

export default App;
