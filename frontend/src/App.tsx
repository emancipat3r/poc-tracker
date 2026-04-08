import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Search, AlertTriangle, ShieldCheck, Activity, Flame, Clock,
  ChevronDown, ChevronUp, ExternalLink, Code, Flag
} from 'lucide-react';
import { format } from 'date-fns';
import SyncStatus from './SyncStatus';

interface PoC {
  id: number;
  url: string;
  description: string;
  source: string;
  trust_tier: number;
  trust_score: number | null;
  flagged_malware: boolean;
}

interface CVE {
  id: string;
  title: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  published_date: string | null;
  is_kev: boolean;
  epss_score: number | null;
  epss_percentile: number | null;
  inthewild_exploited: boolean;
  hype_score: number;
  pocs: PoC[];
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
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(25);
  const [expandedCves, setExpandedCves] = useState<Set<string>>(new Set());
  const [flagged, setFlagged] = useState<Set<number>>(new Set());

  const toggleExpanded = (cveId: string) => {
    setExpandedCves(prev => {
      const s = new Set(prev);
      s.has(cveId) ? s.delete(cveId) : s.add(cveId);
      return s;
    });
  };

  const fetchCVEs = async () => {
    setLoading(true);
    try {
      const url = new URL(`${API_URL}/api/cves`);
      if (search) url.searchParams.append('search', search);
      if (severityFilter) url.searchParams.append('severity', severityFilter);
      url.searchParams.append('sort', sortOrder);
      url.searchParams.append('page', String(page));
      url.searchParams.append('limit', String(limit));
      if (hasPocFilter) url.searchParams.append('has_poc', 'true');

      if (activeTab === 'KEV') {
        url.searchParams.append('is_kev', 'true');
      } else if (activeTab === 'ACTIONABLE') {
        url.searchParams.append('is_weaponized', 'true');
      }

      const res = await fetch(url.toString());
      if (!res.ok) throw new Error('Failed to fetch CVEs');
      const data = await res.json();
      setCves(data.cves || []);
      setTotal(data.total || 0);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(fetchCVEs, 500);
    return () => clearTimeout(timer);
  }, [search, severityFilter, activeTab, sortOrder, hasPocFilter, page, limit]);

  const handleFlag = async (pocId: number, e: React.MouseEvent) => {
    e.stopPropagation();
    const res = await fetch(`${API_URL}/api/pocs/${pocId}/flag`, { method: 'POST' });
    if (res.ok) setFlagged(prev => new Set(prev).add(pocId));
  };

  const getSeverityClass = (severity: string) =>
    `badge severity-${(severity || 'UNKNOWN').toLowerCase()}`;

  const totalPages = Math.max(1, Math.ceil(total / limit));
  const pageStart = total === 0 ? 0 : (page - 1) * limit + 1;
  const pageEnd = Math.min(page * limit, total);

  const pageNumbers: (number | '…')[] = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pageNumbers.push(i);
  } else {
    pageNumbers.push(1);
    if (page > 3) pageNumbers.push('…');
    for (let i = Math.max(2, page - 1); i <= Math.min(totalPages - 1, page + 1); i++) pageNumbers.push(i);
    if (page < totalPages - 2) pageNumbers.push('…');
    pageNumbers.push(totalPages);
  }

  return (
    <div className="app-container">
      <header className="header animate-fade-in">
        <h1 className="header-title">
          <Activity size={32} color="#6366f1" />
          PoC Tracker
        </h1>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '6px' }}>
          <div className="badge" style={{ background: 'rgba(99,102,241,0.2)', color: '#6366f1' }}>
            {total} Vulnerabilities Monitored
          </div>
          <SyncStatus />
        </div>
      </header>

      <div className="tabs-container animate-fade-in" style={{ marginBottom: '2rem', display: 'flex', gap: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
        <button className={`glass-button ${activeTab === 'LATEST' ? 'primary' : ''}`} onClick={() => { setActiveTab('LATEST'); setPage(1); }}>
          <Clock size={18} /> Latest PoCs
        </button>
        <button
          className={`glass-button ${activeTab === 'KEV' ? 'primary' : ''}`}
          onClick={() => { setActiveTab('KEV'); setPage(1); }}
          style={activeTab === 'KEV' ? { background: 'var(--severity-critical)', borderColor: 'var(--severity-critical)' } : {}}
        >
          <Flame size={18} /> Trending / KEV
        </button>
        <button
          className={`glass-button ${activeTab === 'ACTIONABLE' ? 'primary' : ''}`}
          onClick={() => { setActiveTab('ACTIONABLE'); setPage(1); }}
          style={activeTab === 'ACTIONABLE' ? { background: 'var(--severity-high)', borderColor: 'var(--severity-high)' } : {}}
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
              placeholder="Search by CVE ID or title…"
              className="glass-input"
              style={{ paddingLeft: '40px' }}
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
            />
          </div>
        </div>
        <div className="filter-group" style={{ flex: '0 0 250px' }}>
          <select className="glass-input" value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}>
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </div>
        <div className="filter-group" style={{ flex: '0 0 200px' }}>
          <select className="glass-input" value={sortOrder} onChange={e => { setSortOrder(e.target.value as 'desc' | 'asc'); setPage(1); }}>
            <option value="desc">Most Recent</option>
            <option value="asc">Least Recent</option>
          </select>
        </div>
        <div className="filter-group" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)' }}>
          <input
            type="checkbox" id="hasPoc" checked={hasPocFilter}
            onChange={e => { setHasPocFilter(e.target.checked); setPage(1); }}
            style={{ width: '16px', height: '16px', cursor: 'pointer', accentColor: 'var(--accent-color)' }}
          />
          <label htmlFor="hasPoc" style={{ cursor: 'pointer', userSelect: 'none' }}>Has PoCs Only</label>
        </div>
        <div className="filter-group" style={{ flex: '0 0 140px' }}>
          <select className="glass-input" value={limit} onChange={e => { setLimit(Number(e.target.value)); setPage(1); }}>
            <option value={25}>25 per page</option>
            <option value={50}>50 per page</option>
            <option value={75}>75 per page</option>
            <option value={100}>100 per page</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="loader" />
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
            const bestTier = pocCount > 0 ? Math.min(...cve.pocs.map(p => p.trust_tier)) : null;

            return (
              <div
                key={cve.id}
                className={`glass-panel cve-card animate-fade-in ${isExpanded ? 'expanded' : ''}`}
                style={{ animationDelay: `${0.1 + Math.min(i * 0.05, 0.5)}s` }}
              >
                {/* Card Header */}
                <div className="cve-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                    <Link
                      to={`/cve/${cve.id}`}
                      className="cve-id"
                      onClick={e => e.stopPropagation()}
                      style={{ textDecoration: 'none' }}
                    >
                      {cve.id}
                    </Link>
                    <span className={getSeverityClass(cve.severity)}>{cve.severity || 'UNKNOWN'}</span>
                    {cve.is_kev && (
                      <span style={{ background: 'rgba(239,68,68,0.15)', color: 'var(--severity-critical)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.7rem', fontWeight: '700' }}>KEV</span>
                    )}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {cve.hype_score > 0 && (
                      <span style={{ background: cve.hype_score > 60 ? 'rgba(239,68,68,0.15)' : 'rgba(234,179,8,0.15)', color: cve.hype_score > 60 ? 'var(--severity-critical)' : '#eab308', padding: '3px 8px', borderRadius: '10px', fontSize: '0.7rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '3px' }}>
                        <Flame size={10} /> {Math.round(cve.hype_score)}
                      </span>
                    )}
                    {pocCount > 0 && (
                      <span style={{ background: bestTier === 1 ? 'rgba(34,197,94,0.15)' : bestTier === 2 ? 'rgba(234,179,8,0.15)' : 'rgba(99,102,241,0.2)', color: bestTier === 1 ? 'var(--severity-low)' : bestTier === 2 ? '#eab308' : 'var(--accent-color)', padding: '4px 10px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <Code size={12} /> {pocCount} PoC{pocCount > 1 ? 's' : ''}
                      </span>
                    )}
                    <button
                      onClick={() => toggleExpanded(cve.id)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', padding: '4px' }}
                      aria-label={isExpanded ? 'Collapse' : 'Expand'}
                    >
                      {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                    </button>
                  </div>
                </div>

                {/* Summary Row */}
                <div className="cve-summary" style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <span>{cve.published_date ? format(new Date(cve.published_date), 'MMM dd, yyyy') : 'Date unknown'}</span>
                  {cve.cvss_score !== null && <span>CVSS: {cve.cvss_score}</span>}
                  {cve.epss_score !== null && <span>EPSS: {(cve.epss_score * 100).toFixed(1)}%</span>}
                  {cve.inthewild_exploited && (
                    <span style={{ color: 'var(--severity-critical)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Flame size={12} /> In The Wild
                    </span>
                  )}
                </div>

                {/* Description preview (collapsed only) */}
                {!isExpanded && cve.description && (
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginTop: '0.5rem', overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
                    {cve.description.slice(0, 150)}{cve.description.length > 150 ? '…' : ''}
                  </p>
                )}

                {/* Expanded Content */}
                {isExpanded && (
                  <div className="cve-expanded" style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)', animation: 'fadeIn 0.2s ease' }}>

                    <div style={{ marginBottom: '1rem' }}>
                      <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>Description</h4>
                      <p style={{ fontSize: '0.9rem', lineHeight: '1.5' }}>
                        {cve.description || 'No description available yet. NVD enrichment may be pending.'}
                      </p>
                    </div>

                    <div style={{ marginBottom: '1rem', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <Link
                        to={`/cve/${cve.id}`}
                        onClick={e => e.stopPropagation()}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px', background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: '6px', color: 'var(--accent-color)', textDecoration: 'none', fontSize: '0.85rem' }}
                      >
                        <Activity size={14} /> Detail Page
                      </Link>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                        target="_blank" rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', borderRadius: '6px', color: 'var(--accent-color)', textDecoration: 'none', fontSize: '0.85rem' }}
                      >
                        <ExternalLink size={14} /> View on NVD
                      </a>
                    </div>

                    {/* PoCs */}
                    <div>
                      <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Code size={16} /> Proof of Concepts ({pocCount})
                      </h4>
                      {pocCount === 0 ? (
                        <div style={{ padding: '1.5rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                          <Search size={24} style={{ marginBottom: '8px', opacity: 0.5 }} />
                          <p>No PoCs discovered yet for this CVE.</p>
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          {cve.pocs
                            .filter(poc => !poc.flagged_malware && !flagged.has(poc.id))
                            .map((poc) => {
                              const isMalware = poc.flagged_malware;
                              const tc = poc.trust_tier === 1 ? 'var(--severity-low)' : poc.trust_tier === 2 ? '#eab308' : 'var(--severity-high)';
                              const tl = poc.trust_tier === 1 ? 'Official' : poc.trust_tier === 2 ? 'Vetted' : 'Unvetted';
                              let displayName = poc.url;
                              let hostname = '';
                              try {
                                const u = new URL(poc.url);
                                hostname = u.hostname;
                                if (u.hostname.includes('github.com')) {
                                  const parts = u.pathname.split('/').filter(Boolean);
                                  displayName = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : u.pathname;
                                } else {
                                  displayName = u.pathname.length > 40 ? u.pathname.slice(0, 40) + '…' : u.pathname;
                                }
                              } catch { /* keep original */ }

                              return (
                                <div key={poc.id} onClick={e => e.stopPropagation()} style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: isMalware ? 'rgba(239,68,68,0.1)' : 'rgba(99,102,241,0.05)', padding: '12px', borderRadius: '8px', border: `1px solid ${isMalware ? 'rgba(239,68,68,0.3)' : 'rgba(99,102,241,0.2)'}` }}>
                                  {isMalware && (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--severity-critical)', fontWeight: '600', fontSize: '0.8rem' }}>
                                      <AlertTriangle size={14} /> POTENTIAL MALWARE - USE CAUTION
                                    </div>
                                  )}
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                    <span style={{ color: tc, fontWeight: '600', background: `${tc}15`, padding: '4px 10px', borderRadius: '4px', fontSize: '0.75rem', border: `1px solid ${tc}40` }}>{tl}</span>
                                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', background: 'rgba(255,255,255,0.05)', padding: '4px 10px', borderRadius: '4px' }}>via {poc.source}</span>
                                    {poc.trust_score !== null && (
                                      <span style={{ fontSize: '0.75rem', color: poc.trust_score > 0 ? 'var(--severity-low)' : 'var(--severity-high)', fontWeight: '500' }}>
                                        Trust: {poc.trust_score > 0 ? '+' : ''}{poc.trust_score}
                                      </span>
                                    )}
                                  </div>
                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                      <div style={{ fontSize: '0.9rem', fontWeight: '500', marginBottom: '2px' }}>{displayName}</div>
                                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{hostname}</div>
                                    </div>
                                    <div style={{ display: 'flex', gap: '6px', flexShrink: 0 }}>
                                      <a href={poc.url} target="_blank" rel="noopener noreferrer" style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '10px 16px', background: 'var(--accent-color)', color: '#fff', borderRadius: '6px', textDecoration: 'none', fontSize: '0.85rem', fontWeight: '600', whiteSpace: 'nowrap' }}>
                                        <ExternalLink size={14} /> Open
                                      </a>
                                      <button
                                        onClick={e => handleFlag(poc.id, e)}
                                        title="Flag as malware"
                                        style={{ display: 'flex', alignItems: 'center', padding: '10px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', color: 'var(--severity-critical)', cursor: 'pointer' }}
                                      >
                                        <Flag size={14} />
                                      </button>
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          {cve.pocs.filter(p => p.flagged_malware || flagged.has(p.id)).length > 0 && (
                            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: 0 }}>
                              {cve.pocs.filter(p => p.flagged_malware || flagged.has(p.id)).length} PoC(s) hidden — flagged as malware.
                            </p>
                          )}
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

      {!loading && total > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '1.5rem', flexWrap: 'wrap', gap: '12px' }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Showing {pageStart}–{pageEnd} of {total}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <button
              className="glass-button"
              disabled={page === 1}
              onClick={() => setPage(p => p - 1)}
              style={{ padding: '6px 12px', opacity: page === 1 ? 0.4 : 1 }}
            >
              ← Prev
            </button>
            {pageNumbers.map((p, i) =>
              p === '…' ? (
                <span key={`ellipsis-${i}`} style={{ padding: '6px 4px', color: 'var(--text-secondary)' }}>…</span>
              ) : (
                <button
                  key={p}
                  className="glass-button"
                  onClick={() => setPage(p as number)}
                  style={{
                    padding: '6px 12px',
                    background: p === page ? 'var(--accent-color)' : undefined,
                    color: p === page ? '#fff' : undefined,
                    borderColor: p === page ? 'var(--accent-color)' : undefined,
                    fontWeight: p === page ? '700' : undefined,
                  }}
                >
                  {p}
                </button>
              )
            )}
            <button
              className="glass-button"
              disabled={page === totalPages}
              onClick={() => setPage(p => p + 1)}
              style={{ padding: '6px 12px', opacity: page === totalPages ? 0.4 : 1 }}
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
