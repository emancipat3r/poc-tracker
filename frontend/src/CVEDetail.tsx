import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft, ExternalLink, RefreshCw, AlertTriangle, Code,
  Flame, ShieldCheck, Shield, Activity, Flag
} from 'lucide-react';
import { format } from 'date-fns';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

interface PoC {
  id: number;
  url: string;
  description: string;
  source: string;
  trust_tier: number;
  trust_score: number | null;
  flagged_malware: boolean;
}

interface CVEDetail {
  id: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  is_kev: boolean;
  inthewild_exploited: boolean;
  published_date: string | null;
  hype_score: number;
  enriched_at: string | null;
  pocs: PoC[];
}

function severityColor(s: string) {
  switch ((s || '').toUpperCase()) {
    case 'CRITICAL': return 'var(--severity-critical)';
    case 'HIGH':     return 'var(--severity-high)';
    case 'MEDIUM':   return 'var(--severity-medium)';
    case 'LOW':      return 'var(--severity-low)';
    default:         return 'var(--text-secondary)';
  }
}

function tierLabel(t: number) {
  return t === 1 ? 'Official' : t === 2 ? 'Vetted' : 'Unvetted';
}
function tierColor(t: number) {
  return t === 1 ? 'var(--severity-low)' : t === 2 ? '#eab308' : 'var(--severity-high)';
}

function pocDisplayName(url: string): { display: string; host: string } {
  try {
    const u = new URL(url);
    if (u.hostname.includes('github.com')) {
      const parts = u.pathname.split('/').filter(Boolean);
      return { display: parts.length >= 2 ? `${parts[0]}/${parts[1]}` : u.pathname, host: u.hostname };
    }
    const path = u.pathname.length > 50 ? u.pathname.slice(0, 50) + '…' : u.pathname;
    return { display: path, host: u.hostname };
  } catch {
    return { display: url, host: '' };
  }
}

export default function CVEDetail() {
  const { id } = useParams<{ id: string }>();
  const [cve, setCve] = useState<CVEDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [enriching, setEnriching] = useState(false);
  const [flagged, setFlagged] = useState<Set<number>>(new Set());

  const fetchCVE = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/cves/${id}`);
      if (!res.ok) throw new Error('not found');
      setCve(await res.json());
    } catch {
      setCve(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCVE(); }, [id]);

  const handleEnrich = async () => {
    setEnriching(true);
    await fetch(`${API_URL}/api/cves/${id}/enrich`, { method: 'POST' });
    // Poll once after 3s for updated data
    setTimeout(async () => {
      await fetchCVE();
      setEnriching(false);
    }, 3000);
  };

  const handleFlag = async (pocId: number) => {
    const res = await fetch(`${API_URL}/api/pocs/${pocId}/flag`, { method: 'POST' });
    if (res.ok) {
      setFlagged(prev => new Set(prev).add(pocId));
    }
  };

  if (loading) return (
    <div className="app-container">
      <div className="loader" style={{ margin: '4rem auto' }} />
    </div>
  );

  if (!cve) return (
    <div className="app-container">
      <div className="empty-state">
        <ShieldCheck size={64} />
        <h2>CVE not found</h2>
        <Link to="/" className="glass-button" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginTop: '1rem', textDecoration: 'none' }}>
          <ArrowLeft size={16} /> Back to list
        </Link>
      </div>
    </div>
  );

  const sColor = severityColor(cve.severity);
  const pocsByTier = [1, 2, 3].map(t => ({
    tier: t,
    pocs: (cve.pocs || []).filter(p => p.trust_tier === t && !p.flagged_malware && !flagged.has(p.id)),
  })).filter(g => g.pocs.length > 0);

  return (
    <div className="app-container">
      {/* Back nav */}
      <div style={{ marginBottom: '1.5rem' }}>
        <Link to="/" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)', textDecoration: 'none', fontSize: '0.9rem' }}>
          <ArrowLeft size={16} /> All CVEs
        </Link>
      </div>

      {/* Header */}
      <div className="glass-panel animate-fade-in" style={{ marginBottom: '1.5rem', padding: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <h1 style={{ fontSize: '1.6rem', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>{cve.id}</h1>
              <span className={`badge severity-${(cve.severity || 'unknown').toLowerCase()}`}>
                {cve.severity || 'UNKNOWN'}
              </span>
              {cve.is_kev && (
                <span style={{ background: 'rgba(239,68,68,0.2)', color: 'var(--severity-critical)', padding: '3px 10px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: '700', border: '1px solid rgba(239,68,68,0.4)' }}>
                  KEV
                </span>
              )}
              {cve.inthewild_exploited && (
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(239,68,68,0.15)', color: 'var(--severity-critical)', padding: '3px 10px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: '600' }}>
                  <Flame size={12} /> In The Wild
                </span>
              )}
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6', maxWidth: '800px', margin: 0 }}>
              {cve.description || 'No description available. Click Refresh to fetch from NVD.'}
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
            <button
              className="glass-button"
              onClick={handleEnrich}
              disabled={enriching}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', opacity: enriching ? 0.6 : 1 }}
            >
              <RefreshCw size={14} style={{ animation: enriching ? 'spin 1s linear infinite' : 'none' }} />
              {enriching ? 'Refreshing…' : 'Refresh'}
            </button>
            <a
              href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="glass-button"
              style={{ display: 'flex', alignItems: 'center', gap: '6px', textDecoration: 'none' }}
            >
              <ExternalLink size={14} /> NVD
            </a>
          </div>
        </div>
      </div>

      {/* Score grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <ScoreCard label="CVSS Score" value={cve.cvss_score !== null ? cve.cvss_score.toFixed(1) : '—'} color={sColor} icon={<Shield size={18} />} />
        <ScoreCard label="EPSS Score" value={cve.epss_score !== null ? `${(cve.epss_score * 100).toFixed(2)}%` : '—'} sub={cve.epss_percentile !== null ? `${(cve.epss_percentile * 100).toFixed(0)}th percentile` : undefined} icon={<Activity size={18} />} />
        <ScoreCard label="Hype Score" value={cve.hype_score > 0 ? cve.hype_score.toFixed(0) + ' / 100' : '0 / 100'} color={cve.hype_score > 60 ? 'var(--severity-critical)' : cve.hype_score > 30 ? 'var(--severity-high)' : undefined} icon={<Flame size={18} />} />
        <ScoreCard label="Published" value={cve.published_date ? format(new Date(cve.published_date), 'MMM dd, yyyy') : '—'} icon={<ShieldCheck size={18} />} />
      </div>

      {/* PoCs by tier */}
      <div className="glass-panel animate-fade-in" style={{ padding: '1.5rem' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Code size={18} /> Proof of Concepts ({(cve.pocs || []).length})
        </h2>

        {(cve.pocs || []).length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem 0' }}>No PoCs discovered for this CVE yet.</p>
        ) : (
          pocsByTier.map(({ tier, pocs }) => (
            <div key={tier} style={{ marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '0.8rem', fontWeight: '700', color: tierColor(tier), textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
                Tier {tier} — {tierLabel(tier)} ({pocs.length})
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {pocs.map(poc => {
                  const { display, host } = pocDisplayName(poc.url);
                  const tc = tierColor(poc.trust_tier);
                  return (
                    <div key={poc.id} style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px',
                      background: 'rgba(99,102,241,0.05)', padding: '12px', borderRadius: '8px',
                      border: `1px solid rgba(99,102,241,0.2)`, flexWrap: 'wrap'
                    }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: '0.9rem', fontWeight: '500', marginBottom: '2px' }}>{display}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                          <span>{host}</span>
                          <span style={{ color: tc, background: `${tc}15`, padding: '1px 6px', borderRadius: '3px', border: `1px solid ${tc}40` }}>
                            {tierLabel(poc.trust_tier)}
                          </span>
                          <span style={{ background: 'rgba(255,255,255,0.05)', padding: '1px 6px', borderRadius: '3px' }}>via {poc.source}</span>
                          {poc.trust_score !== null && (
                            <span style={{ color: poc.trust_score >= 0 ? 'var(--severity-low)' : 'var(--severity-high)' }}>
                              trust: {poc.trust_score > 0 ? '+' : ''}{poc.trust_score}
                            </span>
                          )}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
                        <a href={poc.url} target="_blank" rel="noopener noreferrer"
                          style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '8px 14px', background: 'var(--accent-color)', color: '#fff', borderRadius: '6px', textDecoration: 'none', fontSize: '0.85rem', fontWeight: '600' }}>
                          <ExternalLink size={13} /> Open
                        </a>
                        <button
                          onClick={() => handleFlag(poc.id)}
                          title="Flag as malware"
                          style={{ display: 'flex', alignItems: 'center', padding: '8px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', color: 'var(--severity-critical)', cursor: 'pointer' }}
                        >
                          <Flag size={14} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))
        )}

        {/* Flagged PoCs notice */}
        {(cve.pocs || []).filter(p => p.flagged_malware || flagged.has(p.id)).length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '1rem', padding: '8px 12px', background: 'rgba(239,68,68,0.05)', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.2)' }}>
            <AlertTriangle size={14} color="var(--severity-critical)" />
            {(cve.pocs || []).filter(p => p.flagged_malware || flagged.has(p.id)).length} PoC(s) hidden — flagged as potential malware.
          </div>
        )}
      </div>
    </div>
  );
}

function ScoreCard({ label, value, sub, color, icon }: {
  label: string; value: string; sub?: string; color?: string; icon: React.ReactNode;
}) {
  return (
    <div className="glass-panel" style={{ padding: '1rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)', fontSize: '0.75rem', marginBottom: '0.5rem' }}>
        {icon} {label}
      </div>
      <div style={{ fontSize: '1.4rem', fontWeight: '700', color: color || 'var(--text-primary)' }}>{value}</div>
      {sub && <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{sub}</div>}
    </div>
  );
}
