import { useEffect, useState } from 'react';
import { Search, AlertTriangle, ShieldCheck, Activity, Flame, Clock } from 'lucide-react';
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
  pocs: { url: string; description: string }[];
  updated_at: string;
}

interface CVEListResponse {
  cves: CVE[];
  total: number;
}

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

function App() {
  const [activeTab, setActiveTab] = useState<'LATEST' | 'KEV'>('LATEST');
  const [cves, setCves] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [hasPocFilter, setHasPocFilter] = useState(false);
  const [total, setTotal] = useState(0);

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
          {cves.map((cve, i) => (
            <div 
              key={cve.id} 
              className="glass-panel cve-card animate-fade-in" 
              style={{ animationDelay: `${0.1 + min(i * 0.05, 0.5)}s` }}
            >
              <div className="cve-header">
                <span className="cve-id">{cve.id}</span>
                <span className={getSeverityBadgeClass(cve.severity)}>
                  {cve.severity || 'UNKNOWN'}
                </span>
              </div>
              <h3 className="cve-title">{cve.title}</h3>
              <p className="cve-desc">{cve.description}</p>
              
              {cve.pocs && cve.pocs.length > 0 && (
                <div style={{ marginTop: '0.5rem', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {cve.pocs.map((poc, idx) => (
                    <a key={idx} href={poc.url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent-color)', fontSize: '0.9rem', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px', background: 'rgba(99,102,241,0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                      <Search size={14} /> View PoC {cve.pocs.length > 1 ? `#${idx + 1}` : ''}
                    </a>
                  ))}
                </div>
              )}
              
              <div className="cve-footer">
                <span>
                  Published: {cve.published_date ? format(new Date(cve.published_date), 'MMM dd, yyyy') : (cve.published_at ? format(new Date(cve.published_at), 'MMM dd, yyyy') : 'Unknown')}
                </span>
                {cve.cvss_score && (
                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <AlertTriangle size={14} /> Score: {cve.cvss_score}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Math.min utility for style above
const min = (a: number, b: number) => a < b ? a : b;

export default App;
