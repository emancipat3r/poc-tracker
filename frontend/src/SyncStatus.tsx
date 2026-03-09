import { useEffect, useState } from 'react';
import { RefreshCw, ChevronDown, ChevronUp } from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

interface SyncEntry {
  source_name: string;
  last_sync_at: string | null;
  last_sync_status: string;
}

interface SyncStatusData {
  running: boolean;
  sources: SyncEntry[];
}

export default function SyncStatus() {
  const [status, setStatus] = useState<SyncStatusData | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [triggering, setTriggering] = useState(false);

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${API_URL}/api/sync/status`);
      if (res.ok) setStatus(await res.json());
    } catch { /* ignore */ }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 30_000);
    return () => clearInterval(interval);
  }, []);

  const handleTrigger = async () => {
    setTriggering(true);
    try {
      await fetch(`${API_URL}/api/sync/trigger`, { method: 'POST' });
      setTimeout(fetchStatus, 1000);
    } finally {
      setTimeout(() => setTriggering(false), 2000);
    }
  };

  const lastSync = status?.sources?.reduce<Date | null>((latest, s) => {
    if (!s.last_sync_at) return latest;
    const d = new Date(s.last_sync_at);
    return !latest || d > latest ? d : latest;
  }, null);

  const statusColor = (s: string) => {
    if (s === 'success') return 'var(--severity-low)';
    if (s === 'error') return 'var(--severity-critical)';
    if (s === 'running') return '#eab308';
    return 'var(--text-secondary)';
  };

  return (
    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        {/* Running indicator */}
        {status?.running && (
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#eab308' }}>
            <RefreshCw size={12} style={{ animation: 'spin 1s linear infinite' }} />
            Syncing…
          </span>
        )}

        {/* Last sync time */}
        {lastSync && !status?.running && (
          <span title={format(lastSync, 'PPpp')}>
            Last sync {formatDistanceToNow(lastSync, { addSuffix: true })}
          </span>
        )}
        {!lastSync && !status?.running && <span>No sync yet</span>}

        {/* Sync now button */}
        <button
          className="glass-button"
          onClick={handleTrigger}
          disabled={triggering || status?.running}
          style={{
            padding: '4px 10px', fontSize: '0.75rem',
            display: 'flex', alignItems: 'center', gap: '4px',
            opacity: (triggering || status?.running) ? 0.5 : 1
          }}
        >
          <RefreshCw size={11} />
          {triggering ? 'Queued' : 'Sync now'}
        </button>

        {/* Toggle expand */}
        {(status?.sources?.length ?? 0) > 0 && (
          <button
            onClick={() => setExpanded(e => !e)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '2px', fontSize: '0.75rem', padding: 0 }}
          >
            {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            {expanded ? 'Hide' : 'Details'}
          </button>
        )}
      </div>

      {/* Per-source breakdown */}
      {expanded && status?.sources && (
        <div style={{
          marginTop: '8px', padding: '10px', background: 'rgba(0,0,0,0.3)',
          borderRadius: '6px', border: '1px solid var(--border-color)',
          display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '6px'
        }}>
          {status.sources.map(s => (
            <div key={s.source_name}>
              <span style={{ color: statusColor(s.last_sync_status), fontWeight: '600' }}>
                {s.source_name}
              </span>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.7rem' }}>
                {s.last_sync_at
                  ? formatDistanceToNow(new Date(s.last_sync_at), { addSuffix: true })
                  : s.last_sync_status}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
