// src/pages/History.jsx
// Displays paginated scan history with filter & clear

import { useState, useEffect, useCallback } from 'react'
import { getHistory, clearHistory } from '../services/api'
import '../styles/History.css'

function fmtPct(val) {
  return `${(val * 100).toFixed(1)}%`
}

function fmtTime(iso) {
  try {
    return new Date(iso + 'Z').toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  } catch {
    return iso
  }
}

function truncate(str, max = 55) {
  return str.length > max ? str.slice(0, max) + '…' : str
}

export default function History() {
  const [rows, setRows]       = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState('all') // all | phishing | legit

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getHistory(100)
      setRows(data)
    } catch {
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleClear = async () => {
    if (!window.confirm('Clear all scan history?')) return
    await clearHistory()
    setRows([])
  }

  const filtered = rows.filter((r) => {
    if (filter === 'phishing') return r.is_phishing
    if (filter === 'legit')    return !r.is_phishing
    return true
  })

  return (
    <main className="history-page">
      {/* Page header */}
      <div className="page-header">
        <h2 className="page-title">
          Scan <span>History</span>
          <span style={{ fontSize: '0.9rem', fontWeight: 400, color: 'var(--text-muted)', marginLeft: '0.75rem' }}>
            ({filtered.length})
          </span>
        </h2>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Filter buttons */}
          {['all', 'phishing', 'legit'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '0.4rem 0.9rem',
                borderRadius: 'var(--radius-md)',
                border: `1px solid ${filter === f ? 'var(--accent-cyan)' : 'var(--border)'}`,
                background: filter === f ? 'rgba(0,212,255,0.08)' : 'transparent',
                color: filter === f ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
                textTransform: 'capitalize',
                transition: 'all 0.2s',
              }}
            >
              {f}
            </button>
          ))}
          <button className="clear-btn" onClick={handleClear}>
            ✕ Clear
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="loading-wrap">
          <div className="loading-spinner" />
          Loading history…
        </div>
      )}

      {/* Empty state */}
      {!loading && filtered.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <div className="empty-title">No scan records yet</div>
          <div className="empty-sub">
            {filter !== 'all'
              ? `No ${filter} URLs in history. Try changing the filter.`
              : 'Head to the Scanner tab and analyse your first URL!'}
          </div>
        </div>
      )}

      {/* Table */}
      {!loading && filtered.length > 0 && (
        <div className="history-table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>#</th>
                <th>URL</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>Risk</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row, idx) => {
                const cls        = row.is_phishing ? 'phishing' : 'legit'
                const conf       = row.confidence
                const riskClass  = row.risk_level
                return (
                  <tr key={`${row.timestamp}-${idx}`}>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                      {idx + 1}
                    </td>
                    <td>
                      <div className="url-cell" title={row.url}>
                        {truncate(row.url)}
                      </div>
                    </td>
                    <td>
                      <span className={`label-pill ${cls}`}>
                        {row.is_phishing ? '🚨' : '✅'} {row.label}
                      </span>
                    </td>
                    <td>
                      <div className="confidence-mini">
                        <div className="mini-bar">
                          <div
                            className={`mini-fill ${cls}`}
                            style={{ width: fmtPct(conf) }}
                          />
                        </div>
                        <span
                          className={`mini-pct ${row.is_phishing ? 'text-phish' : 'text-safe'}`}
                        >
                          {fmtPct(conf)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className={`risk-tag ${riskClass}`}>{riskClass}</span>
                    </td>
                    <td className="ts-cell">{fmtTime(row.timestamp)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </main>
  )
}
