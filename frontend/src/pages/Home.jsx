// src/pages/Home.jsx
// Main scanner page with URL input, result card, and stats summary

import { useState, useEffect, useRef } from 'react'
import { predictURL, getStats } from '../services/api'
import ResultCard from '../components/ResultCard'
import '../styles/Home.css'

// Sample URLs for quick testing
const EXAMPLE_URLS = [
  'https://www.google.com',
  'http://paypa1-secure-login.com/verify?user=123',
  'https://www.github.com',
  'http://amazon-account-update.xyz/login',
  'https://www.netflix.com',
  'http://free-iphone-winner.xyz/claim',
]

export default function Home() {
  const [url, setUrl]         = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState('')
  const [stats, setStats]     = useState(null)
  const inputRef              = useRef(null)

  // Load aggregate stats on mount
  useEffect(() => {
    getStats().then(setStats).catch(() => {})
  }, [result]) // refresh after each scan

  const handleSubmit = async (e) => {
    e?.preventDefault()
    const trimmed = url.trim()
    if (!trimmed) {
      setError('Please enter a URL to scan.')
      return
    }
    setError('')
    setLoading(true)
    setResult(null)

    try {
      const data = await predictURL(trimmed)
      setResult(data)
    } catch (err) {
      setError(err.message || 'Failed to reach the backend. Is Flask running?')
    } finally {
      setLoading(false)
    }
  }

  const handleExample = (exUrl) => {
    setUrl(exUrl)
    setResult(null)
    setError('')
    inputRef.current?.focus()
  }

  return (
    <main className="home">
      {/* Hero */}
      <section className="hero">
        <div className="hero-badge">Real-time AI Scanner</div>
        <h1 className="hero-title">
          Detect <span className="highlight">Phishing URLs</span>
          <br />with AI precision
        </h1>
        <p className="hero-subtitle">
          Powered by Random Forest + XGBoost ensemble with NLP-based TF-IDF
          pattern analysis. Paste any URL below to get an instant threat assessment.
        </p>
      </section>

      {/* Stats row */}
      {stats && (
        <div className="stats-row">
          <div className="stat-card">
            <div className="stat-value text-cyan">{stats.total_scanned}</div>
            <div className="stat-label">URLs Scanned</div>
          </div>
          <div className="stat-card">
            <div className="stat-value text-phish">{stats.phishing}</div>
            <div className="stat-label">Phishing Found</div>
          </div>
          <div className="stat-card">
            <div className="stat-value text-safe">{stats.legitimate}</div>
            <div className="stat-label">Legitimate</div>
          </div>
        </div>
      )}

      {/* Scanner card */}
      <div className="scanner-card">
        <div className="scanner-label">// URL Scanner</div>
        <form onSubmit={handleSubmit}>
          <div className="input-row">
            <input
              ref={inputRef}
              type="text"
              className="url-input"
              placeholder="https://example.com or http://suspicious-site.xyz/login"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
              autoComplete="off"
              spellCheck={false}
            />
            <button type="submit" className="scan-btn" disabled={loading}>
              {loading ? (
                <>
                  <span className="spinner" />
                  Scanning…
                </>
              ) : (
                <>🔍 Scan URL</>
              )}
            </button>
          </div>

          {error && (
            <div className="error-banner">
              ⚠ {error}
            </div>
          )}

          <div className="scanner-hint">
            Quick examples:{' '}
            {EXAMPLE_URLS.map((u, i) => (
              <span key={u}>
                <button
                  type="button"
                  onClick={() => handleExample(u)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--accent-cyan)',
                    cursor: 'pointer',
                    fontSize: '0.72rem',
                    fontFamily: 'var(--font-mono)',
                    padding: 0,
                  }}
                >
                  {u.length > 30 ? u.slice(0, 30) + '…' : u}
                </button>
                {i < EXAMPLE_URLS.length - 1 && (
                  <span style={{ color: 'var(--text-muted)', margin: '0 0.3rem' }}>·</span>
                )}
              </span>
            ))}
          </div>
        </form>
      </div>

      {/* Result */}
      {result && <ResultCard result={result} />}

      {/* Info blurb when no result yet */}
      {!result && !loading && (
        <div
          style={{
            textAlign: 'center',
            padding: '2rem',
            color: 'var(--text-muted)',
            fontSize: '0.82rem',
            animation: 'fadeInUp 0.4s 0.3s ease both',
            opacity: 0,
            animationFillMode: 'forwards',
          }}
        >
          <div style={{ fontSize: '2rem', marginBottom: '0.75rem', opacity: 0.3 }}>🛡️</div>
          Enter a URL above to begin real-time phishing analysis.
          <br />
          The AI model analyses 28+ URL features combined with NLP pattern recognition.
        </div>
      )}
    </main>
  )
}
