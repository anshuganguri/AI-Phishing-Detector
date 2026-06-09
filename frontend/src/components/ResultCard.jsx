// src/components/ResultCard.jsx
// Displays the full AI prediction result for a scanned URL

import { useState } from 'react'

// ── Helpers ───────────────────────────────────────────────────────────────────

function getRiskClass(riskLevel) {
  if (riskLevel === 'HIGH')   return 'phishing'
  if (riskLevel === 'MEDIUM') return 'medium'
  if (riskLevel === 'SAFE')   return 'safe'
  return 'medium' // LOW
}

function getVerdictIcon(isPhishing, riskLevel) {
  if (isPhishing) return '🚨'
  if (riskLevel === 'LOW') return '⚠️'
  return '✅'
}

function fmtPct(val) {
  return `${(val * 100).toFixed(1)}%`
}

function fmtFeatureName(key) {
  return key.replace(/_/g, ' ')
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ResultCard({ result }) {
  const [showFeatures, setShowFeatures] = useState(false)

  if (!result) return null

  const {
    url, is_phishing, label, confidence,
    phishing_prob, legitimate_prob,
    risk_level, risk_factors, features, timestamp,
  } = result

  const cardClass = getRiskClass(risk_level)
  const confClass = is_phishing ? 'phishing' : risk_level === 'LOW' ? 'medium' : 'safe'
  const confWidth = `${(confidence * 100).toFixed(1)}%`

  const ts = new Date(timestamp + 'Z').toLocaleTimeString()

  // Feature entries to display (exclude verbose ones)
  const featureEntries = features
    ? Object.entries(features).filter(([k]) =>
        !['url_entropy', 'digit_ratio'].includes(k)
      )
    : []

  return (
    <div className={`result-card ${cardClass}`}>
      {/* Header */}
      <div className="result-header">
        <div className="result-verdict">
          <span className="verdict-icon">{getVerdictIcon(is_phishing, risk_level)}</span>
          <div>
            <div
              className={`verdict-label ${
                is_phishing ? 'text-phish' : risk_level === 'LOW' ? 'text-low' : 'text-safe'
              }`}
            >
              {label}
            </div>
            <div className="verdict-url">{url}</div>
          </div>
        </div>
        <span className={`risk-badge ${risk_level}`}>{risk_level} Risk</span>
      </div>

      {/* Confidence bar */}
      <div className="confidence-section">
        <div className="conf-header">
          <span>Confidence Score</span>
          <span className={`conf-value ${is_phishing ? 'text-phish' : 'text-safe'}`}>
            {fmtPct(confidence)}
          </span>
        </div>
        <div className="conf-bar-track">
          <div
            className={`conf-bar-fill ${confClass}`}
            style={{ width: confWidth }}
          />
        </div>
      </div>

      {/* Dual probabilities */}
      <div className="prob-row">
        <div className="prob-cell">
          <div className="prob-cell-label">Phishing Probability</div>
          <div className="prob-cell-value text-phish">{fmtPct(phishing_prob)}</div>
        </div>
        <div className="prob-cell">
          <div className="prob-cell-label">Legitimate Probability</div>
          <div className="prob-cell-value text-safe">{fmtPct(legitimate_prob)}</div>
        </div>
      </div>

      {/* Risk factors */}
      {risk_factors && risk_factors.length > 0 && (
        <div className="risk-factors">
          <div className="risk-factors-title">⚠ Risk Factors Detected</div>
          {risk_factors.map((factor, i) => (
            <div key={i} className="risk-factor-item">{factor}</div>
          ))}
        </div>
      )}

      {/* Feature details (collapsible) */}
      {featureEntries.length > 0 && (
        <div>
          <button
            className="features-toggle"
            onClick={() => setShowFeatures((v) => !v)}
          >
            {showFeatures ? '▼' : '▶'} {showFeatures ? 'Hide' : 'Show'} extracted features
          </button>
          {showFeatures && (
            <div className="features-grid">
              {featureEntries.map(([key, val]) => (
                <div key={key} className="feature-cell">
                  <div className="feature-key">{fmtFeatureName(key)}</div>
                  <div className="feature-val">{String(val)}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Timestamp */}
      <div style={{ marginTop: '0.75rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
        Scanned at {ts}
      </div>
    </div>
  )
}
