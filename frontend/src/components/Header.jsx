// src/components/Header.jsx
// Top navigation bar with live server status indicator

import { useEffect, useState } from 'react'
import { healthCheck } from '../services/api'
import '../styles/Header.css'

export default function Header({ activePage, setActivePage }) {
  const [online, setOnline] = useState(null) // null = checking

  useEffect(() => {
    const check = async () => {
      try {
        await healthCheck()
        setOnline(true)
      } catch {
        setOnline(false)
      }
    }
    check()
    const interval = setInterval(check, 30_000) // re-check every 30 s
    return () => clearInterval(interval)
  }, [])

  const statusLabel =
    online === null ? 'Connecting…' : online ? 'API Online' : 'API Offline'
  const dotClass = online === null ? '' : online ? 'online' : 'offline'

  return (
    <header className="header">
      <div className="header-inner">
        {/* Logo */}
        <div className="header-logo">
          <div className="logo-icon">🛡️</div>
          <span className="logo-text">
            AI<span>Phish</span>Guard
          </span>
        </div>

        {/* Nav tabs */}
        <nav className="header-nav">
          <button
            className={`nav-tab ${activePage === 'home' ? 'active' : ''}`}
            onClick={() => setActivePage('home')}
          >
            Scanner
          </button>
          <button
            className={`nav-tab ${activePage === 'history' ? 'active' : ''}`}
            onClick={() => setActivePage('history')}
          >
            History
          </button>
        </nav>

        {/* Status */}
        <div className="header-status">
          <div className={`status-dot ${dotClass}`} />
          <span className="status-label">{statusLabel}</span>
        </div>
      </div>
    </header>
  )
}
