import { useState, useEffect, useCallback, useRef } from 'react'
import './index.css'

// ── DATA LAYER ────────────────────────────────────────────
const SAMPLE_EMAILS = [
  {
    id: 1,
    sender: 'Security Team <no-reply@paypa1.com>',
    subject: 'URGENT: Your account has been suspended',
    body: 'Dear User,\n\nOur automated systems have flagged suspicious activity on your account. Please click the link below immediately to verify your identity and restore access.\n\nhttps://paypa1.com/login/verify?token=xGH92kZ\nhttps://bit.ly/3xF2aAbC\n\nFailure to act within 24 hours will result in permanent account suspension.\n\nFrom: security@paypa1.com\nAuthentication-Results: spf=fail dkim=fail',
    time: '09:41',
    verdict: 'PHISHING',
    threat_score: 82,   // 45×0.20 + 92×0.55 + (95²/100)×0.25 = 9+50.6+22.6 = 82
    analyzed: true,
    engine1: { score: 45, label: 'THREAT', findings: ['SPF: FAIL', 'DKIM: FAIL', 'Domain Spoofing: DETECTED'] },
    engine2: { score: 92, label: 'THREAT', findings: ['NLP model confidence: 92%', 'Suspicious keywords: urgent, account suspended, verify, click here, immediately'] },
    engine3: { score: 95, label: 'MALICIOUS', findings: ['paypa1.com/login/verify -> MALICIOUS (95%)', 'bit.ly/3xF2aAbC -> SUSPICIOUS (72%)'] },
    reasoning_log: [
      '[DISPATCHER] Formula: (E1×20%) + (E2×55%) + (URL²/100×25%)',
      '[DISPATCHER] Final weighted score: 82%  →  PHISHING',
      '[ENGINE 1] Header score: 45%  →  THREAT',
      '  • SPF: FAIL', '  • DKIM: FAIL',
      '[ENGINE 2] NLP score: 92%  →  THREAT',
      '  • NLP model confidence: 92%',
      '[ENGINE 3] URL score: 95%  →  dampened to 90%  →  MALICIOUS',
      '  • paypa1.com/login/verify -> MALICIOUS (95%)',
    ],
  },
  {
    id: 2,
    sender: 'IT Department <it@company.com>',
    subject: 'Weekly System Maintenance Schedule',
    body: 'Hi team,\n\nPlease be advised of the upcoming maintenance window this Friday from 11pm-2am.\n\nThe following services will be unavailable:\n- Email\n- Internal wiki\n- VPN access\n\nContact helpdesk@company.com for questions.',
    time: '08:22',
    verdict: 'SAFE',
    threat_score: 4,    // 0×0.20 + 8×0.55 + 0×0.25 = 4
    analyzed: true,
    engine1: { score: 0, label: 'SAFE', findings: ['SPF: PASS', 'DKIM: PASS'] },
    engine2: { score: 8, label: 'SAFE', findings: ['No suspicious keywords detected', 'NLP model confidence: 8%'] },
    engine3: { score: 0, label: 'SAFE', findings: ['No URLs found in email'] },
    reasoning_log: [
      '[DISPATCHER] Formula: (E1×20%) + (E2×55%) + (URL²/100×25%)',
      '[DISPATCHER] Final weighted score: 4%  →  SAFE',
      '[ENGINE 1] Header score: 0%  →  SAFE',
      '  • SPF: PASS', '  • DKIM: PASS',
      '[ENGINE 2] NLP score: 8%  →  SAFE',
      '  • No suspicious keywords detected',
      '[ENGINE 3] URL score: 0%  →  dampened to 0%  →  SAFE',
      '  • No URLs found in email',
    ],
  },
  {
    id: 3,
    sender: 'Billing <billing@microsft-support.net>',
    subject: 'Invoice #94402 Overdue - Action Required',
    body: 'Your invoice is OVERDUE.\n\nDownload your invoice: http://microsft-support.net/invoice.php?id=94402\n\nImmediate payment required to avoid service interruption.',
    time: 'Yesterday',
    verdict: 'PHISHING',
    threat_score: 68,   // 30×0.20 + 78×0.55 + (88²/100)×0.25 = 6+42.9+19.4 = 68
    analyzed: true,
    engine1: { score: 30, label: 'SUSPICIOUS', findings: ['SPF: MISSING', 'DKIM: MISSING'] },
    engine2: { score: 78, label: 'THREAT', findings: ['Suspicious keywords: overdue, immediate, action required, invoice'] },
    engine3: { score: 88, label: 'MALICIOUS', findings: ['microsft-support.net/invoice.php -> MALICIOUS (88%)'] },
    reasoning_log: [
      '[DISPATCHER] Formula: (E1×20%) + (E2×55%) + (URL²/100×25%)',
      '[DISPATCHER] Final weighted score: 68%  →  PHISHING',
      '[ENGINE 1] Header score: 30%  →  SUSPICIOUS',
      '  • SPF: MISSING', '  • DKIM: MISSING',
      '[ENGINE 2] NLP score: 78%  →  THREAT',
      '  • Suspicious keywords: overdue, immediate, invoice',
      '[ENGINE 3] URL score: 88%  →  dampened to 77%  →  MALICIOUS',
      '  • microsft-support.net/invoice.php -> MALICIOUS (88%)',
    ],
  },
]


const API_BASE = 'http://127.0.0.1:5000'

// ── BADGE ─────────────────────────────────────────────────
function Badge({ verdict }) {
  const cls = verdict === 'PHISHING' ? 'threat' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe'
  const icon = verdict === 'PHISHING' ? '🚨' : verdict === 'SUSPICIOUS' ? '⚠️' : '✅'
  return <span className={`badge ${cls}`}>{icon} {verdict}</span>
}

// ── THREAT GAUGE ──────────────────────────────────────────
function ThreatGauge({ score, verdict }) {
  const color = verdict === 'PHISHING' ? 'var(--color-red)' : verdict === 'SUSPICIOUS' ? 'var(--color-amber)' : 'var(--color-green)'
  const radius = 56
  const circ = 2 * Math.PI * radius
  const offset = circ - (score / 100) * circ

  return (
    <div className="threat-gauge">
      <svg viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--color-border)" strokeWidth="8" />
        <circle
          cx="70" cy="70" r={radius} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
      </svg>
      <span className="threat-gauge__value" style={{ color }}>{score}%</span>
    </div>
  )
}

// ── ENGINE RESULT CARD ────────────────────────────────────
function EngineCard({ title, data }) {
  if (!data) return null
  const cls = data.label === 'THREAT' ? 'threat' : data.label === 'SUSPICIOUS' ? 'suspicious' : 'safe'
  return (
    <div className={`engine-result-card ${cls}`}>
      <div className="engine-result-card__header">
        <span className="engine-result-card__title">{title}</span>
        <span className={`engine-score ${cls}`}>{data.score}/100</span>
      </div>
      <div className="engine-result-card__body">
        <Badge verdict={data.label} />
        {(data.findings || []).slice(0, 5).map((f, i) => (
          <div key={i} className="finding-item">
            <span style={{ opacity: 0.5, flexShrink: 0 }}>›</span>
            <span>{f}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── ANALYSIS RESULTS VIEW ─────────────────────────────────
// onOverride(verdict) — optional prop, only provided by InboxTab
function ResultsView({ result, onBack, onOverride }) {
  const [overrideApplied, setOverrideApplied] = useState(null)

  // Live-update display based on override
  const displayVerdict = overrideApplied || result.verdict
  const displayScore = overrideApplied === 'SAFE' ? 0
    : overrideApplied === 'PHISHING' ? 99
      : result.threat_score

  const cls = displayVerdict === 'PHISHING' ? 'threat' : displayVerdict === 'SUSPICIOUS' ? 'suspicious' : 'safe'
  const verdictLabel = displayVerdict === 'PHISHING'
    ? 'HIGH RISK — Likely Phishing Email'
    : displayVerdict === 'SUSPICIOUS'
      ? 'MODERATE RISK — Exercise Caution'
      : 'LOW RISK — Email appears legitimate'

  const handleOverride = (verdict) => {
    setOverrideApplied(verdict)
    if (onOverride) onOverride(verdict)   // update the email list badge in InboxTab
  }

  const copyReport = () => {
    const text = [
      'PhishGuard Threat Report',
      `Verdict: ${displayVerdict} (${displayScore}%)${overrideApplied ? ' [MANUALLY OVERRIDDEN]' : ''}`,
      `Subject: ${result.subject || 'N/A'}`,
      `Sender: ${result.sender || 'N/A'}`,
      '',
      ...(result.reasoning_log || [])
    ].join('\n')
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="results-view">
      {/* Back button */}
      <button
        className="action-btn"
        style={{ alignSelf: 'flex-start', flex: 'none', minWidth: 'auto', marginBottom: '-8px' }}
        onClick={onBack}
      >
        &larr; Back to Inbox
      </button>

      {/* Override confirmation banner */}
      {overrideApplied && (
        <div style={{
          background: overrideApplied === 'SAFE' ? 'rgba(0,255,136,0.07)' : 'rgba(255,59,59,0.08)',
          border: `1px solid ${overrideApplied === 'SAFE' ? 'var(--color-green)' : 'var(--color-red)'}`,
          borderRadius: 'var(--radius-md)',
          padding: '0.65rem 1.2rem',
          fontSize: '0.83rem',
          color: overrideApplied === 'SAFE' ? 'var(--color-green)' : 'var(--color-red)',
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          fontWeight: 500
        }}>
          {overrideApplied === 'SAFE'
            ? '✅ Override applied — email marked as SAFE. Badge updated in inbox.'
            : '🚨 Override applied — email marked as SPAM. Badge updated in inbox.'}
        </div>
      )}

      {/* Threat Hero */}
      <div className={`threat-hero ${cls}`}>
        <ThreatGauge score={displayScore} verdict={displayVerdict} />
        <div className="threat-hero__info">
          <div className="threat-hero__title">Phishing Threat Confidence</div>
          <div className="threat-hero__verdict" style={{
            color: cls === 'threat' ? 'var(--color-red)' : cls === 'suspicious' ? 'var(--color-amber)' : 'var(--color-green)'
          }}>
            {displayVerdict}
          </div>
          <div style={{ marginBottom: '0.75rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <Badge verdict={displayVerdict} />
            {overrideApplied && (
              <span style={{
                fontSize: '0.68rem', color: 'var(--color-text-muted)',
                background: 'rgba(74,85,104,0.15)', border: '1px solid #4A5568',
                borderRadius: 'var(--radius-pill)', padding: '2px 8px'
              }}>
                ✏️ OVERRIDE
              </span>
            )}
          </div>
          <div className="threat-hero__subject" style={{ marginBottom: '0.25rem' }}>{verdictLabel}</div>
          {result.subject && <div style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>📧 {result.subject}</div>}
          {result.sender && <div style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>👤 {result.sender}</div>}
        </div>
      </div>

      {/* 3 Engine Cards */}
      <div className="engine-results-grid">
        <EngineCard title="⚙️ Engine 1: Header Analysis" data={result.engine1} />
        <EngineCard title="🧠 Engine 2: NLP Content" data={result.engine2} />
        <EngineCard title="🔗 Engine 3: URL XGBoost" data={result.engine3} />
      </div>

      {/* Reasoning Log */}
      <div className="reasoning-block">
        <div className="reasoning-block__header">🖥  AI Reasoning Log</div>
        <pre className="reasoning-log">
          {(result.reasoning_log || []).join('\n')}
        </pre>
      </div>

      {/* Action buttons — all wired up */}
      <div className="action-buttons">
        <button
          className="action-btn danger"
          onClick={() => handleOverride('PHISHING')}
          disabled={displayVerdict === 'PHISHING'}
          title={displayVerdict === 'PHISHING' ? 'Already marked as spam' : 'Override verdict to PHISHING/SPAM'}
        >
          🗑️ {displayVerdict === 'PHISHING' ? 'Marked as Spam ✓' : 'Mark as Spam'}
        </button>

        <button className="action-btn" onClick={copyReport}>
          📋 Copy Report
        </button>

        <button
          className="action-btn safe"
          onClick={() => handleOverride('SAFE')}
          disabled={displayVerdict === 'SAFE'}
          title={displayVerdict === 'SAFE' ? 'Already marked as safe' : 'Override verdict to SAFE'}
        >
          ✅ {displayVerdict === 'SAFE' ? 'Marked as Safe ✓' : 'Mark as Safe (Override)'}
        </button>
      </div>
    </div>
  )
}

// ── MANUAL SCAN TAB ───────────────────────────────────────
function ManualScanTab() {
  const [rawText, setRawText] = useState('')
  const [subject, setSubject] = useState('')
  const [sender, setSender] = useState('')
  const [authResults, setAuthResults] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleAnalyze = async () => {
    if (!rawText.trim()) { setError('Please paste some email text first.'); return }
    setError(''); setLoading(true); setResult(null)

    const combinedText = `From: ${sender}\nSubject: ${subject}\nAuthentication-Results: ${authResults}\n\n${rawText}`
    try {
      const resp = await fetch(`${API_BASE}/api/scan_manual`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_text: combinedText, subject, sender }),
      })
      const data = await resp.json()
      if (data.status === 'error') throw new Error(data.message)
      setResult(data)
    } catch (e) {
      setError(`Analysis failed: ${e.message}`)
    } finally {
      setLoading(false)
    }
  }

  // Manual scan results don't need onOverride (no email list to update)
  if (result) return <ResultsView result={result} onBack={() => setResult(null)} />

  return (
    <div className="manual-scan-view">
      <div className="scan-header">
        <h1>🔍 Manual Email Scanner</h1>
        <p>Paste raw email headers or body text below for instant AI-powered phishing analysis</p>
      </div>

      <div className="scan-form">
        {error && <div className="error-banner">⚠️ {error}</div>}

        <textarea
          className="scan-textarea"
          value={rawText}
          onChange={e => setRawText(e.target.value)}
          placeholder={`Paste email headers or body here...\n\nExample:\nFrom: security@paypa1.com\nSubject: URGENT: Your account has been suspended\nAuthentication-Results: spf=fail dkim=fail\n\nDear User, Click here immediately to verify...`}
        />

        <div className="scan-fields-row">
          <div className="scan-field">
            <label>Sender Email</label>
            <input value={sender} onChange={e => setSender(e.target.value)} placeholder="sender@domain.com" />
          </div>
          <div className="scan-field">
            <label>Subject Line</label>
            <input value={subject} onChange={e => setSubject(e.target.value)} placeholder="Email subject..." />
          </div>
          <div className="scan-field">
            <label>Authentication-Results</label>
            <input value={authResults} onChange={e => setAuthResults(e.target.value)} placeholder="spf=pass dkim=pass..." />
          </div>
        </div>

        <button className="analyze-btn" onClick={handleAnalyze} disabled={loading}>
          {loading
            ? <><span className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} /> Analyzing…</>
            : '🛡️ ANALYZE FOR THREATS'
          }
        </button>

        <div className="engine-cards">
          <div className="engine-card"><span className="engine-icon">⚙️</span><span>Engine 1: Header Analysis — Rule-based SPF/DKIM checks</span></div>
          <div className="engine-card"><span className="engine-icon">🧠</span><span>Engine 2: NLP Content — Naive Bayes keyword model</span></div>
          <div className="engine-card"><span className="engine-icon">🔗</span><span>Engine 3: URL XGBoost — 111-feature URL classifier</span></div>
        </div>
      </div>
    </div>
  )
}

// ── INBOX TAB ─────────────────────────────────────────────
function InboxTab() {
  const [emails, setEmails] = useState(SAMPLE_EMAILS)
  const [selectedId, setSelectedId] = useState(null)
  const [scanResult, setScanResult] = useState(null)
  const [fetching, setFetching] = useState(false)
  const [scanLoading, setScanLoading] = useState(false)
  const [error, setError] = useState('')

  // useRef so seen-ID check is synchronous — not affected by React batching
  const seenImapIds = useRef(new Set(['demo-1', 'demo-2', 'demo-3']))

  const selectedEmail = emails.find(e => e.id === selectedId)

  // ── Auto polling every 15 seconds ──
  const fetchLive = useCallback(async (silent = false) => {
    if (!silent) setFetching(true)
    setError('')
    try {
      const resp = await fetch(`${API_BASE}/api/fetch_live`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      if (!resp.ok) throw new Error(`Server error ${resp.status}`)
      const data = await resp.json()
      if (data.status === 'error') throw new Error(data.message)
      if (data.status === 'no_new_email') return

      // data.emails is now an array of all analyzed emails
      const incoming = (data.emails || [])
      const toAdd = []

      for (const em of incoming) {
        const uid = em.imap_id || em.msg_id || `${em.subject}-${em.sender}`
        if (seenImapIds.current.has(uid)) continue   // already shown
        seenImapIds.current.add(uid)
        toAdd.push({
          id: `live-${uid}`,
          imap_id: uid,
          sender: em.sender || 'Unknown',
          subject: em.subject || 'No Subject',
          body: em.body || '',
          time: em.date
            ? new Date(em.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          verdict: em.verdict,
          threat_score: em.threat_score,
          analyzed: true,
          folder: em.folder || 'Inbox',
          engine1: em.engine1,
          engine2: em.engine2,
          engine3: em.engine3,
          reasoning_log: em.reasoning_log,
        })
      }

      if (toAdd.length > 0) {
        setEmails(prev => [...toAdd, ...prev])
      }
    } catch (e) {
      if (!silent) setError(e.message)
    } finally {
      setFetching(false)
    }
  }, [])  // seenImapIds ref is stable

  useEffect(() => {
    const id = setInterval(() => fetchLive(true), 15000)
    return () => clearInterval(id)
  }, [fetchLive])

  const handleScanEmail = async () => {
    if (!selectedEmail) return
    setScanLoading(true)
    setError('')
    try {
      const resp = await fetch(`${API_BASE}/api/scan_manual`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_text: selectedEmail.body,
          subject: selectedEmail.subject,
          sender: selectedEmail.sender,
        }),
      })
      const data = await resp.json()
      if (data.status === 'error') throw new Error(data.message)
      setScanResult({ ...data, id: selectedEmail.id })
    } catch (e) {
      // Fallback to demo result
      if (selectedEmail.analyzed) {
        setScanResult(selectedEmail)
      } else {
        setError(e.message)
      }
    } finally {
      setScanLoading(false)
    }
  }

  // Called from ResultsView when user clicks Mark as Spam or Mark as Safe
  const handleOverride = (verdict) => {
    if (!selectedId) return
    setEmails(prev => prev.map(em =>
      em.id === selectedId ? { ...em, verdict, analyzed: true } : em
    ))
  }

  if (scanResult) return (
    <ResultsView
      result={scanResult}
      onBack={() => setScanResult(null)}
      onOverride={handleOverride}
    />
  )

  return (
    <div className="inbox-view">
      {/* Left: Email List */}
      <div className="email-list-panel">
        <div className="email-list-header">
          <h2>Inbox ({emails.length})</h2>
          <button className="fetch-btn" onClick={() => fetchLive(false)} disabled={fetching}>
            {fetching
              ? <><span style={{ width: 10, height: 10, border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.8s linear infinite' }} /> Fetching…</>
              : '📥 Fetch Live'
            }
          </button>
        </div>

        {error && <div className="error-banner" style={{ margin: '8px', borderRadius: '6px', fontSize: '0.75rem' }}>⚠️ {error}</div>}

        <div className="email-list">
          {emails.map(em => (
            <div
              key={em.id}
              className={`email-row ${selectedId === em.id ? 'selected' : ''}`}
              onClick={() => { setSelectedId(em.id); setScanResult(null) }}
            >
              <div className="email-row__top">
                <span className="email-row__sender">{em.sender.replace(/<.*>/, '').trim()}</span>
                <span className="email-row__time">{em.time}</span>
              </div>
              <div className="email-row__subject">{em.subject}</div>
              <div className="email-row__footer">
                {em.analyzed && <Badge verdict={em.verdict} />}
                {em.folder && em.folder !== 'Inbox' && (
                  <span style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', background: 'rgba(255,165,0,0.1)', border: '1px solid rgba(255,165,0,0.3)', borderRadius: 'var(--radius-pill)', padding: '1px 6px', marginLeft: 4 }}>
                    📁 {em.folder}
                  </span>
                )}
              </div>
            </div>
          ))}
          {emails.length === 0 && (
            <div className="empty-inbox">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M4 4h16v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4z" />
                <polyline points="4,4 12,13 20,4" />
              </svg>
              <div>No emails yet</div>
              <div style={{ fontSize: '0.75rem' }}>Click "Fetch Live" to check Gmail</div>
            </div>
          )}
        </div>
      </div>

      {/* Right: Email Detail */}
      <div className="email-detail-panel">
        {!selectedEmail ? (
          <div className="email-detail-placeholder">
            <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M4 4h16v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4z" />
              <polyline points="4,4 12,13 20,4" />
            </svg>
            <div>Select an email to preview</div>
          </div>
        ) : (
          <>
            <div className="email-detail-header">
              <div className="email-detail-subject">{selectedEmail.subject}</div>
              <div className="email-detail-meta">
                <span><strong>From</strong>{selectedEmail.sender}</span>
                <span><strong>Time</strong>{selectedEmail.time}</span>
                {selectedEmail.analyzed && (
                  <span><strong>Status</strong><Badge verdict={selectedEmail.verdict} /></span>
                )}
              </div>
            </div>

            {selectedEmail.body && (
              <div className="email-detail-body">{selectedEmail.body}</div>
            )}

            <div className="scan-trigger">
              <button className="scan-btn-large" onClick={handleScanEmail} disabled={scanLoading}>
                {scanLoading
                  ? <><span style={{ width: 16, height: 16, border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.8s linear infinite' }} /> Analyzing…</>
                  : '🔍 Scan for Phishing'
                }
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ── ROOT APP ──────────────────────────────────────────────
export default function App() {
  const [activeTab, setActiveTab] = useState('inbox')
  const [pollTime, setPollTime] = useState('—')
  const [backendOnline, setBackendOnline] = useState(false)

  // Check backend health on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/health`)
      .then(r => r.json())
      .then(d => setBackendOnline(d.status === 'online'))
      .catch(() => setBackendOnline(false))
  }, [])

  // Countdown timer display
  useEffect(() => {
    let count = 15
    const id = setInterval(() => {
      count -= 1
      if (count <= 0) { count = 15; setPollTime('now') }
      else setPollTime(`${count}s`)
    }, 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="app-shell">
      <nav className="navbar">
        <div className="navbar__brand">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5 4.5-1.35 8-6.25 8-11.5V6L12 2z" />
            <circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" opacity="0.8" />
          </svg>
          PHISHGUARD
        </div>

        <div className="navbar__tabs">
          <button className={`navbar__tab ${activeTab === 'inbox' ? 'active' : ''}`} onClick={() => setActiveTab('inbox')}>
            📥 Inbox
          </button>
          <button className={`navbar__tab ${activeTab === 'manual' ? 'active' : ''}`} onClick={() => setActiveTab('manual')}>
            🔍 Manual Scan
          </button>
        </div>

        <div className="navbar__status">
          <div className={`status-dot ${backendOnline ? '' : 'offline'}`} />
          {backendOnline ? 'Backend Online' : 'Backend Offline'}
        </div>
      </nav>

      <main className="main-content">
        {activeTab === 'inbox' && <InboxTab />}
        {activeTab === 'manual' && <ManualScanTab />}
      </main>

      <div className="status-bar">
        <div className={`status-dot ${backendOnline ? '' : 'offline'}`} style={{ width: 6, height: 6 }} />
        Auto-scanning every 15s | Next check in: <strong style={{ color: 'var(--color-blue)' }}>{pollTime}</strong>
        &nbsp;|&nbsp;
        {backendOnline ? '🛡️ All engines operational' : '⚠️ Backend offline — demo mode active'}
      </div>
    </div>
  )
}
