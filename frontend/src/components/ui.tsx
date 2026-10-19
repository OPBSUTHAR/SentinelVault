import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { Copy, Check, X, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'

export function Card({ title, sub, children, style, action }: { title?: string; sub?: string; children: ReactNode; style?: any; action?: ReactNode }) {
  return (
    <div className="card" style={style}>
      {(title || action) && (
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>{title && <h3>{title}</h3>}{sub && <div className="card-sub">{sub}</div>}</div>
          {action}
        </div>
      )}
      {children}
    </div>
  )
}

export function Badge({ tone = 'low', children }: { tone?: string; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>
}

export function severityTone(sev: string): string {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'critical'
  if (s === 'high' || s === 'warning') return 'warn'
  if (s === 'medium') return 'info'
  if (s === 'low') return 'low'
  if (s === 'ok' || s === 'safe' || s === 'none') return 'ok'
  return 'info'
}

export function Spinner() {
  return <div className="spinner" />
}

export function Empty({ icon, text }: { icon?: ReactNode; text: string }) {
  return (
    <div className="empty">
      <div className="big">{icon || <ShieldQuestion size={30} />}</div>
      {text}
    </div>
  )
}

export function ScoreRing({ score, grade }: { score: number; grade?: string }) {
  const color = score >= 80 ? 'var(--ok)' : score >= 60 ? '#84cc16' : score >= 40 ? 'var(--warn)' : 'var(--danger)'
  return (
    <div className="ring" style={{ ['--pct' as any]: score, ['--ring-color' as any]: color }}>
      <div className="ring-inner">
        <div className="ring-score">{score}</div>
        <div className="ring-label">Grade {grade || '—'}</div>
      </div>
    </div>
  )
}

export function StrengthMeter({ score }: { score: number }) {
  const color = score >= 80 ? 'var(--ok)' : score >= 60 ? '#84cc16' : score >= 40 ? 'var(--warn)' : 'var(--danger)'
  return (
    <div className="meter">
      <div style={{ width: `${Math.max(3, Math.min(100, score))}%`, background: color }} />
    </div>
  )
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="btn ghost sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
        } catch {
          const ta = document.createElement('textarea')
          ta.value = text
          document.body.appendChild(ta)
          ta.select()
          document.execCommand('copy')
          ta.remove()
        }
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      }}
    >
      {copied ? <Check size={13} /> : <Copy size={13} />} {label || (copied ? 'Copied' : 'Copy')}
    </button>
  )
}

interface ToastMsg { id: number; text: string; kind: 'info' | 'success' | 'error' }
const ToastCtx = createContext<(text: string, kind?: ToastMsg['kind']) => void>(() => {})

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMsg[]>([])
  const push = (text: string, kind: ToastMsg['kind'] = 'info') => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, text, kind }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200)
  }
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast">
        {toasts.map((t) => (
          <div key={t.id} className={`msg ${t.kind}`}>{t.text}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

export const useToast = () => useContext(ToastCtx)

export function Modal({ title, onClose, children, width }: { title: string; onClose: () => void; children: ReactNode; width?: number }) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])
  return (
    <div className="modal-overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={width ? { maxWidth: width } : undefined}>
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
          <h2 style={{ margin: 0 }}>{title}</h2>
          <button className="icon-btn" onClick={onClose}><X size={15} /></button>
        </div>
        {children}
      </div>
    </div>
  )
}

export function VerdictIcon({ verdict }: { verdict: string }) {
  if (verdict === 'malicious' || verdict === 'suspicious') return <ShieldAlert size={16} style={{ color: 'var(--danger)' }} />
  if (verdict === 'safe' || verdict === 'likely_safe') return <ShieldCheck size={16} style={{ color: 'var(--ok)' }} />
  return <ShieldQuestion size={16} style={{ color: 'var(--muted)' }} />
}

export function timeAgo(iso: string): string {
  if (!iso) return ''
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return iso
  const diff = Math.max(0, Date.now() - then)
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  return new Date(iso).toLocaleDateString()
}
