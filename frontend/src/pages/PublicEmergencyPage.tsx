import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Eye, EyeOff, LifeBuoy, ShieldAlert, ShieldCheck, Send } from 'lucide-react'
import { EmergencyApi, errText } from '../api'
import { Badge, CopyButton, Spinner, timeAgo, useToast } from '../components/ui'

export default function PublicEmergencyPage() {
  const { token } = useParams()
  return token ? <StatusView token={token} /> : <RequestView />
}

function StatusView({ token }: { token: string }) {
  const [data, setData] = useState<any>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [revealed, setRevealed] = useState<Record<number, boolean>>({})

  useEffect(() => {
    EmergencyApi.check(token)
      .then(setData)
      .catch((e) => setError(errText(e)))
      .finally(() => setLoading(false))
  }, [token])

  return (
    <div className="auth-wrap">
      <div className="auth-card" style={{ maxWidth: 640, width: '100%' }}>
        <div className="auth-logo"><LifeBuoy size={22} style={{ color: 'var(--accent)' }} /> SentinelVault Emergency Access</div>
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="alert-item critical"><b>Invalid or expired tracking link</b><div className="msg" style={{ marginTop: 6 }}>{error}</div></div>
        ) : (
          <>
            <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
              <span className="muted small">Request {data.request_id}</span>
              <Badge tone={data.status === 'approved' ? 'ok' : data.status === 'denied' ? 'danger' : 'warn'}>{data.status}</Badge>
            </div>
            <div className="muted small" style={{ marginBottom: 14 }}>
              Requested {timeAgo(data.requested_at)}{data.decided_at ? ` · decided ${timeAgo(data.decided_at)}` : ''}
            </div>

            {data.status === 'pending' && (
              <div className="alert-item">
                <div className="row" style={{ gap: 8 }}><ShieldAlert size={16} style={{ color: 'var(--warn)' }} /><b>Waiting for the vault owner to approve</b></div>
                <div className="msg" style={{ marginTop: 6 }}>
                  The owner has to unlock their vault and approve this request. Check back at this link later.
                </div>
              </div>
            )}

            {data.status === 'denied' && (
              <div className="alert-item critical">
                <div className="row" style={{ gap: 8 }}><ShieldAlert size={16} style={{ color: 'var(--danger)' }} /><b>This request was denied</b></div>
                <div className="msg" style={{ marginTop: 6 }}>The vault owner declined to release access.</div>
              </div>
            )}

            {data.status === 'approved' && data.bundle && (
              <>
                <div className="alert-item" style={{ borderColor: 'rgba(34,197,94,.4)' }}>
                  <div className="row" style={{ gap: 8 }}><ShieldCheck size={16} style={{ color: 'var(--ok)' }} /><b>Access granted — {data.bundle.length} entries released</b></div>
                  <div className="msg" style={{ marginTop: 6 }}>
                    This is the emergency snapshot the owner approved. Treat it confidentially.
                  </div>
                </div>
                {data.bundle.map((b: any, i: number) => (
                  <div key={i} className="list-item" style={{ alignItems: 'flex-start' }}>
                    <div className="grow">
                      <div className="title">{b.title} <span className="muted small">· {b.category}</span></div>
                      <div className="sub">{b.username || b.email || '—'}</div>
                      {b.password && (
                        <div className="row" style={{ gap: 8, marginTop: 6 }}>
                          <code className="mono small" style={{ background: 'rgba(7,11,22,.85)', padding: '5px 8px', borderRadius: 7 }}>
                            {revealed[i] ? b.password : '••••••••••••'}
                          </code>
                          <button className="icon-btn" onClick={() => setRevealed((r) => ({ ...r, [i]: !r[i] }))}>
                            {revealed[i] ? <EyeOff size={13} /> : <Eye size={13} />}
                          </button>
                          <CopyButton text={b.password} />
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function RequestView() {
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')
  const toast = useToast()

  const submit = async () => {
    if (!email) return toast('Enter the email the vault owner registered for you', 'error')
    setBusy(true)
    setError('')
    try {
      const res = await EmergencyApi.request({ email, message })
      setResult(res)
    } catch (e) {
      setError(errText(e))
    } finally {
      setBusy(false)
    }
  }

  const link = result ? `${window.location.origin}/emergency/status/${result.token}` : ''

  return (
    <div className="auth-wrap">
      <div className="auth-card" style={{ maxWidth: 560, width: '100%' }}>
        <div className="auth-logo"><LifeBuoy size={22} style={{ color: 'var(--accent)' }} /> SentinelVault Emergency Access</div>
        {result ? (
          <>
            <div className="alert-item" style={{ borderColor: 'rgba(34,211,238,.4)' }}>
              <b>Request sent</b>
              <div className="msg" style={{ marginTop: 6 }}>
                The vault owner has been notified and must approve your request. Bookmark this tracking link to see the decision:
              </div>
              <div className="row" style={{ marginTop: 10 }}>
                <code className="mono small" style={{ flex: 1, background: 'rgba(7,11,22,.85)', padding: '8px 10px', borderRadius: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{link}</code>
                <CopyButton text={link} label="Copy link" />
              </div>
            </div>
          </>
        ) : (
          <>
            <div className="muted small" style={{ marginBottom: 14 }}>
              If you are a registered emergency contact of a SentinelVault owner, you can ask for access here.
              The owner must approve before anything is released.
            </div>
            <div className="field">
              <label>Your email</label>
              <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="contact@example.com" />
            </div>
            <div className="field">
              <label>Why do you need access? (optional)</label>
              <textarea className="input" value={message} onChange={(e) => setMessage(e.target.value)} placeholder="The owner is unavailable and I need to reach their accounts." />
            </div>
            {error && <div style={{ color: 'var(--danger)', fontSize: 12.5, marginBottom: 10 }}>{error}</div>}
            <button className="btn wide" onClick={submit} disabled={busy}>
              <Send size={14} /> {busy ? 'Sending…' : 'Request emergency access'}
            </button>
          </>
        )}
      </div>
    </div>
  )
}
