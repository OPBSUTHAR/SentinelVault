import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { SharesApi, errText } from '../api'
import { CopyButton, Spinner } from '../components/ui'

export default function PublicSharePage() {
  const { token } = useParams()
  const [data, setData] = useState<any>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [reveal, setReveal] = useState(false)

  useEffect(() => {
    if (!token) return
    SharesApi.view(token)
      .then(setData)
      .catch((e) => setError(errText(e)))
      .finally(() => setLoading(false))
  }, [token])

  const item = data?.item || {}

  return (
    <div className="auth-wrap">
      <div className="auth-card" style={{ maxWidth: 620, width: '100%' }}>
        <div className="auth-logo"><ShieldCheck size={22} style={{ color: 'var(--accent)' }} /> SentinelVault</div>

        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="alert-item critical">
            <b>This link is no longer available</b>
            <div className="msg" style={{ marginTop: 6 }}>{error}</div>
            <div className="time" style={{ marginTop: 6 }}>Share links expire and have limited views. Ask the sender for a fresh link.</div>
          </div>
        ) : (
          <>
            <div className="muted small" style={{ marginBottom: 4 }}>A secret was shared with you{data.label ? ` — “${data.label}”` : ''}</div>
            <h2 style={{ marginTop: 4 }}>{item.title}</h2>

            {item.username && <div className="kv"><span className="muted small">Username</span><span className="mono">{item.username}</span></div>}
            {item.email && <div className="kv"><span className="muted small">Email</span><span className="mono">{item.email}</span></div>}
            {item.url && (
              <div className="kv">
                <span className="muted small">Website</span>
                <a href={item.url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>{item.url}</a>
              </div>
            )}
            {item.password ? (
              <div className="kv">
                <span className="muted small">Password</span>
                <span className="row" style={{ gap: 8 }}>
                  <code className="mono" style={{ background: 'rgba(7,11,22,.85)', padding: '6px 10px', borderRadius: 8 }}>
                    {reveal ? item.password : '••••••••••••'}
                  </code>
                  <button className="icon-btn" onClick={() => setReveal(!reveal)}>{reveal ? <EyeOff size={14} /> : <Eye size={14} />}</button>
                  <CopyButton text={item.password} />
                </span>
              </div>
            ) : (
              <div className="muted small">(the sender chose not to include the password in this share)</div>
            )}
            {item.notes && <div className="kv"><span className="muted small">Notes</span><span className="small">{item.notes}</span></div>}

            <div className="muted small" style={{ marginTop: 14 }}>
              {typeof data.remaining_views === 'number' && <>Views remaining: <b>{data.remaining_views}</b> · </>}
              {data.expires_at && <>Expires {new Date(data.expires_at).toLocaleString()}</>}
            </div>
            <div className="muted small" style={{ marginTop: 10, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
              End-to-end encrypted share via SentinelVault. The content was decrypted in your browser session only.
            </div>
          </>
        )}
      </div>
    </div>
  )
}
