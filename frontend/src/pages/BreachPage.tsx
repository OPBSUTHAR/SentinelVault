import { useState } from 'react'
import { Radar, Search, ShieldAlert, ShieldCheck } from 'lucide-react'
import { SecurityApi, errText } from '../api'
import { Badge, Card, Empty, Spinner, severityTone, useToast } from '../components/ui'

export default function BreachPage() {
  const [pw, setPw] = useState('')
  const [pwResult, setPwResult] = useState<any>(null)
  const [pwBusy, setPwBusy] = useState(false)

  const [email, setEmail] = useState('')
  const [emailData, setEmailData] = useState<any>(null)
  const [emailBusy, setEmailBusy] = useState(false)
  const toast = useToast()

  const checkPw = async () => {
    if (!pw) return
    setPwBusy(true)
    try {
      const d = await SecurityApi.checkPassword(pw)
      setPwResult(d.result)
    } catch (e) {
      toast(errText(e), 'error')
    } finally {
      setPwBusy(false)
    }
  }

  const checkEmail = async () => {
    if (!email) return
    setEmailBusy(true)
    try {
      const d = await SecurityApi.checkEmail(email)
      setEmailData(d)
    } catch (e) {
      toast(errText(e), 'error')
    } finally {
      setEmailBusy(false)
    }
  }

  return (
    <div className="grid" style={{ gap: 16 }}>
      <Card title="Is this password breached?" sub="Checked against the Have I Been Pwned Pwned Passwords corpus using k-anonymity">
        <div className="row">
          <input className="input mono" type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="Type a password to check…" onKeyDown={(e) => e.key === 'Enter' && checkPw()} />
          <button className="btn" onClick={checkPw} disabled={pwBusy || !pw}>{pwBusy ? 'Checking…' : 'Check password'}</button>
        </div>
        {pwBusy && <div style={{ marginTop: 12 }}><Spinner /></div>}
        {pwResult && !pwBusy && (
          <div style={{ marginTop: 14 }}>
            {pwResult.breached ? (
              <div className="alert-item critical">
                <div className="row" style={{ gap: 8 }}>
                  <ShieldAlert size={18} style={{ color: 'var(--danger)' }} />
                  <b>This password was found in a data breach — change it now</b>
                </div>
                <div className="msg" style={{ marginTop: 6 }}>
                  Seen <b className="mono">{Number(pwResult.count).toLocaleString()}</b> times in the Pwned Passwords corpus.
                  Known-breached passwords are cracked first — rotate it everywhere you used it.
                </div>
                <div className="time">source: {pwResult.source}</div>
              </div>
            ) : (
              <div className="alert-item" style={{ borderColor: 'rgba(34,197,94,.4)' }}>
                <div className="row" style={{ gap: 8 }}>
                  <ShieldCheck size={18} style={{ color: 'var(--ok)' }} />
                  <b>Not found in the breach corpus</b>
                </div>
                <div className="msg" style={{ marginTop: 6 }}>
                  {pwResult.available === false
                    ? 'The breach database was unreachable right now — try again later.'
                    : `Count: ${pwResult.count ?? 0}. This specific password is not part of any known public breach.`}
                </div>
                <div className="time">source: {pwResult.source}</div>
              </div>
            )}
            <div className="muted small" style={{ marginTop: 10 }}>
              <Radar size={12} /> Privacy: only the first 5 characters of the password's SHA-1 hash are sent to HIBP — the password itself never leaves SentinelVault.
            </div>
          </div>
        )}
      </Card>

      <Card title="Was this email/account in a breach?" sub="Live HIBP account lookup when an API key is configured; otherwise a reference catalog of famous breaches">
        <div className="row">
          <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" onKeyDown={(e) => e.key === 'Enter' && checkEmail()} />
          <button className="btn" onClick={checkEmail} disabled={emailBusy || !email}>{emailBusy ? 'Searching…' : 'Check account'}</button>
        </div>

        {emailBusy && <div style={{ marginTop: 12 }}><Spinner /></div>}

        {emailData && !emailBusy && (
          <div style={{ marginTop: 14 }}>
            {emailData.result?.available === false && (
              <div className="muted small" style={{ marginBottom: 10 }}>
                {emailData.result.message || 'Live account lookup unavailable.'} Showing the reference catalog instead.
              </div>
            )}
            {(emailData.result?.breaches || []).length === 0 ? (
              <Empty icon={<Search size={26} />} text="No breaches to show for this lookup." />
            ) : (
              <table className="table">
                <thead><tr><th>Breach</th><th>When</th><th>Accounts</th><th>Severity</th><th>Data exposed</th></tr></thead>
                <tbody>
                  {(emailData.result.breaches || []).map((b: any, i: number) => (
                    <tr key={i}>
                      <td><b>{b.name}</b></td>
                      <td className="muted small">{b.breach_date || b.date || '—'}</td>
                      <td className="mono small">{b.pwn_count ? Number(b.pwn_count).toLocaleString() : '—'}</td>
                      <td><Badge tone={severityTone(b.severity)}>{b.severity || 'unknown'}</Badge></td>
                      <td className="small muted">{(b.data_classes || b.dataClasses || []).slice(0, 4).join(', ') || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {emailData.impact && (
              <div style={{ marginTop: 16 }}>
                <div className="row wrap" style={{ gap: 10, marginBottom: 10 }}>
                  <Badge tone={severityTone(emailData.impact.max_severity)}>max severity: {emailData.impact.max_severity || 'none'}</Badge>
                  <Badge tone={emailData.impact.password_exposed ? 'danger' : 'ok'}>
                    {emailData.impact.password_exposed ? 'passwords were exposed' : 'no password exposure flagged'}
                  </Badge>
                </div>
                {(emailData.impact.affected_accounts || []).length > 0 && (
                  <div style={{ marginBottom: 10 }}>
                    <div className="small" style={{ marginBottom: 6 }}><b>Vault accounts affected:</b></div>
                    {emailData.impact.affected_accounts.map((a: any, i: number) => (
                      <div key={i} className="list-item">
                        <ShieldAlert size={14} style={{ color: 'var(--danger)' }} />
                        <div className="grow">
                          <div className="title">{a.title || a.id}</div>
                          <div className="sub">{a.reason || 'matches the breached identity'}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {(emailData.impact.recommendations || []).length > 0 && (
                  <ul className="small muted" style={{ margin: '0 0 0 18px', lineHeight: 1.8 }}>
                    {emailData.impact.recommendations.map((r: string, i: number) => <li key={i}>{r}</li>)}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
