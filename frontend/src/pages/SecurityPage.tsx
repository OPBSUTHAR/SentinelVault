import { useEffect, useState } from 'react'
import { Bell, BellOff, Fish, ShieldCheck } from 'lucide-react'
import { SecurityApi, ToolsApi, errText } from '../api'
import { Badge, Card, Empty, Spinner, severityTone, timeAgo, useToast } from '../components/ui'

export default function SecurityPage() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [unread, setUnread] = useState(0)
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [events, setEvents] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  const [url, setUrl] = useState('')
  const [phish, setPhish] = useState<any>(null)
  const [phishBusy, setPhishBusy] = useState(false)
  const toast = useToast()

  const load = () => {
    setLoading(true)
    Promise.all([SecurityApi.alerts(100, unreadOnly), SecurityApi.events(60)])
      .then(([a, e]) => {
        setAlerts(a.alerts || [])
        setUnread(a.unread || 0)
        setEvents(e.events || [])
      })
      .catch((err) => toast(errText(err), 'error'))
      .finally(() => setLoading(false))
  }
  useEffect(load, [unreadOnly])

  const markRead = async (id: string) => {
    try {
      await SecurityApi.markRead(id)
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const checkPhish = async () => {
    if (!url) return
    setPhishBusy(true)
    try {
      const d = await ToolsApi.phishing(url)
      setPhish(d.result)
    } catch (e) {
      toast(errText(e), 'error')
    } finally {
      setPhishBusy(false)
    }
  }

  const verdictTone = (v: string) => (v === 'malicious' ? 'danger' : v === 'suspicious' ? 'warn' : v === 'likely_safe' ? 'info' : 'ok')

  return (
    <div className="grid" style={{ gap: 16 }}>
      <Card
        title={`Security alerts ${unread ? `(${unread} unread)` : ''}`}
        sub="Login behavior anomalies detected for your account (new devices, new networks, brute-force attempts, odd hours)"
        action={
          <button className="btn ghost sm" onClick={() => setUnreadOnly(!unreadOnly)}>
            {unreadOnly ? <BellOff size={13} /> : <Bell size={13} />} {unreadOnly ? 'Show all' : 'Unread only'}
          </button>
        }
      >
        {loading ? (
          <Spinner />
        ) : alerts.length === 0 ? (
          <Empty icon={<ShieldCheck size={28} />} text="No alerts — your sign-in behavior looks normal." />
        ) : (
          alerts.map((a) => (
            <div key={a.id} className={`alert-item ${a.severity}`}>
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <div className="title">{a.title} {!a.read && <Badge tone="info">new</Badge>}</div>
                <Badge tone={severityTone(a.severity)}>{a.severity}</Badge>
              </div>
              <div className="msg">{a.message}</div>
              <div className="row" style={{ justifyContent: 'space-between', marginTop: 6 }}>
                <span className="time">{timeAgo(a.created_at)} · {a.kind}</span>
                {!a.read && <button className="btn ghost sm" onClick={() => markRead(a.id)}>Mark read</button>}
              </div>
            </div>
          ))
        )}
      </Card>

      <div className="grid cols-2" style={{ alignItems: 'start' }}>
        <Card title="Phishing site detector" sub="Heuristic URL analysis: lookalike domains, suspicious TLDs, IP hosts, punycode, lure keywords">
          <div className="row">
            <input className="input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://secure-login.example.tk/verify" onKeyDown={(e) => e.key === 'Enter' && checkPhish()} />
            <button className="btn" onClick={checkPhish} disabled={phishBusy || !url}>{phishBusy ? 'Analyzing…' : 'Analyze'}</button>
          </div>
          {phish && !phishBusy && (
            <div style={{ marginTop: 14 }}>
              <div className="row" style={{ gap: 10, marginBottom: 10 }}>
                <Badge tone={verdictTone(phish.verdict)}>{phish.verdict.replace('_', ' ')}</Badge>
                <span className="muted small">risk score {phish.score}/100 · host {phish.host || '—'}</span>
              </div>
              {phish.findings?.length ? (
                (phish.findings || []).map((f: any, i: number) => (
                  <div key={i} className="list-item">
                    <Fish size={13} style={{ color: f.severity === 'high' ? 'var(--danger)' : f.severity === 'medium' ? 'var(--warn)' : 'var(--muted)' }} />
                    <div className="grow">
                      <div className="sub">{f.detail}</div>
                    </div>
                    <Badge tone={f.severity === 'high' ? 'danger' : f.severity === 'medium' ? 'warn' : 'info'}>{f.severity}</Badge>
                  </div>
                ))
              ) : (
                <div className="muted small">No suspicious signals found.</div>
              )}
            </div>
          )}
        </Card>

        <Card title="Account activity log" sub="Every sign-in attempt is fingerprinted (device, network, hour)">
          {loading ? (
            <Spinner />
          ) : (
            <table className="table">
              <thead><tr><th>Event</th><th>Severity</th><th>Network</th><th>When</th></tr></thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td className="small">{e.event_type.replace(/_/g, ' ')}</td>
                    <td><Badge tone={severityTone(e.severity)}>{e.severity}</Badge></td>
                    <td className="mono small">{e.detail?.subnet ? `${e.detail.subnet}.x.x` : e.ip || '—'}</td>
                    <td className="muted small">{timeAgo(e.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  )
}
