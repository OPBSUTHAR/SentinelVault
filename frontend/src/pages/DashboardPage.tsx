import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, RefreshCw, ShieldCheck, Sparkles, Wand2, KeyRound, Radar } from 'lucide-react'
import { DashboardApi, VaultApi, errText } from '../api'
import UnlockGate from '../components/UnlockGate'
import { Badge, Card, CopyButton, Empty, Modal, ScoreRing, Spinner, severityTone, timeAgo, useToast } from '../components/ui'

export default function DashboardPage() {
  return (
    <UnlockGate>
      <DashboardInner />
    </UnlockGate>
  )
}

function DashboardInner() {
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [newPasswords, setNewPasswords] = useState<any[] | null>(null)
  const [seeding, setSeeding] = useState(false)
  const toast = useToast()

  const load = () => {
    setLoading(true)
    DashboardApi.load()
      .then(setData)
      .catch((e) => toast(errText(e), 'error'))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const rotateAll = async () => {
    const ids = (data?.change_now || []).map((c: any) => c.id)
    if (!ids.length) return
    try {
      const res = await VaultApi.rotateBulk(ids, 'strong')
      setNewPasswords(res.rotated)
      toast(`Rotated ${res.count} password(s)`, 'success')
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const seed = async () => {
    setSeeding(true)
    try {
      const res = await VaultApi.seedDemo()
      toast(res.created ? `Added ${res.created} demo accounts` : 'Demo data already present', 'success')
      load()
    } catch (e) {
      toast(errText(e), 'error')
    } finally {
      setSeeding(false)
    }
  }

  if (loading) return <Spinner />
  if (!data) return <Empty text="Could not load the dashboard." />

  const health = data.health || {}
  const empty = (data.items || 0) === 0

  return (
    <div className="grid" style={{ gap: 18 }}>
      <div className="hero">
        <Card>
          <div className="row" style={{ gap: 22, alignItems: 'center' }}>
            <ScoreRing score={health.overall_score || 0} grade={health.grade} />
            <div>
              <div style={{ fontSize: 17, fontWeight: 700, marginBottom: 4 }}>Vault health</div>
              <div className="muted small" style={{ maxWidth: 330, lineHeight: 1.55 }}>
                {(health.top_actions || []).map((a: string, i: number) => (
                  <div key={i} style={{ marginBottom: 3 }}>• {a}</div>
                ))}
              </div>
            </div>
          </div>
        </Card>
        <div className="grid cols-2" style={{ flex: 1, minWidth: 320, gap: 12 }}>
          <Card><div className="stat"><div className="label">Accounts stored</div><div className="value">{data.items}</div><div className="hint">encrypted with AES-256-GCM</div></div></Card>
          <Card><div className="stat"><div className="label">Weak passwords</div><div className="value" style={{ color: health.weak_count ? 'var(--warn)' : 'var(--ok)' }}>{health.weak_count ?? 0}</div><div className="hint">below 50/100 strength</div></div></Card>
          <Card><div className="stat"><div className="label">Reused passwords</div><div className="value" style={{ color: health.reused_count ? 'var(--warn)' : 'var(--ok)' }}>{health.reused_count ?? 0}</div><div className="hint">same secret on multiple sites</div></div></Card>
          <Card><div className="stat"><div className="label">Breached passwords</div><div className="value" style={{ color: health.breached_count ? 'var(--danger)' : 'var(--ok)' }}>{health.breached_count ?? 0}</div><div className="hint">found in HIBP corpus</div></div></Card>
        </div>
      </div>

      {empty && (
        <Card>
          <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontWeight: 600, marginBottom: 4 }}><Sparkles size={14} /> Your vault is empty</div>
              <div className="muted small">Load a realistic demo dataset (14 accounts with intentional weak/reused/breached passwords) to see the AI health scoring and breach detection in action.</div>
            </div>
            <button className="btn" onClick={seed} disabled={seeding}>{seeding ? 'Loading…' : 'Load demo vault'}</button>
          </div>
        </Card>
      )}

      {(data.change_now || []).length > 0 && (
        <Card
          title="Change these now"
          sub="AI flagged these accounts — breached, reused, or weak secrets"
        >
          {(data.change_now || []).map((c: any) => (
            <div key={c.id} className="list-item">
              <AlertTriangle size={16} style={{ color: 'var(--danger)', flexShrink: 0 }} />
              <div className="grow">
                <div className="title">{c.title}</div>
                <div className="sub">{(c.issues || []).join(' · ')}</div>
              </div>
              <Link className="btn ghost sm" to="/vault">Open</Link>
            </div>
          ))}
          <div className="row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
            <button className="btn violet" onClick={rotateAll}>
              <RefreshCw size={14} /> Auto-rotate all {(data.change_now || []).length} passwords
            </button>
          </div>
        </Card>
      )}

      <div className="grid cols-2">
        <Card title="Recent security alerts">
          {(data.recent_alerts || []).length === 0 ? (
            <Empty icon={<ShieldCheck size={28} />} text="No alerts — sign-in behavior looks normal." />
          ) : (
            (data.recent_alerts || []).map((a: any) => (
              <div key={a.id} className={`alert-item ${a.severity}`}>
                <div className="row" style={{ justifyContent: 'space-between' }}>
                  <div className="title">{a.title}</div>
                  <Badge tone={severityTone(a.severity)}>{a.severity}</Badge>
                </div>
                <div className="msg">{a.message}</div>
                <div className="time">{timeAgo(a.created_at)}</div>
              </div>
            ))
          )}
        </Card>

        <Card title="Recent account activity">
          {(data.recent_events || []).length === 0 ? (
            <Empty text="No sign-in activity yet." />
          ) : (
            <table className="table">
              <thead><tr><th>Event</th><th>Severity</th><th>When</th></tr></thead>
              <tbody>
                {(data.recent_events || []).map((e: any) => (
                  <tr key={e.id}>
                    <td>{e.event_type === 'login_success' ? 'Sign-in success' : 'Failed sign-in'}</td>
                    <td><Badge tone={severityTone(e.severity)}>{e.severity}</Badge></td>
                    <td className="muted small">{timeAgo(e.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="grid cols-3">
        <Link to="/generator" className="card" style={{ color: 'inherit' }}>
          <div className="row"><Wand2 size={16} style={{ color: 'var(--accent)' }} /> <b>Generate a strong password</b></div>
          <div className="muted small" style={{ marginTop: 6 }}>Live strength scoring, policies, passphrases.</div>
        </Link>
        <Link to="/vault" className="card" style={{ color: 'inherit' }}>
          <div className="row"><KeyRound size={16} style={{ color: 'var(--accent)' }} /> <b>Manage your vault</b></div>
          <div className="muted small" style={{ marginTop: 6 }}>Reveal, copy, rotate, 2FA codes, notes.</div>
        </Link>
        <Link to="/breach" className="card" style={{ color: 'inherit' }}>
          <div className="row"><Radar size={16} style={{ color: 'var(--accent)' }} /> <b>Run a breach check</b></div>
          <div className="muted small" style={{ marginTop: 6 }}>k-anonymity password checks + account lookup.</div>
        </Link>
      </div>

      {newPasswords && (
        <Modal title="Auto-rotation complete" onClose={() => setNewPasswords(null)} width={620}>
          <div className="muted small" style={{ marginBottom: 12 }}>
            These accounts now use fresh 16-character machine-generated passwords. Update them on the websites too.
          </div>
          {newPasswords.map((r: any) => (
            <div key={r.id} className="list-item">
              <div className="grow">
                <div className="title">{r.title}</div>
                <div className="sub mono">{r.new_password}</div>
              </div>
              <CopyButton text={r.new_password} />
            </div>
          ))}
          <div className="row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
            <button className="btn" onClick={() => setNewPasswords(null)}>Done</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
