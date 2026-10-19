import { useEffect, useState } from 'react'
import { Link2, Share2, Trash2 } from 'lucide-react'
import { SharesApi, VaultApi, errText } from '../api'
import UnlockGate from '../components/UnlockGate'
import { Badge, Card, CopyButton, Empty, Spinner, timeAgo, useToast } from '../components/ui'

export default function SharingPage() {
  return (
    <UnlockGate>
      <SharingInner />
    </UnlockGate>
  )
}

function SharingInner() {
  const [items, setItems] = useState<any[]>([])
  const [shares, setShares] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState({ item_id: '', label: '', expires_in_hours: 72, max_views: 5, include_password: true })
  const [created, setCreated] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  const load = () => {
    setLoading(true)
    Promise.all([VaultApi.list(), SharesApi.list()])
      .then(([v, s]) => {
        const items = v.items || []
        const byId: Record<string, any> = {}
        items.forEach((it: any) => (byId[it.id] = it))
        setItems(items)
        setShares((s.shares || []).map((sh: any) => ({ ...sh, item_title: byId[sh.item_id]?.title || sh.item_id })))
        if (!form.item_id && items.length) setForm((f) => ({ ...f, item_id: items[0].id }))
      })
      .catch((e) => toast(errText(e), 'error'))
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  const create = async () => {
    if (!form.item_id) return toast('Pick an item to share', 'error')
    setBusy(true)
    try {
      const d = await SharesApi.create(form)
      setCreated(d.share)
      load()
    } catch (e) {
      toast(errText(e), 'error')
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (id: string) => {
    try {
      await SharesApi.revoke(id)
      toast('Share link revoked', 'success')
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const status = (s: any) => (s.revoked ? 'revoked' : s.expired ? 'expired' : 'active')
  const statusTone = (s: string) => (s === 'active' ? 'ok' : s === 'expired' ? 'warn' : 'danger')

  if (loading) return <Spinner />

  return (
    <div className="grid" style={{ gap: 16 }}>
      <Card title="Share a password securely" sub="End-to-end encrypted link: the secret is sealed with a key derived from the token — the server cannot read it later">
        {items.length === 0 ? (
          <Empty text="Add items to your vault first." />
        ) : (
          <>
            <div className="grid cols-2" style={{ gap: 0 }}>
              <div className="field">
                <label>Vault item</label>
                <select className="input" value={form.item_id} onChange={(e) => setForm({ ...form, item_id: e.target.value })}>
                  {items.map((i) => <option key={i.id} value={i.id}>{i.title} ({i.username || i.category})</option>)}
                </select>
              </div>
              <div className="field">
                <label>Label (optional)</label>
                <input className="input" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="For Rahul — Netflix" />
              </div>
              <div className="field">
                <label>Expires in</label>
                <select className="input" value={form.expires_in_hours} onChange={(e) => setForm({ ...form, expires_in_hours: +e.target.value })}>
                  <option value={1}>1 hour</option>
                  <option value={24}>24 hours</option>
                  <option value={72}>3 days</option>
                  <option value={168}>7 days</option>
                </select>
              </div>
              <div className="field">
                <label>Max views</label>
                <input className="input" type="number" min={1} max={50} value={form.max_views} onChange={(e) => setForm({ ...form, max_views: +e.target.value })} />
              </div>
            </div>
            <label className="row small" style={{ gap: 8, marginBottom: 12, cursor: 'pointer' }}>
              <input type="checkbox" checked={form.include_password} onChange={(e) => setForm({ ...form, include_password: e.target.checked })} />
              Include the password in the shared snapshot (uncheck to share username/notes only)
            </label>
            <button className="btn" onClick={create} disabled={busy}><Share2 size={15} /> {busy ? 'Creating…' : 'Create secure link'}</button>
          </>
        )}

        {created && (
          <div className="alert-item" style={{ borderColor: 'rgba(34,211,238,.4)', marginTop: 16 }}>
            <div className="row" style={{ gap: 8 }}>
              <Link2 size={16} style={{ color: 'var(--accent)' }} />
              <b>Share link created — copy it now, it is shown only once</b>
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <code className="mono small" style={{ flex: 1, background: 'rgba(7,11,22,.85)', padding: '10px 12px', borderRadius: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {created.url}
              </code>
              <CopyButton text={created.url} label="Copy link" />
            </div>
            <div className="time" style={{ marginTop: 8 }}>expires {new Date(created.expires_at).toLocaleString()} · max {created.max_views} view(s)</div>
          </div>
        )}
      </Card>

      <Card title="Active & past shares">
        {shares.length === 0 ? (
          <Empty text="No shares created yet." />
        ) : (
          <table className="table">
            <thead><tr><th>Label</th><th>Item</th><th>Views</th><th>Expires</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {shares.map((s) => {
                const st = status(s)
                return (
                  <tr key={s.id}>
                    <td>{s.label || '—'}</td>
                    <td className="small">{s.item_title || s.item_id}</td>
                    <td className="mono small">{s.views}/{s.max_views}</td>
                    <td className="muted small">{s.expires_at ? new Date(s.expires_at).toLocaleDateString() : '—'}</td>
                    <td><Badge tone={statusTone(st)}>{st}</Badge></td>
                    <td style={{ textAlign: 'right' }}>
                      {st === 'active' && (
                        <button className="btn ghost sm" onClick={() => revoke(s.id)}><Trash2 size={12} /> Revoke</button>
                      )}
                      <span className="muted small" style={{ marginLeft: 8 }}>{timeAgo(s.created_at)}</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
