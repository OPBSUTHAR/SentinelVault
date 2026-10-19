import { useEffect, useMemo, useState } from 'react'
import { Eye, EyeOff, Plus, RefreshCw, Search, ShieldAlert, Star, Trash2, KeyRound, TimerReset } from 'lucide-react'
import { ToolsApi, VaultApi, errText } from '../api'
import UnlockGate from '../components/UnlockGate'
import { Badge, Card, CopyButton, Empty, Modal, Spinner, StrengthMeter, timeAgo, useToast } from '../components/ui'

const CATEGORIES = ['login', 'card', 'note', 'identity']
const EMPTY_FORM = { title: '', category: 'login', username: '', email: '', password: '', url: '', notes: '', totp_secret: '', tags: [] as string[], favorite: false }

function scoreTone(score: number) {
  if (score >= 80) return 'ok'
  if (score >= 60) return 'info'
  if (score >= 40) return 'warn'
  return 'danger'
}

export default function VaultPage() {
  return (
    <UnlockGate>
      <VaultInner />
    </UnlockGate>
  )
}

function VaultInner() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [modal, setModal] = useState<'create' | 'edit' | null>(null)
  const [form, setForm] = useState<any>({ ...EMPTY_FORM })
  const [editingId, setEditingId] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [totp, setTotp] = useState<Record<string, { code: string; seconds_left: number }>>({})
  const [busyId, setBusyId] = useState<string | null>(null)
  const [formStrength, setFormStrength] = useState<any>(null)
  const [rotated, setRotated] = useState<any[] | null>(null)
  const [qrUrl, setQrUrl] = useState<string | null>(null)
  const toast = useToast()

  const load = () => {
    setLoading(true)
    VaultApi.list(category || undefined)
      .then((d) => setItems(d.items || []))
      .catch((e) => toast(errText(e), 'error'))
      .finally(() => setLoading(false))
  }
  useEffect(load, [category])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return items.filter(
      (i) =>
        !q ||
        (i.title || '').toLowerCase().includes(q) ||
        (i.username || '').toLowerCase().includes(q) ||
        (i.url || '').toLowerCase().includes(q) ||
        (i.tags || []).join(',').toLowerCase().includes(q),
    )
  }, [items, search])

  // live strength for the create/edit form
  useEffect(() => {
    if (!modal) return
    const t = setTimeout(() => {
      ToolsApi.strength(form.password || '')
        .then((d) => setFormStrength(d.report))
        .catch(() => {})
    }, 250)
    return () => clearTimeout(t)
  }, [form.password, modal])

  const openCreate = () => {
    setForm({ ...EMPTY_FORM })
    setEditingId(null)
    setFormStrength(null)
    setQrUrl(null)
    setModal('create')
  }

  const openEdit = async (item: any) => {
    try {
      const d = await VaultApi.get(item.id)
      const it = d.item
      setForm({
        title: it.title || '', category: it.category || 'login', username: it.username || '', email: it.email || '',
        password: it.password || '', url: it.url || '', notes: it.notes || '', totp_secret: it.totp_secret || '',
        tags: it.tags || [], favorite: !!it.favorite,
      })
      setEditingId(item.id)
      setQrUrl(null)
      setModal('edit')
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const save = async () => {
    if (!form.title.trim()) return toast('Title is required', 'error')
    try {
      if (modal === 'create') {
        await VaultApi.create(form)
        toast('Item stored and encrypted', 'success')
      } else if (editingId) {
        await VaultApi.update(editingId, form)
        toast('Item updated', 'success')
      }
      setModal(null)
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const reveal = async (item: any) => {
    if (revealed[item.id]) {
      setRevealed((r) => {
        const n = { ...r }
        delete n[item.id]
        return n
      })
      return
    }
    try {
      const d = await VaultApi.get(item.id)
      setRevealed((r) => ({ ...r, [item.id]: d.item.password || '' }))
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const loadTotp = async (item: any) => {
    try {
      const d = await VaultApi.totp(item.id)
      setTotp((t) => ({ ...t, [item.id]: d }))
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  // live countdown for totp codes
  useEffect(() => {
    const t = setInterval(() => {
      setTotp((prev) => {
        let changed = false
        const next: any = {}
        for (const [k, v] of Object.entries(prev)) {
          if (v.seconds_left > 1) {
            next[k] = { ...v, seconds_left: v.seconds_left - 1 }
            changed = true
          } else {
            next[k] = { ...v, seconds_left: 30 }
            const item = items.find((i) => i.id === k)
            if (item) VaultApi.totp(k).then((d) => setTotp((t2) => ({ ...t2, [k]: d }))).catch(() => {})
            changed = true
          }
        }
        return changed ? next : prev
      })
    }, 1000)
    return () => clearInterval(t)
  }, [items])

  const rotate = async (item: any) => {
    setBusyId(item.id)
    try {
      const res = await VaultApi.rotate(item.id, 'strong')
      setRotated(res.rotated)
      load()
    } catch (e) {
      toast(errText(e), 'error')
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (item: any) => {
    if (!window.confirm(`Delete "${item.title}" from the vault?`)) return
    try {
      await VaultApi.remove(item.id)
      toast('Item deleted', 'success')
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const generateInto = async () => {
    try {
      const d = await ToolsApi.generate({ policy: 'strong' })
      setForm((f: any) => ({ ...f, password: d.password }))
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const generateTotp = async () => {
    try {
      const d = await ToolsApi.totpGenerate()
      setForm((f: any) => ({ ...f, totp_secret: d.secret }))
      toast('2FA secret generated — scan the QR in your authenticator app', 'success')
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const showQr = async () => {
    try {
      const res = await fetch('/api/tools/totp/qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: form.totp_secret, account: form.username || form.title }),
      })
      const blob = await res.blob()
      setQrUrl(URL.createObjectURL(blob))
    } catch {
      toast('Could not render QR code', 'error')
    }
  }

  const seed = async () => {
    try {
      const res = await VaultApi.seedDemo()
      toast(res.created ? `Added ${res.created} demo accounts` : 'Demo data already present', 'success')
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  if (loading) return <Spinner />

  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="row wrap" style={{ justifyContent: 'space-between' }}>
        <div className="row wrap" style={{ gap: 10 }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: 11, color: 'var(--muted)' }} />
            <input className="input" style={{ paddingLeft: 30, width: 260 }} placeholder="Search vault…" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <select className="input" style={{ width: 140 }} value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All categories</option>
            {CATEGORIES.map((cat) => <option key={cat} value={cat}>{cat}</option>)}
          </select>
          <span className="muted small">{filtered.length} item(s)</span>
        </div>
        <div className="row">
          {items.length === 0 && <button className="btn ghost" onClick={seed}>Load demo vault</button>}
          <button className="btn" onClick={openCreate}><Plus size={15} /> Add item</button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <Empty icon={<KeyRound size={30} />} text={items.length ? 'No items match your search.' : 'Your vault is empty — add your first account.'} />
      ) : (
        <div className="grid cols-2">
          {filtered.map((item) => (
            <Card key={item.id}>
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ minWidth: 0 }}>
                  <div className="row" style={{ gap: 6 }}>
                    <b style={{ fontSize: 15 }}>{item.title}</b>
                    {item.favorite && <Star size={13} style={{ color: 'var(--warn)', fill: 'var(--warn)' }} />}
                  </div>
                  <div className="muted small" style={{ marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 320 }}>
                    {[item.username, item.url].filter(Boolean).join(' · ') || item.category}
                  </div>
                </div>
                <div className="row" style={{ gap: 6 }}>
                  <Badge tone={scoreTone(item.strength_score || 0)}>{item.strength_score ?? 0}/100</Badge>
                  {item.breached_count > 0 && <Badge tone="danger"><ShieldAlert size={11} /> breached</Badge>}
                </div>
              </div>

              <div style={{ margin: '12px 0 6px' }}>
                <StrengthMeter score={item.strength_score || 0} />
              </div>

              {revealed[item.id] !== undefined && (
                <div className="row" style={{ gap: 8, marginBottom: 8 }}>
                  <code className="mono" style={{ background: 'rgba(7,11,22,.8)', padding: '6px 10px', borderRadius: 8, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {revealed[item.id] || '(no password saved)'}
                  </code>
                  {revealed[item.id] && <CopyButton text={revealed[item.id]} />}
                </div>
              )}

              {totp[item.id] && (
                <div className="row" style={{ gap: 10, marginBottom: 8 }}>
                  <TimerReset size={14} style={{ color: 'var(--accent)' }} />
                  <b className="mono" style={{ fontSize: 18, letterSpacing: 2 }}>{totp[item.id].code}</b>
                  <div className="meter" style={{ width: 60 }}><div style={{ width: `${(totp[item.id].seconds_left / 30) * 100}%`, background: 'var(--accent)' }} /></div>
                  <span className="muted small">{totp[item.id].seconds_left}s</span>
                </div>
              )}

              <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
                <button className="btn ghost sm" onClick={() => reveal(item)}>
                  {revealed[item.id] !== undefined ? <EyeOff size={13} /> : <Eye size={13} />} {revealed[item.id] !== undefined ? 'Hide' : 'Reveal'}
                </button>
                {item.totp_secret ? (
                  <button className="btn ghost sm" onClick={() => loadTotp(item)}><TimerReset size={13} /> 2FA code</button>
                ) : null}
                <button className="btn ghost sm" onClick={() => openEdit(item)}>Edit</button>
                <button className="btn ghost sm" disabled={busyId === item.id} onClick={() => rotate(item)}>
                  <RefreshCw size={13} /> {busyId === item.id ? 'Rotating…' : 'Rotate'}
                </button>
                <button className="btn ghost sm" onClick={() => remove(item)}><Trash2 size={13} /></button>
                <span className="muted small" style={{ marginLeft: 'auto' }}>updated {timeAgo(item.updated_at)}</span>
              </div>
            </Card>
          ))}
        </div>
      )}

      {modal && (
        <Modal title={modal === 'create' ? 'Add vault item' : 'Edit vault item'} onClose={() => setModal(null)} width={640}>
          <div className="grid cols-2" style={{ gap: 0 }}>
            <div className="field">
              <label>Title *</label>
              <input className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="GitHub" />
            </div>
            <div className="field">
              <label>Category</label>
              <select className="input" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>
                {CATEGORIES.map((cat) => <option key={cat} value={cat}>{cat}</option>)}
              </select>
            </div>
            <div className="field">
              <label>Username</label>
              <input className="input" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            </div>
            <div className="field">
              <label>Email</label>
              <input className="input" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </div>
          </div>
          <div className="field">
            <label>Password {formStrength && <span className="muted">— {formStrength.score}/100 {formStrength.rating}</span>}</label>
            <div className="row">
              <input className="input mono" type="text" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="Leave blank to keep current (when editing)" />
              <button className="btn ghost sm" onClick={generateInto} type="button">Generate</button>
            </div>
            {formStrength && <div style={{ marginTop: 6 }}><StrengthMeter score={formStrength.score} /></div>}
          </div>
          <div className="grid cols-2" style={{ gap: 0 }}>
            <div className="field">
              <label>Website URL</label>
              <input className="input" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://example.com" />
            </div>
            <div className="field">
              <label>Tags (comma separated)</label>
              <input className="input" value={(form.tags || []).join(', ')} onChange={(e) => setForm({ ...form, tags: e.target.value.split(',').map((t: string) => t.trim()).filter(Boolean) })} placeholder="work, bank" />
            </div>
          </div>
          <div className="field">
            <label>2FA secret (TOTP) — optional</label>
            <div className="row">
              <input className="input mono" value={form.totp_secret} onChange={(e) => setForm({ ...form, totp_secret: e.target.value })} placeholder="Base32 secret" />
              <button className="btn ghost sm" type="button" onClick={generateTotp}>Generate</button>
              {form.totp_secret && <button className="btn ghost sm" type="button" onClick={showQr}>QR</button>}
            </div>
            {qrUrl && <img src={qrUrl} alt="TOTP QR" style={{ width: 150, marginTop: 10, borderRadius: 8, background: '#fff', padding: 6 }} />}
          </div>
          <div className="field">
            <label>Notes</label>
            <textarea className="input" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </div>
          <label className="row" style={{ gap: 8, marginBottom: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={form.favorite} onChange={(e) => setForm({ ...form, favorite: e.target.checked })} />
            <span className="small">Mark as favorite</span>
          </label>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <button className="btn ghost" onClick={() => setModal(null)}>Cancel</button>
            <button className="btn" onClick={save}>{modal === 'create' ? 'Save item' : 'Save changes'}</button>
          </div>
        </Modal>
      )}

      {rotated && (
        <Modal title="Password rotated" onClose={() => setRotated(null)}>
          <div className="muted small" style={{ marginBottom: 12 }}>The vault now stores a fresh password. Update it on the website too.</div>
          {rotated.map((r: any) => (
            <div key={r.id} className="list-item">
              <div className="grow">
                <div className="title">{r.title}</div>
                <div className="sub mono">{r.new_password}</div>
              </div>
              <CopyButton text={r.new_password} />
            </div>
          ))}
          <div className="row" style={{ justifyContent: 'flex-end', marginTop: 14 }}>
            <button className="btn" onClick={() => setRotated(null)}>Done</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
