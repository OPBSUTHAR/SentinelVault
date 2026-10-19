import { useEffect, useState } from 'react'
import { LifeBuoy, Mail, Plus, Trash2, UserCheck } from 'lucide-react'
import { EmergencyApi, errText } from '../api'
import UnlockGate from '../components/UnlockGate'
import { Badge, Card, CopyButton, Empty, Modal, Spinner, timeAgo, useToast } from '../components/ui'

export default function EmergencyPage() {
  return (
    <UnlockGate>
      <EmergencyInner />
    </UnlockGate>
  )
}

function EmergencyInner() {
  const [contacts, setContacts] = useState<any[]>([])
  const [requests, setRequests] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [contactForm, setContactForm] = useState({ name: '', email: '', phone: '', relationship: '' })
  const [testEmail, setTestEmail] = useState('')
  const [testResult, setTestResult] = useState<any>(null)
  const [bundle, setBundle] = useState<any[] | null>(null)
  const toast = useToast()

  const load = () => {
    setLoading(true)
    Promise.all([EmergencyApi.contacts(), EmergencyApi.requests()])
      .then(([c, r]) => {
        setContacts(c.contacts || [])
        setRequests(r.requests || [])
      })
      .catch((e) => toast(errText(e), 'error'))
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  const addContact = async () => {
    if (!contactForm.name || !contactForm.email) return toast('Name and email are required', 'error')
    try {
      await EmergencyApi.addContact(contactForm)
      toast('Emergency contact added', 'success')
      setContactForm({ name: '', email: '', phone: '', relationship: '' })
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const removeContact = async (id: string) => {
    try {
      await EmergencyApi.removeContact(id)
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const decide = async (id: string, approve: boolean) => {
    try {
      const res = await EmergencyApi.decide(id, approve)
      if (approve && res.bundle) {
        setBundle(res.bundle)
        toast('Access approved — emergency bundle released', 'success')
      } else {
        toast(approve ? 'Access approved' : 'Access denied', 'success')
      }
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const simulate = async () => {
    if (!testEmail) return
    try {
      const res = await EmergencyApi.request({ email: testEmail, message: 'I need access to the vault.' })
      setTestResult(res)
      load()
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  if (loading) return <Spinner />

  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid cols-2" style={{ alignItems: 'start' }}>
        <Card title="Emergency contacts" sub="Trusted people who can request vault access if something happens to you">
          <div className="grid cols-2" style={{ gap: 0 }}>
            <div className="field"><label>Name</label><input className="input" value={contactForm.name} onChange={(e) => setContactForm({ ...contactForm, name: e.target.value })} /></div>
            <div className="field"><label>Email</label><input className="input" value={contactForm.email} onChange={(e) => setContactForm({ ...contactForm, email: e.target.value })} /></div>
            <div className="field"><label>Phone (optional)</label><input className="input" value={contactForm.phone} onChange={(e) => setContactForm({ ...contactForm, phone: e.target.value })} /></div>
            <div className="field"><label>Relationship</label><input className="input" value={contactForm.relationship} onChange={(e) => setContactForm({ ...contactForm, relationship: e.target.value })} placeholder="spouse, lawyer…" /></div>
          </div>
          <button className="btn" onClick={addContact}><Plus size={14} /> Add contact</button>

          <div style={{ marginTop: 14 }}>
            {contacts.length === 0 ? (
              <Empty text="No emergency contacts yet." />
            ) : (
              contacts.map((c) => (
                <div key={c.id} className="list-item">
                  <Mail size={14} style={{ color: 'var(--accent)' }} />
                  <div className="grow">
                    <div className="title">{c.name} {c.relationship && <span className="muted small">· {c.relationship}</span>}</div>
                    <div className="sub">{c.email}{c.phone ? ` · ${c.phone}` : ''}</div>
                  </div>
                  <button className="btn ghost sm" onClick={() => removeContact(c.id)}><Trash2 size={12} /></button>
                </div>
              ))
            )}
          </div>
        </Card>

        <Card title="How emergency access works">
          <ul className="small muted" style={{ margin: '0 0 12px 18px', lineHeight: 1.9 }}>
            <li>Your contacts can open <code className="mono">/emergency-request</code> anytime and ask for access using their registered email.</li>
            <li>You (the owner) get the request here — approve to release the bundle, deny to block it.</li>
            <li>Approving requires your vault to be <b>unlocked</b>, so nothing ever leaves without your master password.</li>
            <li>The released bundle contains logins/notes but <b>not</b> your master password or recovery key.</li>
          </ul>
          <div className="field">
            <label>Test the flow (creates a request as your contact)</label>
            <div className="row">
              <input className="input" value={testEmail} onChange={(e) => setTestEmail(e.target.value)} placeholder={contacts[0]?.email || 'contact@example.com'} />
              <button className="btn ghost" onClick={simulate}><UserCheck size={14} /> Request access</button>
            </div>
          </div>
          {testResult && (
            <div className="alert-item" style={{ borderColor: 'rgba(34,211,238,.4)' }}>
              <div className="row" style={{ gap: 8 }}><LifeBuoy size={15} style={{ color: 'var(--accent)' }} /><b>Request created — the contact's tracking link</b></div>
              <div className="row" style={{ marginTop: 8 }}>
                <code className="mono small" style={{ flex: 1, background: 'rgba(7,11,22,.85)', padding: '8px 10px', borderRadius: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {window.location.origin}/emergency/status/{testResult.token}
                </code>
                <CopyButton text={`${window.location.origin}/emergency/status/${testResult.token}`} label="Copy link" />
              </div>
            </div>
          )}
        </Card>
      </div>

      <Card title="Access requests" sub="Pending and past emergency requests from your contacts">
        {requests.length === 0 ? (
          <Empty text="No emergency requests yet." />
        ) : (
          <table className="table">
            <thead><tr><th>Contact</th><th>Status</th><th>Requested</th><th>Decided</th><th></th></tr></thead>
            <tbody>
              {requests.map((r) => (
                <tr key={r.id}>
                  <td>{r.contact_name || r.contact_email || '—'}<div className="muted small">{r.contact_email}</div></td>
                  <td><Badge tone={r.status === 'approved' ? 'ok' : r.status === 'denied' ? 'danger' : 'warn'}>{r.status}</Badge></td>
                  <td className="muted small">{timeAgo(r.requested_at)}</td>
                  <td className="muted small">{r.decided_at ? timeAgo(r.decided_at) : '—'}</td>
                  <td style={{ textAlign: 'right' }}>
                    {r.status === 'pending' && (
                      <div className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
                        <button className="btn sm" onClick={() => decide(r.id, true)}>Approve</button>
                        <button className="btn ghost sm" onClick={() => decide(r.id, false)}>Deny</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {bundle && (
        <Modal title="Emergency bundle released" onClose={() => setBundle(null)} width={680}>
          <div className="muted small" style={{ marginBottom: 12 }}>
            This snapshot is encrypted for the contact's token. It contains {bundle.length} entries — the contact can view it at their tracking link.
          </div>
          {bundle.map((b: any, i: number) => (
            <div key={i} className="list-item">
              <div className="grow">
                <div className="title">{b.title} <span className="muted small">· {b.category}</span></div>
                <div className="sub">{b.username || b.email || '—'}</div>
              </div>
              {b.password && <CopyButton text={b.password} label="Copy pw" />}
            </div>
          ))}
          <div className="row" style={{ justifyContent: 'flex-end', marginTop: 14 }}>
            <button className="btn" onClick={() => setBundle(null)}>Done</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
