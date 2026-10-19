import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { BookOpen, KeyRound, Lock, LogOut, RefreshCw } from 'lucide-react'
import { AuthApi, ToolsApi, errText } from '../api'
import { useAuth } from '../store'
import { Badge, Card, CopyButton, Modal, StrengthMeter, useToast } from '../components/ui'

export default function SettingsPage() {
  const { user, unlocked, token, setUnlocked, logout } = useAuth()
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState<any>(null)
  const [newRecovery, setNewRecovery] = useState<string | null>(null)
  const [savedKey, setSavedKey] = useState(false)
  const toast = useToast()
  const navigate = useNavigate()

  const analyze = async (v: string) => {
    setNewPw(v)
    setConfirmPw((c) => c)
    if (!v) { setReport(null); return }
    try {
      const d = await ToolsApi.strength(v)
      setReport(d.report)
    } catch { /* ignore */ }
  }

  const changePw = async () => {
    if (newPw !== confirmPw) return toast('Passwords do not match', 'error')
    setBusy(true)
    try {
      const res = await AuthApi.changePassword('', newPw)
      setNewRecovery(res.recovery_key)
      setSavedKey(false)
      setNewPw('')
      setConfirmPw('')
      setReport(null)
      toast('Master password changed — vault re-encrypted', 'success')
    } catch (e) {
      toast(errText(e), 'error')
    } finally {
      setBusy(false)
    }
  }

  const lockVault = async () => {
    try {
      await AuthApi.lock()
      setUnlocked(false)
      toast('Vault locked', 'success')
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  const signOut = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid cols-2" style={{ alignItems: 'start' }}>
        <Card title="Account">
          <div className="kv"><span className="muted small">Email</span><b>{user?.email}</b></div>
          <div className="kv"><span className="muted small">Display name</span><b>{user?.display_name || '—'}</b></div>
          <div className="kv"><span className="muted small">Member since</span><b className="small">{user?.created_at ? new Date(user.created_at).toLocaleDateString() : '—'}</b></div>
          <div className="kv"><span className="muted small">Recovery key</span>{user?.has_recovery ? <Badge tone="ok">configured</Badge> : <Badge tone="warn">missing</Badge>}</div>
          <div className="kv"><span className="muted small">Vault state</span>{unlocked ? <Badge tone="ok">unlocked</Badge> : <Badge tone="warn">locked</Badge>}</div>

          <div className="row" style={{ marginTop: 16, gap: 8 }}>
            {unlocked && <button className="btn ghost" onClick={lockVault}><Lock size={14} /> Lock vault now</button>}
            <button className="btn danger" onClick={signOut}><LogOut size={14} /> Sign out</button>
          </div>
          <div className="muted small" style={{ marginTop: 14 }}>
            <BookOpen size={12} /> API reference is available at <a href="/api/docs" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>/api/docs</a>.
            Zero-knowledge design: the server only ever stores ciphertext, salts and verifiers — never your master password.
          </div>
        </Card>

        <Card title="Change master password" sub="Re-derives your key and re-encrypts every vault item; a new recovery key is issued">
          {!unlocked ? (
            <div className="muted small">Unlock the vault to change the master password.</div>
          ) : (
            <>
              <div className="field">
                <label>New master password</label>
                <input className="input" type="password" value={newPw} onChange={(e) => analyze(e.target.value)} placeholder="At least 10 characters" />
                {report && (
                  <div style={{ marginTop: 8 }}>
                    <div className="row" style={{ justifyContent: 'space-between', marginBottom: 5 }}>
                      <span className="muted small">Strength</span>
                      <Badge tone={report.score >= 80 ? 'ok' : report.score >= 60 ? 'info' : report.score >= 40 ? 'warn' : 'danger'}>{report.score}/100 · {report.rating}</Badge>
                    </div>
                    <StrengthMeter score={report.score} />
                  </div>
                )}
              </div>
              <div className="field">
                <label>Confirm new password</label>
                <input className="input" type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} />
              </div>
              <button className="btn" onClick={changePw} disabled={busy || !newPw || newPw !== confirmPw}>
                <RefreshCw size={14} /> {busy ? 'Re-encrypting vault…' : 'Change & re-encrypt'}
              </button>
              <div className="muted small" style={{ marginTop: 10 }}>
                <KeyRound size={12} /> After changing, all items are re-encrypted with a subkey of the new master key. Existing share links keep working (their keys are independent).
              </div>
            </>
          )}
        </Card>
      </div>

      {newRecovery && (
        <Modal title="New recovery key" onClose={() => (savedKey ? setNewRecovery(null) : toast('Please confirm you saved the key first', 'error'))} width={620}>
          <div className="muted small" style={{ marginBottom: 10 }}>
            Your master password changed, so your old recovery key no longer works. Save this new one — it is displayed only once.
          </div>
          <div className="recovery-key">{newRecovery}</div>
          <div className="row" style={{ marginTop: 12, justifyContent: 'space-between' }}>
            <CopyButton text={newRecovery} label="Copy recovery key" />
            <label className="row small" style={{ gap: 8, cursor: 'pointer' }}>
              <input type="checkbox" checked={savedKey} onChange={(e) => setSavedKey(e.target.checked)} /> I saved this recovery key
            </label>
          </div>
          <div className="row" style={{ justifyContent: 'flex-end', marginTop: 16 }}>
            <button className="btn" disabled={!savedKey} onClick={() => setNewRecovery(null)}>Done</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
