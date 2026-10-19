import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, KeyRound, AlertTriangle } from 'lucide-react'
import { AuthApi, errText, setMasterKey, SyncApi } from '../api'
import { useAuth } from '../store'
import { Card, CopyButton, useToast } from '../components/ui'

type Mode = 'login' | 'register' | 'recovery'

export default function LoginPage() {
  const [mode, setMode] = useState<Mode>('login')
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [recoveryKey, setRecoveryKey] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [issuedKey, setIssuedKey] = useState('')
  const [savedKey, setSavedKey] = useState(false)
  const { setAuth } = useAuth()
  const navigate = useNavigate()
  const toast = useToast()

  const finish = (data: any, key?: string) => {
    setAuth(data.token, data.user || null, true)
    if (data.master_key) setMasterKey(data.master_key)
    SyncApi.refreshBackup()
    if (key) {
      setIssuedKey(key)
    } else {
      toast('Welcome back to SentinelVault', 'success')
      navigate('/')
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      if (mode === 'login') {
        // If this serverless instance hasn't seen the account yet, seed it
        // from the browser's encrypted backup before signing in.
        await SyncApi.ensureAccount(email)
        const data = await AuthApi.login({ email, password })
        finish(data)
      } else if (mode === 'register') {
        const data = await AuthApi.register({ email, display_name: name, password })
        finish(data, data.recovery_key)
      } else {
        await SyncApi.ensureAccount(email)
        const data = await AuthApi.recovery(email, recoveryKey.trim(), newPassword)
        finish(data, data.recovery_key)
      }
    } catch (error: any) {
      setErr(errText(error))
    } finally {
      setBusy(false)
    }
  }

  if (issuedKey) {
    return (
      <div className="auth-wrap">
        <Card style={{ maxWidth: 520 }}>
          <div className="auth-logo">
            <img src="/shield.svg" alt="" />
            <div>
              <div style={{ fontWeight: 700, fontSize: 17 }}>Save your recovery key</div>
              <div className="muted small">This is the only way back into your vault if you forget the master password.</div>
            </div>
          </div>
          <div className="recovery-key">{issuedKey}</div>
          <div className="row" style={{ marginTop: 12 }}>
            <CopyButton text={issuedKey} label="Copy recovery key" />
          </div>
          <label className="row" style={{ margin: '16px 0', gap: 8, cursor: 'pointer' }}>
            <input type="checkbox" checked={savedKey} onChange={(e) => setSavedKey(e.target.checked)} />
            <span className="small">I have saved my recovery key somewhere safe and offline</span>
          </label>
          <button
            className="btn wide"
            disabled={!savedKey}
            onClick={() => {
              toast('Vault unlocked — welcome', 'success')
              navigate('/')
            }}
          >
            <ShieldCheck size={15} /> Continue to my vault
          </button>
        </Card>
      </div>
    )
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="auth-logo">
          <img src="/shield.svg" alt="" />
          <div>
            <div style={{ fontWeight: 800, fontSize: 20 }}>SentinelVault</div>
            <div className="muted small">AI-powered password manager</div>
          </div>
        </div>

        <Card>
          <div className="tab-row">
            <div className={`tab${mode === 'login' ? ' active' : ''}`} onClick={() => { setMode('login'); setErr('') }}>Sign in</div>
            <div className={`tab${mode === 'register' ? ' active' : ''}`} onClick={() => { setMode('register'); setErr('') }}>Create account</div>
            <div className={`tab${mode === 'recovery' ? ' active' : ''}`} onClick={() => { setMode('recovery'); setErr('') }}>Recovery key</div>
          </div>

          <form onSubmit={submit}>
            <div className="field">
              <label>Email</label>
              <input className="input" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
            </div>
            {mode === 'register' && (
              <div className="field">
                <label>Display name</label>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Omprakash Suthar" />
              </div>
            )}
            {mode !== 'recovery' ? (
              <div className="field">
                <label>Master password</label>
                <input className="input" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder={mode === 'register' ? 'At least 10 characters, make it strong' : 'Your master password'} />
              </div>
            ) : (
              <>
                <div className="field">
                  <label>Recovery key</label>
                  <input className="input mono" required value={recoveryKey} onChange={(e) => setRecoveryKey(e.target.value)} placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" />
                </div>
                <div className="field">
                  <label>New master password</label>
                  <input className="input" type="password" required value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
                </div>
              </>
            )}

            {err && (
              <div className="row" style={{ color: 'var(--danger)', marginBottom: 12, fontSize: 12.5 }}>
                <AlertTriangle size={14} /> {err}
              </div>
            )}

            <button className="btn wide" disabled={busy}>
              {busy ? 'Working…' : mode === 'login' ? <><KeyRound size={15} /> Unlock vault</> : mode === 'register' ? 'Create my vault' : 'Reset with recovery key'}
            </button>
          </form>

          <div className="small muted" style={{ marginTop: 12, lineHeight: 1.5 }}>
            Zero-knowledge: your master password never leaves this device — only a key derived through Argon2id does.
          </div>
        </Card>
      </div>
    </div>
  )
}
