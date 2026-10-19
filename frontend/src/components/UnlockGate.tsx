import { useState, ReactNode } from 'react'
import { Lock } from 'lucide-react'
import { AuthApi, errText, setMasterKey, SyncApi } from '../api'
import { useAuth } from '../store'
import { Card, useToast } from './ui'

export default function UnlockGate({ children }: { children: ReactNode }) {
  const { unlocked, user, token, setAuth, setUnlocked } = useAuth()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const toast = useToast()

  if (unlocked) return <>{children}</>

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      const data = await AuthApi.unlock(password)
      setPassword('')
      if (data.token) {
        setAuth(data.token, user, true)
      } else {
        setUnlocked(true)
      }
      if (data.master_key) setMasterKey(data.master_key)
      SyncApi.seedFromAuth(data)
      SyncApi.refreshBackup()
      toast('Vault unlocked', 'success')
    } catch (error: any) {
      setErr(errText(error))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="unlock-card">
      <Card title="Vault is locked">
        <div className="muted small" style={{ marginBottom: 14 }}>
          Your master key is not in memory. Enter your master password to decrypt the vault.
        </div>
        <form onSubmit={submit}>
          <div className="field">
            <label>Master password</label>
            <input className="input" type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Master password" />
          </div>
          {err && <div style={{ color: 'var(--danger)', fontSize: 12.5, marginBottom: 10 }}>{err}</div>}
          <button className="btn wide" disabled={busy || !password || !token}>
            <Lock size={15} /> {busy ? 'Deriving key…' : 'Unlock vault'}
          </button>
        </form>
      </Card>
    </div>
  )
}
