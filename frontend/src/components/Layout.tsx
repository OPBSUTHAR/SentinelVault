import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, KeyRound, Wand2, ShieldAlert, Radar, Share2, Siren, Settings as SettingsIcon,
  Lock, Unlock, LogOut, Bell, ShieldCheck,
} from 'lucide-react'
import { AuthApi, SecurityApi, SyncApi, setMasterKey } from '../api'
import { useAuth } from '../store'
import { Spinner } from './ui'

const NAV = [
  { section: 'Vault' },
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/vault', label: 'My Vault', icon: KeyRound },
  { to: '/generator', label: 'Generator', icon: Wand2 },
  { section: 'Monitoring' },
  { to: '/breach', label: 'Breach Monitor', icon: Radar },
  { to: '/security', label: 'Security & Alerts', icon: ShieldAlert },
  { section: 'Access' },
  { to: '/sharing', label: 'Secure Sharing', icon: Share2 },
  { to: '/emergency', label: 'Emergency Access', icon: Siren },
  { section: 'Account' },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
]

export default function Layout() {
  const { user, unlocked, setUnlocked, logout, setUser } = useAuth()
  const navigate = useNavigate()
  const [unread, setUnread] = useState(0)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    const boot = async () => {
      try {
        // Serverless instances are interchangeable: seed the one answering
        // this request with our encrypted backup before asking for state.
        const backup = SyncApi.readBackup()
        if (backup && localStorage.getItem('sv_token')) {
          try {
            await SyncApi.restore(backup.bundle)
          } catch {
            /* account already present on this instance — fine */
          }
        }
        const d = await AuthApi.me()
        setUser(d.user)
        setUnlocked(!!d.unlocked)
      } catch {
        /* invalid token handled by the api interceptor */
      } finally {
        setChecking(false)
      }
    }
    boot()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const load = () => SecurityApi.alerts(1, true).then((d) => setUnread(d.unread)).catch(() => {})
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [unlocked])

  const handleLock = async () => {
    try {
      await AuthApi.lock()
    } catch {}
    setMasterKey(null)
    setUnlocked(false)
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  if (checking) return <Spinner />

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img src="/shield.svg" alt="SentinelVault" />
          <div className="name">Sentinel<span>Vault</span></div>
        </div>
        {NAV.map((n, i) =>
          'section' in n && n.section ? (
            <div key={i} className="nav-section">{n.section}</div>
          ) : (
            <NavLink key={i} to={(n as any).to} end={(n as any).to === '/'} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
              <n.icon size={16} />
              {(n as any).label}
              {(n as any).to === '/security' && unread > 0 && <span className="badge-count">{unread}</span>}
            </NavLink>
          ),
        )}
        <div style={{ flex: 1 }} />
        <div className="nav-item" onClick={handleLogout}>
          <LogOut size={16} /> Sign out
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <ShieldCheck size={20} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>{user?.display_name || 'SentinelVault'}</div>
            <div className="sub">{user?.email}</div>
          </div>
          <span className={`badge ${unlocked ? 'ok' : 'warn'}`}>
            {unlocked ? <Unlock size={12} /> : <Lock size={12} />} {unlocked ? 'Vault unlocked' : 'Vault locked'}
          </span>
          <NavLink to="/security" className="icon-btn" style={{ position: 'relative' }}>
            <Bell size={15} />
            {unread > 0 && <span style={{ position: 'absolute', top: -4, right: -4, background: 'var(--danger)', color: '#fff', borderRadius: 999, fontSize: 10, padding: '0 5px' }}>{unread}</span>}
          </NavLink>
          {unlocked && (
            <button className="icon-btn" title="Lock vault" onClick={handleLock}>
              <Lock size={15} />
            </button>
          )}
        </header>
        <main className="page">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
