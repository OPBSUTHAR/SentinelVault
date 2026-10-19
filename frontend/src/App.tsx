import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import Layout from './components/Layout'
import { ToastProvider } from './components/ui'
import { useAuth } from './store'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import VaultPage from './pages/VaultPage'
import GeneratorPage from './pages/GeneratorPage'
import BreachPage from './pages/BreachPage'
import SecurityPage from './pages/SecurityPage'
import SharingPage from './pages/SharingPage'
import EmergencyPage from './pages/EmergencyPage'
import SettingsPage from './pages/SettingsPage'
import PublicSharePage from './pages/PublicSharePage'
import PublicEmergencyPage from './pages/PublicEmergencyPage'

function Protected({ children }: { children: JSX.Element }) {
  const token = useAuth((s) => s.token)
  const location = useLocation()
  if (!token) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return children
}

export default function App() {
  return (
    <ToastProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/share/:token" element={<PublicSharePage />} />
        <Route path="/emergency/status/:token" element={<PublicEmergencyPage />} />
        <Route path="/emergency-request" element={<PublicEmergencyPage />} />
        <Route
          path="/"
          element={
            <Protected>
              <Layout />
            </Protected>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="vault" element={<VaultPage />} />
          <Route path="generator" element={<GeneratorPage />} />
          <Route path="breach" element={<BreachPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="sharing" element={<SharingPage />} />
          <Route path="emergency" element={<EmergencyPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </ToastProvider>
  )
}
