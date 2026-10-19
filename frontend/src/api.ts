import axios from 'axios'

export const API_BASE = import.meta.env.VITE_API_URL || '/api'

export const api = axios.create({ baseURL: API_BASE, timeout: 60000 })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sv_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status
    const url: string = error?.config?.url || ''
    if (status === 401 && !url.includes('/auth/login') && !url.includes('/auth/register')) {
      localStorage.removeItem('sv_token')
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  },
)

export function errText(error: any): string {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((d: any) => d?.msg || JSON.stringify(d)).join('; ')
  return error?.message || 'Something went wrong'
}

// ---- API helpers ---------------------------------------------------------

export const AuthApi = {
  register: (body: { email: string; display_name: string; password: string }) =>
    api.post('/auth/register', body).then((r) => r.data),
  login: (body: { email: string; password: string }) => api.post('/auth/login', body).then((r) => r.data),
  me: () => api.get('/auth/me').then((r) => r.data),
  unlock: (password: string) => api.post('/auth/unlock', { password }).then((r) => r.data),
  lock: () => api.post('/auth/lock').then((r) => r.data),
  changePassword: (current_password: string, new_password: string) =>
    api.post('/auth/change-password', { current_password, new_password }).then((r) => r.data),
  recovery: (email: string, recovery_key: string, new_password: string) =>
    api.post('/auth/recovery', { email, recovery_key, new_password }).then((r) => r.data),
}

export const VaultApi = {
  list: (category?: string) => api.get('/vault/items', { params: category ? { category } : {} }).then((r) => r.data),
  get: (id: string) => api.get(`/vault/items/${id}`).then((r) => r.data),
  create: (body: any) => api.post('/vault/items', body).then((r) => r.data),
  update: (id: string, body: any) => api.put(`/vault/items/${id}`, body).then((r) => r.data),
  remove: (id: string) => api.delete(`/vault/items/${id}`).then((r) => r.data),
  rotate: (id: string, policy = 'strong') => api.post(`/vault/items/${id}/rotate`, { policy }).then((r) => r.data),
  rotateBulk: (item_ids: string[], policy = 'strong') => api.post('/vault/rotate', { item_ids, policy }).then((r) => r.data),
  health: () => api.get('/vault/health').then((r) => r.data),
  totp: (id: string) => api.get(`/vault/items/${id}/totp`).then((r) => r.data),
  seedDemo: () => api.post('/vault/seed-demo').then((r) => r.data),
}

export const ToolsApi = {
  strength: (password: string, user_inputs: string[] = []) =>
    api.post('/tools/strength', { password, user_inputs }).then((r) => r.data),
  generate: (body: any) => api.post('/tools/generate', body).then((r) => r.data),
  policies: () => api.get('/tools/policies').then((r) => r.data),
  phishing: (url: string) => api.post('/tools/phishing', { url }).then((r) => r.data),
  totpCode: (secret: string) => api.post('/tools/totp/code', { secret }).then((r) => r.data),
  totpGenerate: () => api.post('/tools/totp/generate').then((r) => r.data),
}

export const SecurityApi = {
  checkPassword: (password: string) => api.post('/security/check-password', { password }).then((r) => r.data),
  checkEmail: (email: string) => api.post('/security/check-email', { email }).then((r) => r.data),
  events: (limit = 50) => api.get('/security/events', { params: { limit } }).then((r) => r.data),
  alerts: (limit = 50, unread_only = false) =>
    api.get('/security/alerts', { params: { limit, unread_only } }).then((r) => r.data),
  markRead: (id: string) => api.post(`/security/alerts/${id}/read`).then((r) => r.data),
  summary: () => api.get('/security/summary').then((r) => r.data),
}

export const SharesApi = {
  create: (body: any) => api.post('/shares', body).then((r) => r.data),
  list: () => api.get('/shares').then((r) => r.data),
  revoke: (id: string) => api.delete(`/shares/${id}`).then((r) => r.data),
  view: (token: string) => api.get(`/shares/view/${token}`).then((r) => r.data),
}

export const EmergencyApi = {
  contacts: () => api.get('/emergency/contacts').then((r) => r.data),
  addContact: (body: any) => api.post('/emergency/contacts', body).then((r) => r.data),
  removeContact: (id: string) => api.delete(`/emergency/contacts/${id}`).then((r) => r.data),
  request: (email: string, message: string) => api.post('/emergency/request', { email, message }).then((r) => r.data),
  check: (token: string) => api.get(`/emergency/check/${token}`).then((r) => r.data),
  requests: () => api.get('/emergency/requests').then((r) => r.data),
  decide: (id: string, approve: boolean) => api.post(`/emergency/requests/${id}/decide`, { approve }).then((r) => r.data),
}

export const DashboardApi = {
  load: () => api.get('/dashboard').then((r) => r.data),
}
