import { create } from 'zustand'

export interface User {
  id: string
  email: string
  display_name: string
  created_at?: string
  has_recovery?: boolean
}

interface AuthState {
  token: string | null
  user: User | null
  unlocked: boolean
  setAuth: (token: string | null, user: User | null, unlocked?: boolean) => void
  setUnlocked: (unlocked: boolean) => void
  setUser: (user: User) => void
  logout: () => void
}

export const useAuth = create<AuthState>((set) => ({
  token: localStorage.getItem('sv_token'),
  user: JSON.parse(localStorage.getItem('sv_user') || 'null'),
  unlocked: localStorage.getItem('sv_unlocked') === '1',
  setAuth: (token, user, unlocked) => {
    if (token) localStorage.setItem('sv_token', token)
    else localStorage.removeItem('sv_token')
    if (user) localStorage.setItem('sv_user', JSON.stringify(user))
    else localStorage.removeItem('sv_user')
    const u = unlocked !== undefined ? unlocked : token ? true : false
    localStorage.setItem('sv_unlocked', u ? '1' : '0')
    set({ token, user, unlocked: u })
  },
  setUnlocked: (unlocked) => {
    localStorage.setItem('sv_unlocked', unlocked ? '1' : '0')
    set({ unlocked })
  },
  setUser: (user) => {
    localStorage.setItem('sv_user', JSON.stringify(user))
    set({ user })
  },
  logout: () => {
    localStorage.removeItem('sv_token')
    localStorage.removeItem('sv_user')
    localStorage.removeItem('sv_unlocked')
    set({ token: null, user: null, unlocked: false })
  },
}))
