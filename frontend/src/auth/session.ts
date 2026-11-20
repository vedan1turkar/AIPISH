// Session store (P5b). The access token is held in memory and mirrored to
// sessionStorage so a page refresh keeps the user signed in within this tab.
// sessionStorage (not localStorage): it is per-tab and cleared when the tab
// closes. Trade-off: like any script-readable storage, an XSS bug could read
// it; the backend therefore keeps tokens short-lived (60 min), revocable
// (token_version) and enforces every permission itself.
export interface SessionUser {
  id: string
  username: string
  role: 'viewer' | 'analyst' | 'admin' | string
  is_active?: boolean
  must_change_password: boolean
  permissions?: string[]
}

export interface Session {
  token: string
  expiresAt: string
  user: SessionUser
}

const KEY = 'aipish.session'
type Listener = (s: Session | null, reason: string | null) => void
const listeners = new Set<Listener>()

function storage(): Storage | null {
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

function load(): Session | null {
  try {
    const raw = storage()?.getItem(KEY)
    if (!raw) return null
    const s = JSON.parse(raw) as Session
    if (!s?.token || !s.user || Date.parse(s.expiresAt) <= Date.now()) return null
    return s
  } catch {
    return null
  }
}

let current: Session | null = load()
let lastReason: string | null = null

export function getSession(): Session | null {
  if (current && Date.parse(current.expiresAt) <= Date.now()) clearSession('Your session expired. Sign in again.')
  return current
}

export function getToken(): string | null {
  return getSession()?.token ?? null
}

export function setSession(s: Session): void {
  current = s
  lastReason = null
  try {
    storage()?.setItem(KEY, JSON.stringify(s))
  } catch {
    /* storage unavailable: session lives in memory only */
  }
  listeners.forEach((l) => l(current, null))
}

export function updateUser(user: SessionUser): void {
  if (current) setSession({ ...current, user })
}

export function clearSession(reason: string | null = null): void {
  const had = current !== null
  current = null
  lastReason = reason
  try {
    storage()?.removeItem(KEY)
  } catch {
    /* ignore */
  }
  if (had || reason) listeners.forEach((l) => l(null, reason))
}

export function lastLogoutReason(): string | null {
  return lastReason
}

export function subscribe(l: Listener): () => void {
  listeners.add(l)
  return () => listeners.delete(l)
}
