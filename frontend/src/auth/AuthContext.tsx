// Auth context (P5b): current session, permission checks and sign-out.
// The UI hides actions a role cannot perform, but the backend is the real
// enforcement: every endpoint checks the token and role server-side.
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { clearSession, getSession, lastLogoutReason, subscribe, type Session } from './session'

export interface AuthState {
  session: Session | null
  reason: string | null
  can: (permission: string) => boolean
}

const deny: AuthState = { session: null, reason: null, can: () => false }
export const AuthContext = createContext<AuthState>(deny)

export function authStateFor(session: Session | null, reason: string | null = null): AuthState {
  const perms = new Set(session?.user.permissions ?? [])
  return { session, reason, can: (p) => !!session && !session.user.must_change_password && perms.has(p) }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => getSession())
  const [reason, setReason] = useState<string | null>(() => lastLogoutReason())

  useEffect(
    () =>
      subscribe((s, r) => {
        setSession(s)
        setReason(r)
      }),
    [],
  )

  // Sign out locally exactly when the token expires (no refresh tokens).
  useEffect(() => {
    if (!session) return
    const ms = Date.parse(session.expiresAt) - Date.now()
    const t = window.setTimeout(() => clearSession('Your session expired. Sign in again.'), Math.max(0, ms))
    return () => window.clearTimeout(t)
  }, [session])

  const value = useMemo(() => authStateFor(session, reason), [session, reason])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  return useContext(AuthContext)
}
