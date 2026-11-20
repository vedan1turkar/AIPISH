// Test helper: render inside an AuthContext for a given role (permissions mirror backend/app/security/permissions.py).
import type { ReactElement } from 'react'
import { AuthContext, authStateFor } from '../auth/AuthContext'
import type { Session } from '../auth/session'

const VIEWER = ['self', 'analysis:read', 'case:read', 'report:download', 'intel:read', 'assessment:read', 'ml:status',
  'correlation:read', 'search:read']
const ANALYST = [...VIEWER, 'analysis:create', 'case:write', 'evidence:verify', 'intel:run', 'assessment:run', 'ml:run']
const ADMIN = [...ANALYST, 'users:manage', 'config:status', 'docs:read', 'correlation:rebuild']
export const PERMS: Record<string, string[]> = { viewer: VIEWER, analyst: ANALYST, admin: ADMIN }

export function sessionFor(role: 'viewer' | 'analyst' | 'admin', extra: Partial<Session['user']> = {}): Session {
  return {
    token: `test-token-${role}`,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    user: { id: `id-${role}`, username: `demo-${role}`, role, must_change_password: false, permissions: PERMS[role], ...extra },
  }
}

export function withRole(
  ui: ReactElement,
  role: 'viewer' | 'analyst' | 'admin' = 'analyst',
  extra: Partial<Session['user']> = {},
): ReactElement {
  return <AuthContext.Provider value={authStateFor(sessionFor(role, extra))}>{ui}</AuthContext.Provider>
}
