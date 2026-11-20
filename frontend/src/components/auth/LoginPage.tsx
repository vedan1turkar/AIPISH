// Sign-in page (P5b). Errors are shown exactly as generic as the backend sends them.
import { useState, type FormEvent } from 'react'
import { ApiError, getMe, login } from '../../api/client'
import { setSession } from '../../auth/session'
import { Button, Field, Input, LED } from '../ui'

export default function LoginPage({ notice }: { notice?: string | null }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      const res = await login(username.trim(), password)
      const me = await getMe(res.access_token)
      setPassword('')
      setSession({ token: res.access_token, expiresAt: res.expires_at, user: me })
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setError('Invalid username or password.')
      else if (err instanceof ApiError && err.status === 429) setError(err.message)
      else setError(err instanceof Error ? err.message : 'Sign-in failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <form onSubmit={onSubmit} aria-label="Sign in" className="w-full max-w-[400px] border border-line bg-surface">
        <div className="flex items-baseline justify-between border-b border-line px-4 py-2.5">
          <h1 className="font-mono text-base font-semibold tracking-wider text-fg">AIPISH</h1>
          <span className="font-mono text-xs uppercase tracking-wider text-muted">Email threat forensics</span>
        </div>
        <div className="space-y-3 px-4 py-4">
          <p className="text-sm text-muted">Sign in to view or analyse stored forensic data.</p>
          {notice && !error && (
            <div role="status" className="flex items-center gap-2 border border-warn-line bg-warn-weak px-3 py-1.5 text-sm text-fg">
              <LED tone="warn" />{notice}
            </div>
          )}
          {error && (
            <p role="alert" className="flex items-center gap-2 border border-danger-line bg-danger-weak px-3 py-1.5 text-sm text-danger">
              <LED tone="danger" />{error}
            </p>
          )}
          <Field label="Username">
            <Input name="username" autoComplete="username" value={username}
                   onChange={(e) => setUsername(e.target.value)} required />
          </Field>
          <Field label="Password">
            <Input name="password" type="password" autoComplete="current-password" value={password}
                   onChange={(e) => setPassword(e.target.value)} required />
          </Field>
          <Button type="submit" variant="primary" className="w-full" disabled={busy || !username || !password}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
        </div>
        <p className="border-t border-line px-4 py-2 font-mono text-xs text-muted">
          Local accounts only · sessions expire after 60 min · access is audited
        </p>
      </form>
    </div>
  )
}
