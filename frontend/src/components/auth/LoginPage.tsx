// Sign-in page (P5b). Errors are shown exactly as generic as the backend sends them.
import { useState, type FormEvent } from 'react'
import { ApiError, getMe, login } from '../../api/client'
import { setSession } from '../../auth/session'
import { ErrorAlert } from '../ui'

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
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <form
        onSubmit={onSubmit}
        aria-label="Sign in"
        className="w-full max-w-sm space-y-4 rounded-xl border border-gray-200 bg-white p-6 shadow-sm"
      >
        <div className="flex items-center gap-2">
          <span aria-hidden className="text-xl">🛡️</span>
          <h1 className="text-base font-semibold text-gray-900">Email Forensics Platform</h1>
        </div>
        <p className="text-xs text-gray-500">Sign in to view or analyse stored forensic data.</p>
        {notice && !error && (
          <div role="status" className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {notice}
          </div>
        )}
        {error && <ErrorAlert message={error} />}
        <label className="block text-xs font-medium text-gray-700">
          Username
          <input
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
          />
        </label>
        <label className="block text-xs font-medium text-gray-700">
          Password
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
          />
        </label>
        <button
          type="submit"
          disabled={busy || !username || !password}
          className="w-full rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-gray-300"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
