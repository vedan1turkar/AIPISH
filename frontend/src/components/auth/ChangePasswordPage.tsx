// Password change (P5b). Required before anything else when the account has a temporary password.
import { useState, type FormEvent } from 'react'
import { ApiError, changePassword, getMe } from '../../api/client'
import { setSession } from '../../auth/session'
import { ErrorAlert, Panel } from '../ui'

export default function ChangePasswordPage({ required, onDone }: { required: boolean; onDone?: () => void }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (busy) return
    if (next !== confirm) {
      setError('The new passwords do not match.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const res = await changePassword(current, next)
      const me = await getMe(res.access_token)
      setSession({ token: res.access_token, expiresAt: res.expires_at, user: me })
      setCurrent('')
      setNext('')
      setConfirm('')
      setDone(true)
      onDone?.()
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : 'Password change failed.')
    } finally {
      setBusy(false)
    }
  }

  const field = (label: string, name: string, value: string, set: (v: string) => void, auto: string) => (
    <label className="block text-xs font-medium text-gray-700">
      {label}
      <input
        name={name}
        type="password"
        autoComplete={auto}
        value={value}
        onChange={(e) => set(e.target.value)}
        required
        className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
      />
    </label>
  )

  return (
    <div className="mx-auto max-w-md">
      <Panel title={required ? 'Change your temporary password' : 'Change password'}>
        <form onSubmit={onSubmit} aria-label="Change password" className="space-y-3">
          {required && (
            <p className="text-xs text-amber-800">
              Your account uses a temporary password. Choose a new one to continue.
            </p>
          )}
          <p className="text-xs text-gray-500">
            12–128 characters, not based on your username and not a common password. Changing it signs out
            your other sessions.
          </p>
          {error && <ErrorAlert message={error} />}
          {done && !required && <p role="status" className="text-xs text-emerald-700">Password changed.</p>}
          {field('Current password', 'current', current, setCurrent, 'current-password')}
          {field('New password', 'new', next, setNext, 'new-password')}
          {field('Repeat new password', 'confirm', confirm, setConfirm, 'new-password')}
          <button
            type="submit"
            disabled={busy || !current || !next || !confirm}
            className="rounded-lg bg-indigo-600 px-3 py-2 text-xs font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-gray-300"
          >
            {busy ? 'Saving…' : 'Change password'}
          </button>
        </form>
      </Panel>
    </div>
  )
}
