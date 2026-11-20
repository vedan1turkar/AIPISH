// Admin user management (P5b). Temporary passwords are shown once, in this
// page's state only: never logged, never stored client-side.
import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  createUser,
  listUsers,
  resetUserPassword,
  updateUser,
  type AdminUser,
  type TempPasswordResult,
} from '../../api/client'
import { useAuth } from '../../auth/AuthContext'
import { ErrorAlert, Panel, Spinner, formatDate } from '../ui'

const ROLES: AdminUser['role'][] = ['viewer', 'analyst', 'admin']

export default function AdminUsersPage() {
  const { session } = useAuth()
  const [users, setUsers] = useState<AdminUser[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [newRole, setNewRole] = useState<AdminUser['role']>('viewer')
  const [secret, setSecret] = useState<{ username: string; password: string; note: string } | null>(null)

  const refresh = useCallback(async () => {
    try {
      setUsers(await listUsers())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load users.')
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  async function act(id: string, fn: () => Promise<unknown>) {
    setBusyId(id)
    setError(null)
    try {
      await fn()
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.')
    } finally {
      setBusyId(null)
    }
  }

  const showOnce = (r: TempPasswordResult) =>
    setSecret({ username: r.user.username, password: r.temporary_password, note: r.note })

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    await act('new', async () => {
      showOnce(await createUser(newName.trim(), newRole))
      setNewName('')
    })
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-gray-900">User management</h2>
      {error && <ErrorAlert message={error} onDismiss={() => setError(null)} />}
      {secret && (
        <div role="alert" className=" border-2 border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <p className="font-semibold">Temporary password for {secret.username}</p>
          <p className="mt-1 font-mono text-base break-all" data-testid="temp-password">{secret.password}</p>
          <p className="mt-1 text-xs">{secret.note} It will not be shown again.</p>
          <button
            onClick={() => setSecret(null)}
            className="mt-2 border border-amber-400 bg-white px-2 py-1 text-xs font-medium"
          >
            I have handed it over: hide it
          </button>
        </div>
      )}

      <Panel title="Create user">
        <form onSubmit={onCreate} className="flex flex-wrap items-end gap-2" aria-label="Create user">
          <label className="text-xs font-medium text-gray-700">
            Username
            <input
              name="new-username"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              required
              minLength={3}
              maxLength={64}
              className="mt-1 block border border-gray-300 px-3 py-1.5 text-sm"
            />
          </label>
          <label className="text-xs font-medium text-gray-700">
            Role
            <select
              name="new-role"
              value={newRole}
              onChange={(e) => setNewRole(e.target.value as AdminUser['role'])}
              className="mt-1 block border border-gray-300 px-2 py-1.5 text-sm"
            >
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </label>
          <button
            type="submit"
            disabled={busyId === 'new' || newName.trim().length < 3}
            className=" bg-indigo-600 px-3 py-2 text-xs font-semibold text-white disabled:bg-gray-300"
          >
            Create with temporary password
          </button>
        </form>
      </Panel>

      <Panel title="Users">
        {!users ? (
          <Spinner label="Loading users…" />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="text-gray-500">
                <tr>
                  <th className="py-1 pr-3">Username</th>
                  <th className="py-1 pr-3">Role</th>
                  <th className="py-1 pr-3">Status</th>
                  <th className="py-1 pr-3">Last sign-in</th>
                  <th className="py-1">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-t border-gray-100" data-testid={`user-row-${u.username}`}>
                    <td className="py-1.5 pr-3 font-medium text-gray-900">
                      {u.username}
                      {u.id === session?.user.id && <span className="ml-1 text-gray-400">(you)</span>}
                    </td>
                    <td className="py-1.5 pr-3">
                      <select
                        aria-label={`Role for ${u.username}`}
                        value={u.role}
                        disabled={busyId === u.id}
                        onChange={(e) =>
                          act(u.id, () => updateUser(u.id, { role: e.target.value as AdminUser['role'] }))
                        }
                        className=" border border-gray-300 px-1 py-0.5"
                      >
                        {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td className="py-1.5 pr-3">
                      {u.is_active ? 'active' : 'disabled'}
                      {u.locked && ' · locked'}
                      {u.must_change_password && ' · must change password'}
                    </td>
                    <td className="py-1.5 pr-3 text-gray-500">{u.last_login_at ? formatDate(u.last_login_at) : 'never'}</td>
                    <td className="py-1.5">
                      <div className="flex gap-1">
                        <button
                          disabled={busyId === u.id}
                          onClick={() => act(u.id, () => updateUser(u.id, { is_active: !u.is_active }))}
                          className=" border border-gray-300 bg-white px-2 py-0.5 hover:bg-gray-50 disabled:opacity-50"
                        >
                          {u.is_active ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          disabled={busyId === u.id}
                          onClick={() => act(u.id, async () => showOnce(await resetUserPassword(u.id)))}
                          className=" border border-gray-300 bg-white px-2 py-0.5 hover:bg-gray-50 disabled:opacity-50"
                        >
                          Reset password
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  )
}
