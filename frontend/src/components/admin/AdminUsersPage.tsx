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
import { Button, DataTable, ErrorAlert, Field, Input, LED, Panel, Select, SkeletonRows, StatusTag, formatDate } from '../ui'

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

  const statusTone = (u: AdminUser) => (!u.is_active ? 'neutral' : u.locked ? 'danger' : u.must_change_password ? 'warn' : 'ok')

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-fg">User management</h1>
        <p className="text-sm text-muted">Local accounts and roles. Temporary passwords are shown once and never stored in the browser.</p>
      </div>
      {error && <ErrorAlert message={error} onDismiss={() => setError(null)} />}
      {secret && (
        <div role="alert" className="border border-warn-line bg-warn-weak px-3 py-2.5 text-sm text-warn">
          <p className="flex items-center gap-2 font-semibold"><LED tone="warn" />Temporary password for {secret.username}</p>
          <p className="mt-1 break-all font-mono text-base text-fg" data-testid="temp-password">{secret.password}</p>
          <p className="mt-1 text-sm">{secret.note} It will not be shown again.</p>
          <div className="mt-2">
            <Button size="sm" onClick={() => setSecret(null)}>I have handed it over: hide it</Button>
          </div>
        </div>
      )}

      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Users" className="xl:col-span-9" bodyClassName="p-0"
               status={users ? <span className="font-mono text-xs">{users.length} accounts</span> : undefined}>
          {!users ? (
            <div className="p-3"><SkeletonRows rows={4} label="Loading users…" /></div>
          ) : (
            <DataTable<AdminUser>
              label="Users"
              rows={users}
              rowKey={(u) => u.id}
              rowTestId={(u) => `user-row-${u.username}`}
              initialSort={{ key: 'name', dir: 'asc' }}
              pageSize={50}
              empty="No user accounts."
              columns={[
                { key: 'name', header: 'Username', mono: true, className: 'whitespace-nowrap', sortValue: (u) => u.username, render: (u) => (
                  <span className="text-fg">
                    {u.username}
                    {u.id === session?.user.id && <span className="ml-1 text-muted">(you)</span>}
                  </span>) },
                { key: 'role', header: 'Role', sortValue: (u) => u.role, render: (u) => (
                  <Select
                    aria-label={`Role for ${u.username}`}
                    value={u.role}
                    disabled={busyId === u.id}
                    onChange={(e) => act(u.id, () => updateUser(u.id, { role: e.target.value as AdminUser['role'] }))}
                    className="!h-7 !w-28"
                  >
                    {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  </Select>) },
                { key: 'status', header: 'Status', className: 'w-full whitespace-nowrap', sortValue: (u) => (u.is_active ? 0 : 1), render: (u) => (
                  <StatusTag tone={statusTone(u)}>
                    {u.is_active ? 'active' : 'disabled'}
                    {u.locked && ' · locked'}
                    {u.must_change_password && ' · must change password'}
                  </StatusTag>) },
                { key: 'last', header: 'Last sign-in', mono: true, className: 'whitespace-nowrap text-muted',
                  sortValue: (u) => u.last_login_at ?? '', render: (u) => (u.last_login_at ? formatDate(u.last_login_at) : 'never') },
                { key: 'act', header: 'Actions', render: (u) => (
                  <div className="flex gap-1 whitespace-nowrap">
                    <Button size="sm" variant={u.is_active ? 'danger' : 'secondary'} disabled={busyId === u.id}
                            onClick={() => act(u.id, () => updateUser(u.id, { is_active: !u.is_active }))}>
                      {u.is_active ? 'Disable' : 'Enable'}
                    </Button>
                    <Button size="sm" disabled={busyId === u.id}
                            onClick={() => act(u.id, async () => showOnce(await resetUserPassword(u.id)))}>
                      Reset password
                    </Button>
                  </div>) },
              ]}
            />
          )}
        </Panel>

        <Panel title="Create user" className="xl:col-span-3">
          <form onSubmit={onCreate} className="space-y-3" aria-label="Create user">
            <Field label="Username">
              <Input name="new-username" value={newName} onChange={(e) => setNewName(e.target.value)}
                     required minLength={3} maxLength={64} autoComplete="off" />
            </Field>
            <Field label="Role">
              <Select name="new-role" value={newRole} onChange={(e) => setNewRole(e.target.value as AdminUser['role'])}>
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </Select>
            </Field>
            <Button type="submit" variant="primary" disabled={busyId === 'new' || newName.trim().length < 3}>
              Create with temporary password
            </Button>
            <p className="text-sm text-muted">The new user must change the temporary password at first sign-in.</p>
          </form>
        </Panel>
      </div>
    </div>
  )
}
