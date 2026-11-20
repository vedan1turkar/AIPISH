import { useCallback, useEffect, useState } from 'react'
import { getHealth, getAnalysis, getMe, logout, type AnalysisDetail } from './api/client'
import { useAuth } from './auth/AuthContext'
import { clearSession, updateUser } from './auth/session'
import { ErrorAlert, Spinner } from './components/ui'
import LoginPage from './components/auth/LoginPage'
import ChangePasswordPage from './components/auth/ChangePasswordPage'
import AdminUsersPage from './components/admin/AdminUsersPage'
import UploadPage from './components/UploadPage'
import ResultsDashboard from './components/ResultsDashboard'
import HistoryPage from './components/HistoryPage'
import { CampaignDetailView, CampaignList } from './components/correlation/CampaignsPage'
import CasePage from './components/cases/CasePage'
import SearchPage from './components/search/SearchPage'
import BackendStatus from './components/BackendStatus'

type View = 'upload' | 'results' | 'history' | 'users' | 'account' | 'campaigns' | 'campaign' | 'case' | 'search'

// `perm`: shown only to roles holding it. The backend enforces the same permission on every call.
const NAV: { id: View; label: string; icon: string; perm?: string }[] = [
  { id: 'upload', label: 'Analyse', icon: '📥', perm: 'analysis:create' },
  { id: 'history', label: 'History', icon: '🗂️', perm: 'analysis:read' },
  { id: 'campaigns', label: 'Campaigns', icon: '🕸️', perm: 'correlation:read' },
  { id: 'search', label: 'Search', icon: '🔎', perm: 'search:read' },
  { id: 'users', label: 'Users', icon: '👥', perm: 'users:manage' },
]

export default function App() {
  const auth = useAuth()
  if (!auth.session) return <LoginPage notice={auth.reason} />
  if (auth.session.user.must_change_password) {
    return (
      <div className="min-h-screen bg-gray-50 px-4 py-10">
        <ChangePasswordPage required />
        <div className="mt-4 text-center">
          <SignOutButton />
        </div>
      </div>
    )
  }
  return <SignedInApp />
}

function SignOutButton() {
  const [busy, setBusy] = useState(false)
  return (
    <button
      onClick={async () => {
        setBusy(true)
        try {
          await logout() // revokes this user's tokens server-side
        } catch {
          /* still sign out locally */
        }
        clearSession('You signed out.')
      }}
      disabled={busy}
      className="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50"
    >
      Sign out
    </button>
  )
}

function SignedInApp() {
  const { session, can } = useAuth()
  const user = session!.user
  const [view, setView] = useState<View>(() => (can('analysis:create') ? 'upload' : 'history'))
  // Resume: analysis currently open in the dashboard (either fresh from upload
  // or re-opened from history). `null` on the upload page.
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null)
  const [loadingId, setLoadingId] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  // id for #campaign/{id} and #case/{id} routes (P5c)
  const [routeId, setRouteId] = useState<string | null>(null)

  const openAnalysis = useCallback(async (id: string) => {
    setLoadError(null)
    setLoadingId(id)
    try {
      const detail = await getAnalysis(id)
      setAnalysis(detail)
      setView('results')
      window.scrollTo({ top: 0 })
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Could not load that analysis.')
    } finally {
      setLoadingId(null)
    }
  }, [])

  useEffect(() => {
    // Warm the health check so BackendStatus is ready on first paint.
    void getHealth().catch(() => undefined)
    // Re-validate a session restored from sessionStorage (a revoked token → 401 → login page).
    void getMe().then(updateUser).catch(() => undefined)
  }, [])

  const allowed = useCallback(
    (v: View) => {
      const item = NAV.find((n) => n.id === v)
      return !item?.perm || can(item.perm)
    },
    [can],
  )

  //rudimentary hash routing so refresh/back work acceptably
  useEffect(() => {
    const applyHash = () => {
      const h = window.location.hash
      if (h === '#upload') setView(allowed('upload') ? 'upload' : 'history')
      else if (h === '#history') setView('history')
      else if (h === '#users') setView(allowed('users') ? 'users' : 'history')
      else if (h === '#account') setView('account')
      else if (h === '#campaigns') setView(allowed('campaigns') ? 'campaigns' : 'history')
      else if (h === '#search') setView(allowed('search') ? 'search' : 'history')
      else if (h.startsWith('#campaign/') && allowed('campaigns')) {
        setRouteId(h.slice('#campaign/'.length))
        setView('campaign')
      } else if (h.startsWith('#case/')) {
        setRouteId(h.slice('#case/'.length))
        setView('case')
      }
      else if (h.startsWith('#analysis/')) {
        const id = h.slice('#analysis/'.length)
        if (id) void openAnalysis(id)
      }
    }
    applyHash()
    window.addEventListener('hashchange', applyHash)
    return () => window.removeEventListener('hashchange', applyHash)
  }, [openAnalysis, allowed])

  function navigate(v: View) {
    if (!allowed(v)) v = 'history'
    setView(v)
    window.location.hash = v === 'upload' ? '#upload' : `#${v}`
    if (v === 'results' && !analysis) setView('upload')
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* top bar */}
      <header className="sticky top-0 z-10 border-b border-gray-200 bg-white/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2">
            <span aria-hidden className="text-xl">🛡️</span>
            <h1 className="text-base font-semibold text-gray-900 whitespace-nowrap">
              Email Forensics Platform
            </h1>
            <BackendStatus />
          </div>
          <nav className="flex gap-1 rounded-lg bg-gray-100 p-1 sm:ml-auto" aria-label="Main navigation">
            {NAV.filter((n) => !n.perm || can(n.perm)).map((n) => (
              <button
                key={n.id}
                onClick={() => navigate(n.id)}
                aria-current={view === n.id ? 'page' : undefined}
                className={`whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium ${
                  view === n.id || (view === 'results' && n.id === 'upload')
                    ? 'bg-white text-gray-900 shadow-sm'
                    : 'text-gray-500 hover:text-gray-800'
                }`}
              >
                <span className="mr-1" aria-hidden>{n.icon}</span>
                {n.label}
              </button>
            ))}
          </nav>
          <div className="flex items-center gap-2 text-xs" data-testid="current-user">
            <span className="text-gray-700">
              <span aria-hidden>👤</span> <strong>{user.username}</strong>
            </span>
            <span className="rounded-full bg-indigo-50 px-2 py-0.5 font-semibold uppercase tracking-wide text-indigo-700 ring-1 ring-indigo-200">
              {user.role}
            </span>
            <button
              onClick={() => navigate('account')}
              className="rounded-md px-2 py-1 font-medium text-gray-500 hover:text-gray-800"
            >
              Password
            </button>
            <SignOutButton />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
        {loadError && (
          <div className="mb-4">
            <ErrorAlert message={loadError} onDismiss={() => setLoadError(null)} />
          </div>
        )}
        {view === 'upload' && can('analysis:create') && (
          <UploadPage
            onAnalyzed={(detail) => {
              setAnalysis(detail)
              setView('results')
              window.location.hash = `#analysis/${detail.id}`
              window.scrollTo({ top: 0 })
            }}
          />
        )}
        {view === 'results' && analysis && !loadingId && (
          <ResultsDashboard
            analysis={analysis}
            onNewAnalysis={() => {
              setAnalysis(null)
              navigate('upload')
            }}
          />
        )}
        {view === 'results' && !analysis && !loadingId && (
          <ErrorAlert message="No analysis is open — pick one from history or upload a new file." />
        )}
        {view === 'history' && <HistoryPage onOpenAnalysis={openAnalysis} />}
        {view === 'users' && can('users:manage') && <AdminUsersPage />}
        {view === 'account' && <ChangePasswordPage required={false} />}
        {view === 'campaigns' && can('correlation:read') && <CampaignList />}
        {view === 'campaign' && routeId && can('correlation:read') && <CampaignDetailView id={routeId} />}
        {view === 'case' && routeId && can('case:read') && <CasePage id={routeId} />}
        {view === 'search' && can('search:read') && <SearchPage />}
      </main>

      <footer className="mx-auto max-w-6xl px-4 pb-8 text-center text-xs text-gray-400 sm:px-6">
        All results come from the connected backend. Heuristic scores are investigative
        indicators — not proof of who sent a message or where they are located.
      </footer>

      {loadingId && (
        <div className="fixed inset-0 z-20 flex items-center justify-center bg-white/60">
          <Spinner label="Loading analysis…" />
        </div>
      )}
    </div>
  )
}
