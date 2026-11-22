import { useCallback, useEffect, useState } from 'react'
import { getAnalysis, getMe, logout, type AnalysisDetail } from './api/client'
import { useAuth } from './auth/AuthContext'
import { clearSession, updateUser } from './auth/session'
import { Button, ErrorAlert, PageNotice, Spinner } from './components/ui'
import LoginPage from './components/auth/LoginPage'
import ChangePasswordPage from './components/auth/ChangePasswordPage'
import AdminUsersPage from './components/admin/AdminUsersPage'
import UploadPage from './components/UploadPage'
import ResultsDashboard from './components/ResultsDashboard'
import HistoryPage from './components/HistoryPage'
import { CampaignDetailView, CampaignList } from './components/correlation/CampaignsPage'
import CasePage from './components/cases/CasePage'
import SearchPage from './components/search/SearchPage'
import AnalyticsPage from './components/analytics/AnalyticsPage'
import AuditPage from './components/admin/AuditPage'
import RetentionPage from './components/admin/RetentionPage'
import StatusBar from './components/shell/StatusBar'
import OverviewPage from './components/overview/OverviewPage'
import AlertsPage from './components/alerts/AlertsPage'
import { AlertBadge } from './components/alerts/shared'

type View = 'overview' | 'upload' | 'results' | 'history' | 'users' | 'account' | 'campaigns' | 'campaign' | 'case' | 'search' | 'analytics' | 'audit' | 'retention' | 'alerts' | 'notfound'

// `perm`: shown only to roles holding it. The backend enforces the same permission on every call.
const NAV: { id: View; label: string; perm?: string }[] = [
  { id: 'overview', label: 'Overview', perm: 'analysis:read' },
  { id: 'upload', label: 'Analyse', perm: 'analysis:create' },
  { id: 'history', label: 'History', perm: 'analysis:read' },
  { id: 'alerts', label: 'Alerts', perm: 'alert:read' },
  { id: 'campaigns', label: 'Campaigns', perm: 'correlation:read' },
  { id: 'analytics', label: 'Analytics', perm: 'analysis:read' },
  { id: 'search', label: 'Search', perm: 'search:read' },
  { id: 'users', label: 'Users', perm: 'users:manage' },
  { id: 'audit', label: 'Audit', perm: 'audit:read' },
  { id: 'retention', label: 'Retention', perm: 'retention:manage' },
]

function Brand() {
  return (
    <div className="flex items-baseline gap-2 whitespace-nowrap">
      <span className="font-mono text-base font-semibold tracking-wider text-fg">AIPISH</span>
      <span className="hidden font-mono text-xs uppercase tracking-wider text-muted xl:inline">Email threat forensics</span>
    </div>
  )
}

export default function App() {
  const auth = useAuth()
  if (!auth.session) return <LoginPage notice={auth.reason} />
  if (auth.session.user.must_change_password) {
    return (
      <div className="min-h-screen bg-bg">
        <header className="flex h-11 items-center justify-between border-b border-line bg-surface px-4">
          <Brand />
          <SignOutButton />
        </header>
        <main className="px-4 py-8"><ChangePasswordPage required /></main>
      </div>
    )
  }
  return <SignedInApp />
}

function SignOutButton() {
  const [busy, setBusy] = useState(false)
  return (
    <Button
      size="sm"
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
    >
      Sign out
    </Button>
  )
}

function SignedInApp() {
  const { session, can } = useAuth()
  const user = session!.user
  const [view, setView] = useState<View>('overview')
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
      if (h === '#overview' || h === '') setView('overview')
      else if (h === '#upload') setView(allowed('upload') ? 'upload' : 'history')
      else if (h === '#history') setView('history')
      else if (h === '#users') setView(allowed('users') ? 'users' : 'history')
      else if (h === '#account') setView('account')
      else if (h === '#campaigns') setView(allowed('campaigns') ? 'campaigns' : 'history')
      else if (h === '#search') setView(allowed('search') ? 'search' : 'history')
      else if (h === '#audit') setView(allowed('audit') ? 'audit' : 'history')
      else if (h === '#retention') setView(allowed('retention') ? 'retention' : 'history')
      else if (h === '#analytics') setView(allowed('analytics') ? 'analytics' : 'history')
      else if (h === '#alerts' || h.startsWith('#alerts/')) {
        setRouteId(h.startsWith('#alerts/') ? h.slice('#alerts/'.length) || null : null)
        setView(allowed('alerts') ? 'alerts' : 'history')
      }
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
        else setView('notfound')
      }
      else setView('notfound')
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
    <div className="flex min-h-screen flex-col bg-bg pb-7">
      <header className="sticky top-0 z-10 border-b border-line bg-surface">
        <div className="mx-auto flex h-11 max-w-content items-stretch gap-6 px-4">
          <div className="flex items-center"><Brand /></div>
          <nav className="flex items-stretch overflow-x-auto" aria-label="Main navigation">
            {NAV.filter((n) => !n.perm || can(n.perm)).map((n) => {
              const on = view === n.id || (view === 'results' && n.id === 'history') ||
                (view === 'campaign' && n.id === 'campaigns') || (view === 'case' && n.id === 'history')
              return (
                <button
                  key={n.id}
                  onClick={() => navigate(n.id)}
                  aria-current={on ? 'page' : undefined}
                  className={`-mb-px whitespace-nowrap border-b-2 px-3 text-sm ${
                    on ? 'border-accent bg-surface-2 text-fg' : 'border-transparent text-muted hover:bg-surface-3 hover:text-fg'
                  }`}
                >
                  {n.label}
                </button>
              )
            })}
          </nav>
          <div className="ml-auto flex items-center gap-2 text-sm" data-testid="current-user">
            {can('alert:read') && <AlertBadge />}
            <span className="whitespace-nowrap font-mono text-sm text-fg">{user.username}</span>
            <span className="rounded-sm border border-line-strong px-1.5 font-mono text-xs uppercase tracking-wider text-muted">
              {user.role}
            </span>
            <Button size="sm" variant="ghost" onClick={() => navigate('account')}>Password</Button>
            <SignOutButton />
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-content flex-1 px-4 py-4">
        {loadError && (
          <div className="mb-4">
            <ErrorAlert message={loadError} onDismiss={() => setLoadError(null)} />
          </div>
        )}
        {view === 'overview' && <OverviewPage onOpenAnalysis={(id) => { window.location.hash = `#analysis/${id}` }} />}
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
          <PageNotice title="No analysis open" actions={<>
            <Button variant="primary" onClick={() => navigate('history')}>Open history</Button>
            {can('analysis:create') && <Button onClick={() => navigate('upload')}>Analyse an email</Button>}
          </>}>
            No analysis is open — pick one from history or upload a new file.
          </PageNotice>
        )}
        {view === 'notfound' && (
          <PageNotice title="Page not found" code="404" actions={<Button variant="primary" onClick={() => navigate('overview')}>Go to overview</Button>}>
            There is no page at <span className="font-mono">{window.location.hash || '/'}</span>. Use the navigation above.
          </PageNotice>
        )}
        {view === 'case' && routeId && !can('case:read') && (
          <PageNotice title="Not permitted" code="403" actions={<Button onClick={() => navigate('history')}>Open history</Button>}>
            Your role cannot open investigation cases.
          </PageNotice>
        )}
        {view === 'history' && <HistoryPage onOpenAnalysis={openAnalysis} />}
        {view === 'users' && can('users:manage') && <AdminUsersPage />}
        {view === 'account' && <ChangePasswordPage required={false} />}
        {view === 'campaigns' && can('correlation:read') && <CampaignList />}
        {view === 'campaign' && routeId && can('correlation:read') && <CampaignDetailView id={routeId} />}
        {view === 'case' && routeId && can('case:read') && <CasePage id={routeId} />}
        {view === 'search' && can('search:read') && <SearchPage />}
        {view === 'analytics' && can('analysis:read') && <AnalyticsPage />}
        {view === 'audit' && can('audit:read') && <AuditPage />}
        {view === 'retention' && can('retention:manage') && <RetentionPage />}
        {view === 'alerts' && can('alert:read') && <AlertsPage initialId={routeId} />}
        <p className="mt-6 border-t border-line pt-2 text-sm text-muted">
          All results come from the connected backend. Heuristic scores are investigative
          indicators — not proof of who sent a message or where they are located.
        </p>
      </main>

      <StatusBar />

      {loadingId && (
        <div className="fixed inset-0 z-20 flex items-center justify-center bg-[rgba(10,14,19,0.82)]">
          <div className="border border-line bg-surface px-4 py-3">
            <Spinner label="Loading analysis…" />
            <p className="mt-1 font-mono text-xs text-muted">{loadingId}</p>
          </div>
        </div>
      )}
    </div>
  )
}
