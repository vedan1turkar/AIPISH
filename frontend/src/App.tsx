import { useCallback, useEffect, useState } from 'react'
import { getHealth, getAnalysis, type AnalysisDetail } from './api/client'
import { ErrorAlert, Spinner } from './components/ui'
import UploadPage from './components/UploadPage'
import ResultsDashboard from './components/ResultsDashboard'
import HistoryPage from './components/HistoryPage'
import BackendStatus from './components/BackendStatus'

type View = 'upload' | 'results' | 'history'

const NAV: { id: View; label: string; icon: string }[] = [
  { id: 'upload', label: 'Analyse', icon: '📥' },
  { id: 'history', label: 'History', icon: '🗂️' },
]

export default function App() {
  const [view, setView] = useState<View>('upload')
  // Resume: analysis currently open in the dashboard (either fresh from upload
  // or re-opened from history). `null` on the upload page.
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null)
  const [loadingId, setLoadingId] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

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
  }, [])

  //rudimentary hash routing so refresh/back work acceptably
  useEffect(() => {
    const applyHash = () => {
      const h = window.location.hash
      if (h === '#upload') setView('upload')
      else if (h === '#history') setView('history')
      else if (h.startsWith('#analysis/')) {
        const id = h.slice('#analysis/'.length)
        if (id) void openAnalysis(id)
      }
    }
    applyHash()
    window.addEventListener('hashchange', applyHash)
    return () => window.removeEventListener('hashchange', applyHash)
  }, [openAnalysis])

  function navigate(v: View) {
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
            {NAV.map((n) => (
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
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
        {loadError && (
          <div className="mb-4">
            <ErrorAlert message={loadError} onDismiss={() => setLoadError(null)} />
          </div>
        )}
        {view === 'upload' && (
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
