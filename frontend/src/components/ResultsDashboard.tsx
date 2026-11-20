import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import type { AnalysisDetail } from '../api/client'
import {
  createInvestigation,
  downloadReport,
  ApiError,
  generateAssessment,
  getAssessment,
  getAssessmentVersion,
  listAssessments,
  getLlmStatus,
  getMlStatus,
  getIntelStatus,
  getThreatIntel,
  listInvestigations,
  runThreatIntel,
  verifyIntegrity,
  type Assessment,
  type IntelServiceStatus,
  type ThreatIntelRun,
  type AssessmentSummary,
  type InvestigationCase,
  type IntegrityResult,
  type LlmStatus,
  type MlStatus,
} from '../api/client'
import {
  ErrorAlert,
  MetaRow,
  Panel,
  ScoreBadge,
  SeverityChip,
  Spinner,
  StatusBadge,
  classifyStatus,
  formatDate,
  formatBytes,
} from './ui'
import { HeaderForensicsPanel, AnomaliesPanel, IntelligenceDetailsPanel } from './ForensicsPanels'
import TraceView from './trace/TraceView'
import { AssessmentOverviewCard, AssessmentView } from './assessment/AssessmentPanels'
import ThreatIntelPanel from './intel/ThreatIntelPanel'
import { useAuth } from '../auth/AuthContext'

type Tab = 'overview' | 'findings' | 'auth' | 'headers' | 'intel' | 'threat' | 'trace' | 'ai'

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: 'overview', label: 'Overview', icon: '📋' },
  { id: 'findings', label: 'Findings', icon: '🚩' },
  { id: 'auth', label: 'Authentication', icon: '🔐' },
  { id: 'headers', label: 'Headers & relay', icon: '🔀' },
  { id: 'intel', label: 'IP & domain intel', icon: '🌐' },
  { id: 'threat', label: 'Threat intel', icon: '🛡️' },
  { id: 'trace', label: 'Trace view', icon: '🕸️' },
  { id: 'ai', label: 'AI assessment', icon: '🤖' },
]

export default function ResultsDashboard({
  analysis,
  onNewAnalysis,
}: {
  analysis: AnalysisDetail
  onNewAnalysis: () => void
}) {
  // Role-aware UI (P5b): hide actions the role cannot perform. The backend enforces the same rules.
  const { can } = useAuth()
  const canCreateCase = can('case:write')
  const [tab, setTab] = useState<Tab>('overview')
  const [caseInfo, setCaseInfo] = useState<InvestigationCase | null>(null)
  const [caseBusy, setCaseBusy] = useState(false)
  const [caseError, setCaseError] = useState<string | null>(null)
  const [integrity, setIntegrity] = useState<IntegrityResult | null>(null)
  const [integrityBusy, setIntegrityBusy] = useState(false)
  const [integrityError, setIntegrityError] = useState<string | null>(null)
  const [pdfBusy, setPdfBusy] = useState(false)
  const [pdfError, setPdfError] = useState<string | null>(null)
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [assessmentLoading, setAssessmentLoading] = useState(true)
  const [assessmentError, setAssessmentError] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState<string | null>(null)
  const [mlStatus, setMlStatus] = useState<MlStatus | null>(null)
  const [llmStatus, setLlmStatus] = useState<LlmStatus | null>(null)
  const [history, setHistory] = useState<AssessmentSummary[]>([])
  const [elapsed, setElapsed] = useState(0)
  const [intelRun, setIntelRun] = useState<ThreatIntelRun | null>(null)
  const [intelStatus, setIntelStatus] = useState<IntelServiceStatus | null>(null)
  const [intelLoading, setIntelLoading] = useState(true)
  const [intelError, setIntelError] = useState<string | null>(null)
  const [intelRunning, setIntelRunning] = useState(false)
  const [intelRunError, setIntelRunError] = useState<string | null>(null)

  // Real elapsed time while a generation request is open (no invented progress).
  useEffect(() => {
    if (!generating) return
    setElapsed(0)
    const t0 = Date.now()
    const timer = window.setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 1000)
    return () => window.clearInterval(timer)
  }, [generating])

  const refreshHistory = useCallback(
    (signal?: AbortSignal) =>
      listAssessments(analysis.id, signal)
        .then(setHistory)
        .catch(() => setHistory([])),
    [analysis.id],
  )

  // One stored assessment feeds the AI tab, the overview card and the PDF.
  useEffect(() => {
    const ctl = new AbortController()
    setAssessment(null)
    setAssessmentError(null)
    setAssessmentLoading(true)
    getAssessment(analysis.id, ctl.signal)
      .then(setAssessment)
      .catch((err) => {
        if (!(err instanceof DOMException && err.name === 'AbortError'))
          setAssessmentError(err instanceof Error ? err.message : 'request failed')
      })
      .finally(() => setAssessmentLoading(false))
    void refreshHistory(ctl.signal)
    if (can('ml:status')) getMlStatus(ctl.signal).then(setMlStatus).catch(() => setMlStatus(null))
    if (can('config:status')) getLlmStatus(ctl.signal).then(setLlmStatus).catch(() => setLlmStatus(null))
    return () => ctl.abort()
  }, [analysis.id, refreshHistory, can])

  // An existing investigation case for this analysis (so viewers can download its PDF).
  useEffect(() => {
    const ctl = new AbortController()
    setCaseInfo(null)
    if (can('case:read'))
      listInvestigations(ctl.signal)
        .then((cases) => {
          const found = cases.find((c) => (c.analyses ?? []).some((a) => a.analysis_id === analysis.id))
          if (found) setCaseInfo(found)
        })
        .catch(() => undefined)
    return () => ctl.abort()
  }, [analysis.id, can])

  // Stored threat-intel run (P5a): loading it never triggers a lookup.
  useEffect(() => {
    const ctl = new AbortController()
    setIntelRun(null)
    setIntelError(null)
    setIntelLoading(true)
    getThreatIntel(analysis.id, ctl.signal)
      .then(setIntelRun)
      .catch((err) => {
        if (!(err instanceof DOMException && err.name === 'AbortError'))
          setIntelError(err instanceof Error ? err.message : 'request failed')
      })
      .finally(() => setIntelLoading(false))
    if (can('config:status')) getIntelStatus(ctl.signal).then(setIntelStatus).catch(() => setIntelStatus(null))
    return () => ctl.abort()
  }, [analysis.id, can])

  const intelInFlight = useRef(false)
  const handleRunIntel = useCallback(
    async (consent: boolean) => {
      if (intelInFlight.current) return // one run at a time; the backend also refuses duplicates (409)
      intelInFlight.current = true
      setIntelRunning(true)
      setIntelRunError(null)
      try {
        setIntelRun(await runThreatIntel(analysis.id, { consent, source: 'on_demand' }))
        setIntelError(null)
      } catch (err) {
        if (err instanceof ApiError && err.code === 'INTEL_IN_PROGRESS')
          setIntelRunError('A threat-intel lookup for this analysis is already running. Wait for it to finish.')
        else if (err instanceof ApiError && err.status === 0)
          setIntelRunError('The backend could not be reached. The analysis is unaffected; try again when it is running.')
        else setIntelRunError(err instanceof Error ? err.message : 'Threat-intel lookup failed.')
      } finally {
        intelInFlight.current = false
        setIntelRunning(false)
      }
    },
    [analysis.id],
  )

  // Synchronous guard: React state is not updated between clicks fired in the same
  // task, so a ref (not `generating`) decides whether a request is already open.
  const inFlight = useRef(false)
  const handleGenerate = useCallback(async () => {
    if (inFlight.current) return // one request at a time; the backend also refuses duplicates (409)
    inFlight.current = true
    setGenerating(true)
    setGenerateError(null)
    try {
      setAssessment(await generateAssessment(analysis.id))
      setAssessmentError(null)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'ASSESSMENT_IN_PROGRESS')
        setGenerateError('An assessment for this analysis is already being generated. Wait for it to finish, then reload this tab.')
      else if (err instanceof ApiError && err.status === 0)
        setGenerateError('The backend could not be reached. The rule-based analysis is unaffected; try again when it is running.')
      else setGenerateError(err instanceof Error ? err.message : 'Generation failed.')
    } finally {
      inFlight.current = false
      setGenerating(false)
      void refreshHistory()
    }
  }, [analysis.id, refreshHistory])

  const handleSelectVersion = useCallback(
    async (assessmentId: string) => {
      setAssessmentError(null)
      try {
        setAssessment(await getAssessmentVersion(analysis.id, assessmentId))
      } catch (err) {
        setAssessmentError(err instanceof Error ? err.message : 'Could not load that version.')
      }
    },
    [analysis.id],
  )

  async function ensureCase(): Promise<InvestigationCase> {
    if (caseInfo) return caseInfo
    if (!canCreateCase) {
      const msg = 'No investigation case exists for this analysis yet. An analyst must create one before the PDF can be generated.'
      setCaseError(msg)
      throw new Error(msg)
    }
    setCaseBusy(true)
    setCaseError(null)
    try {
      const created = await createInvestigation(analysis.id)
      setCaseInfo(created)
      return created
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Could not create an investigation case.'
      setCaseError(msg)
      throw err
    } finally {
      setCaseBusy(false)
    }
  }

  async function handleCreateCase() {
    setCaseError(null)
    try {
      await ensureCase()
    } catch { /* error shown */ }
  }

  async function handleDownloadPdf() {
    setPdfError(null)
    setPdfBusy(true)
    try {
      const c = await ensureCase()
      // the PDF prints exactly the assessment version shown in the AI tab
      // ...and the threat-intel run shown in the Threat intel tab, when one exists
      if (intelRun) await downloadReport(c.id, analysis.id, assessment?.assessment_id ?? null, intelRun.run_id)
      else await downloadReport(c.id, analysis.id, assessment?.assessment_id ?? null)
    } catch (err) {
      setPdfError(err instanceof Error ? err.message : 'Report download failed.')
    } finally {
      setPdfBusy(false)
    }
  }

  async function handleIntegrityCheck() {
    setIntegrityError(null)
    setIntegrityBusy(true)
    try {
      const c = await ensureCase()
      const res = await verifyIntegrity(c.id, analysis.id)
      setIntegrity(res)
    } catch (err) {
      setIntegrityError(err instanceof Error ? err.message : 'Integrity check failed.')
    } finally {
      setIntegrityBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-6xl">
      {/* header */}
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold text-gray-900">
            {analysis.subject || '(no subject)'}
          </h2>
          <p className="mt-0.5 text-xs text-gray-400 break-all">
            analysis {analysis.id.slice(0, 8)} · sha256 {analysis.sha256.slice(0, 16)}… ·{' '}
            {formatDate(analysis.created_at)}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {can('analysis:create') && (
            <button
              onClick={onNewAnalysis}
              className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-xs font-medium text-gray-700 hover:bg-gray-50"
            >
              + New analysis
            </button>
          )}
          <button
            onClick={handleDownloadPdf}
            disabled={pdfBusy || caseBusy || (!caseInfo && !canCreateCase)}
            title={!caseInfo && !canCreateCase ? 'No investigation case exists yet; an analyst must create one.' : undefined}
            className="rounded-lg bg-indigo-600 px-3 py-2 text-xs font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-gray-300"
          >
            {pdfBusy ? 'Preparing report…' : '⬇ Download forensic PDF'}
          </button>
        </div>
      </div>

      {(pdfError || caseError) && (
        <div className="mb-4">
          <ErrorAlert message={pdfError ?? caseError ?? ''} onDismiss={() => { setPdfError(null); setCaseError(null) }} />
        </div>
      )}

      {/* tabs (scrollable on mobile) */}
      <div className="mb-4 -mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
        <nav className="flex gap-1 rounded-lg bg-gray-100 p-1" aria-label="Result sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              aria-selected={tab === t.id}
              role="tab"
              className={`whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                tab === t.id ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-500 hover:text-gray-800'
              }`}
            >
              <span className="mr-1" aria-hidden>{t.icon}</span>
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      {tab === 'overview' && (
        <OverviewTab
          analysis={analysis}
          caseInfo={caseInfo}
          caseBusy={caseBusy}
          onCreateCase={handleCreateCase}
          canCreateCase={canCreateCase}
          canVerify={can('evidence:verify')}
          integrity={integrity}
          integrityBusy={integrityBusy}
          integrityError={integrityError}
          onIntegrityCheck={handleIntegrityCheck}
          assessmentCard={
            <AssessmentOverviewCard
              assessment={assessment}
              loading={assessmentLoading}
              onOpen={() => setTab('ai')}
            />
          }
        />
      )}
      {tab === 'findings' && <FindingsTab analysis={analysis} />}
      {tab === 'auth' && <AuthTab analysis={analysis} />}
      {tab === 'headers' && <HeadersTab analysis={analysis} />}
      {tab === 'intel' && <IntelTab analysis={analysis} />}
      {tab === 'threat' && (
        <ThreatIntelPanel
          run={intelRun}
          status={intelStatus}
          loading={intelLoading}
          error={intelError}
          running={intelRunning}
          runError={intelRunError}
          onRun={handleRunIntel}
          canRun={can('intel:run')}
          onDismissError={() => setIntelRunError(null)}
        />
      )}
      {tab === 'trace' && <TraceView analysis={analysis} />}
      {tab === 'ai' && (
        <AssessmentView
          assessment={assessment}
          loading={assessmentLoading}
          error={assessmentError}
          generating={generating}
          generateError={generateError}
          onGenerate={handleGenerate}
          canGenerate={can('assessment:run')}
          mlStatus={mlStatus}
          llmStatus={llmStatus}
          history={history}
          onSelectVersion={handleSelectVersion}
          elapsedSeconds={elapsed}
        />
      )}
    </div>
  )
}

// ── Overview ───────────────────────────────────────────────────────────────
function OverviewTab({
  analysis,
  caseInfo,
  caseBusy,
  onCreateCase,
  canCreateCase = true,
  canVerify = true,
  integrity,
  integrityBusy,
  integrityError,
  onIntegrityCheck,
  assessmentCard,
}: {
  analysis: AnalysisDetail
  caseInfo: InvestigationCase | null
  caseBusy: boolean
  onCreateCase: () => void
  canCreateCase?: boolean
  canVerify?: boolean
  integrity: IntegrityResult | null
  integrityBusy: boolean
  integrityError: string | null
  onIntegrityCheck: () => void
  assessmentCard: ReactNode
}) {
  const d = analysis.detection
  const f = analysis.forensics
  const score = d.score

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        <Panel title="Verdict">
          <ScoreBadge score={score} verdict={d.verdict} />
          <div className="mt-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">
              Evidence supporting this score
            </h3>
            {d.findings.length === 0 ? (
              <p className="mt-1 text-sm text-gray-400">
                No risk indicators fired — the score is 0 with no supporting findings.
              </p>
            ) : (
              <ul className="mt-2 space-y-1.5">
                {d.findings.map((fdt) => (
                  <li key={fdt.rule_id} className="flex flex-wrap items-center gap-2 text-sm">
                    <SeverityChip severity={fdt.severity} />
                    <span className="text-gray-800">{fdt.title}</span>
                    <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] font-medium text-gray-600">
                      +{fdt.contribution} pts
                    </span>
                    <StatusBadge
                      kind={fdt.knowledge === 'fact' ? 'verified' : 'inferred'}
                      title={fdt.knowledge === 'fact'
                        ? 'Directly observed in the message bytes'
                        : 'Heuristic judgement from the detection rules'}
                    />
                  </li>
                ))}
              </ul>
            )}
            {d.unknowns.length > 0 && (
              <div className="mt-3 rounded-md bg-gray-50 px-3 py-2">
                <p className="text-xs font-semibold text-gray-500">Data that could not be evaluated</p>
                <ul className="mt-1 space-y-0.5 text-xs text-gray-500">
                  {d.unknowns.map((u, i) => (
                    <li key={i}>
                      <span className="font-mono">{u.field}</span> — {u.reason}{' '}
                      <StatusBadge kind="unavailable" />
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Panel>

        <Panel title="Email metadata">
          <MetaRow label="From">
            {analysis.from ? (
              <>
                {analysis.from.display_name && <span className="font-medium">{analysis.from.display_name} </span>}
                <span className="font-mono">&lt;{analysis.from.email}&gt;</span>
              </>
            ) : (
              <span className="text-gray-400">not present</span>
            )}
          </MetaRow>
          <MetaRow label="To">
            {analysis.to.length > 0
              ? analysis.to.map((a, i) => <span key={i} className="mr-2 font-mono text-xs">{a.email}</span>)
              : <span className="text-gray-400">none</span>}
          </MetaRow>
          <MetaRow label="Reply-To">
            {analysis.reply_to.length > 0
              ? analysis.reply_to.map((a, i) => <span key={i} className="font-mono text-xs">{a.email}</span>)
              : <span className="text-gray-400">none (falls back to From)</span>}
          </MetaRow>
          <MetaRow label="Return-Path">
            {analysis.return_path ?? <span className="text-gray-400">not present</span>}
          </MetaRow>
          <MetaRow label="Date header">{analysis.date ?? <span className="text-gray-400">not present</span>}</MetaRow>
          <MetaRow label="Message-ID">{analysis.message_id ?? <span className="text-gray-400">not present</span>}</MetaRow>
          <MetaRow label="Received hops">{analysis.received_count}</MetaRow>
        </Panel>

        <IntelligenceDetailsPanel analysis={analysis} />
      </div>

      {/* side column */}
      <div className="space-y-4">
        {assessmentCard}
        <Panel title="Investigation case">
          {caseInfo ? (
            <>
              <MetaRow label="Case number">{caseInfo.case_number}</MetaRow>
              <MetaRow label="Status">{caseInfo.status}</MetaRow>
              <p className="mt-2 text-xs text-gray-400">
                Evidence policy: <strong>{caseInfo.evidence_policy.store_mode}</strong> — {caseInfo.evidence_policy.retention_days}-day retention documented{caseInfo.evidence_policy.key_required ? ', raw access key-gated' : ''}.
              </p>
            </>
          ) : (
            <>
              <p className="text-sm text-gray-500">
                Link this analysis to an open investigation case to enable the forensic PDF and
                integrity verification.
              </p>
              {canCreateCase ? (
                <button
                  onClick={onCreateCase}
                  disabled={caseBusy}
                  className="mt-2 inline-flex items-center gap-2 rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2 text-xs font-semibold text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
                >
                  {caseBusy ? <Spinner /> : '📁 Create investigation case'}
                </button>
              ) : (
                <p className="mt-2 text-xs text-gray-400">Your role can view cases but not create them.</p>
              )}
            </>
          )}
        </Panel>

        <Panel title="Evidence integrity">
          {integrityBusy ? (
            <Spinner label="Recomputing SHA-256 over stored bytes…" />
          ) : integrityError ? (
            <ErrorAlert message={integrityError} />
          ) : (
            <>
              {integrity ? (
                <div>
                  <div className="flex items-center gap-2">
                    <StatusBadge
                      kind={integrity.result === 'match' ? 'match' : integrity.result === 'mismatch' ? 'mismatch' : 'unavailable'}
                    />
                    <span className="text-sm text-gray-700 capitalize">{integrity.result}</span>
                  </div>
                  <p className="mt-1 text-xs text-gray-500">{integrity.detail || 'Integrity recomputed over retained raw bytes.'}</p>
                  <p className="mt-1 font-mono text-[11px] break-all text-gray-400">recorded {integrity.sha256_recorded}</p>
                </div>
              ) : (
                <p className="text-sm text-gray-500">
                  {caseInfo
                    ? 'Recompute SHA-256 over the retained bytes and compare with the recorded hash.'
                    : 'Create an investigation case first to enable integrity verification.'}
                </p>
              )}
              {canVerify && (
                <button
                  onClick={onIntegrityCheck}
                  disabled={caseBusy || integrityBusy || !caseInfo}
                  className="mt-2 rounded-lg border border-gray-300 bg-white px-3 py-2 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  Run integrity check
                </button>
              )}
            </>
          )}
        </Panel>

        <Panel title="Quick facts">
          <MetaRow label="Score">{score} / 100 <span className="text-gray-400">(heuristic)</span></MetaRow>
          <MetaRow label="Findings">{d.findings.length}</MetaRow>
          <MetaRow label="Relay hops">{f.relay_chain.length}</MetaRow>
          <MetaRow label="URLs">{analysis.urls.length}</MetaRow>
          <MetaRow label="Attachments">{analysis.attachments.length}</MetaRow>
          <MetaRow label="Size">{formatBytes(analysis.size_bytes)}</MetaRow>
          <MetaRow label="Parse defects">
            {analysis.parse_defects.length > 0 ? (
              <span className="text-amber-700">{analysis.parse_defects.join(', ')}</span>
            ) : (
              'none'
            )}
          </MetaRow>
        </Panel>
      </div>
    </div>
  )
}

// ── Findings ───────────────────────────────────────────────────────────────
function FindingsTab({ analysis }: { analysis: AnalysisDetail }) {
  const d = analysis.detection
  return (
    <div className="space-y-4">
      <Panel
        title="Risk indicators"
        status={
          d.findings.length > 0 ? (
            <span className="text-xs text-gray-400">{d.findings.length} contributing to score {d.score}</span>
          ) : undefined
        }
      >
        {d.findings.length === 0 ? (
          <div className="space-y-3">
            <p className="text-sm text-gray-500">
              No risk indicators fired for this message. Absence of findings reflects the rules
              that ran, not a guarantee of safety.
            </p>
          </div>
        ) : (
          <ul className="space-y-3">
            {d.findings.map((fdt) => (
              <li
                key={fdt.rule_id}
                className="rounded-lg border border-gray-200 p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip severity={fdt.severity} />
                  <span className="font-medium text-gray-900">{fdt.title}</span>
                  <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] font-medium text-gray-600">
                    +{fdt.contribution}/{fdt.weight} pts
                  </span>
                  <span className="ml-auto">
                    <StatusBadge
                      kind={fdt.knowledge === 'fact' ? 'verified' : 'inferred'}
                      title={fdt.knowledge === 'fact'
                        ? 'OBSERVED FACT — directly provable from message bytes'
                        : 'HEURISTIC — a judgement call, not a proven fact'}
                    />
                  </span>
                </div>
                <dl className="mt-3 space-y-1.5 text-sm">
                  <div>
                    <dt className="text-xs font-semibold uppercase tracking-wide text-gray-400">Evidence</dt>
                    <dd className="text-gray-800">{fdt.evidence}</dd>
                  </div>
                  <div>
                    <dt className="text-xs font-semibold uppercase tracking-wide text-gray-400">Why it matters</dt>
                    <dd className="text-gray-600">{fdt.rationale}</dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Observed facts (no points added)">
        {d.observed_facts.length === 0 ? (
          <EmptyStateInline icon="ℹ️" text="No neutral observations were recorded for this message." />
        ) : (
          <ul className="list-disc space-y-1 pl-5 text-sm text-gray-700">
            {d.observed_facts.map((fact, i) => (
              <li key={i}>{fact}</li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

// ── Authentication ─────────────────────────────────────────────────────────
function AuthTab({ analysis }: { analysis: AnalysisDetail }) {
  const a = analysis.authentication
  const protos = [a.spf, a.dkim, a.dmarc]

  return (
    <div className="space-y-4">
      <Panel title="Authentication results — claimed vs. independently verified">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead>
              <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-400">
                <th className="pb-2 pr-3">Protocol</th>
                <th className="pb-2 pr-3">Independent check <span className="normal-case text-gray-300">(verified)</span></th>
                <th className="pb-2 pr-3">Header claim</th>
                <th className="pb-2">Reason</th>
              </tr>
            </thead>
            <tbody>
              {protos.map((p) => {
                const claimPass = p.claims.some((c) => c.toLowerCase().includes('pass'))
                const claimFail = p.claims.some((c) => c.toLowerCase().includes('fail'))
                const claimLabel = claimPass ? 'pass' : claimFail ? 'fail' : null
                const mismatch =
                  claimLabel !== null &&
                  ((claimPass && p.status === 'verified_fail') ||
                    (claimFail && p.status === 'verified_pass'))
                return (
                  <tr key={p.protocol} className="border-b border-gray-100 align-top last:border-0">
                    <td className="py-3 pr-3 font-semibold uppercase text-gray-800">{p.protocol}</td>
                    <td className="py-3 pr-3">
                      <StatusBadge kind={classifyStatus(p.status)} />
                    </td>
                    <td className="py-3 pr-3">
                      {p.claims.length > 0 ? (
                        <div className="flex flex-wrap items-center gap-1">
                          <span className="font-mono text-xs text-gray-600">{p.claims.join(', ')}</span>
                          <StatusBadge kind="claimed" />
                        </div>
                      ) : (
                        <StatusBadge kind="unknown" title="No claim present in the Authentication-Results header" />
                      )}
                    </td>
                    <td className="py-3 text-xs text-gray-500">
                      {misMatchNote(p, mismatch)}
                      <div className="mt-1 block max-w-md break-words">{p.reason ?? ''}</div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-gray-400">
          Claims come from the email&apos;s own <code>Authentication-Results</code> header (which a
          sender can forge). “Verified” results are re-derived by this backend&apos;s independent
          DNS checks.
        </p>
      </Panel>

      <Panel title="Alignment">
        <div className="grid gap-2 sm:grid-cols-3">
          {Object.entries(a.alignment).length === 0 ? (
            <p className="text-sm text-gray-400 sm:col-span-3">No alignment data was computed.</p>
          ) : (
            Object.entries(a.alignment).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-2">
                <span className="text-xs font-semibold uppercase text-gray-600">{k}</span>
                <StatusBadge kind={v === 'aligned' ? 'verified' : 'inferred'} title={v} />
                <span className="text-xs text-gray-500">{v}</span>
              </div>
            ))
          )}
        </div>
      </Panel>

      <Panel title="Raw Authentication-Results header lines (observed facts)">
        {analysis.authentication_results.length === 0 ? (
          <EmptyStateInline icon="ℹ️" text="No Authentication-Results headers present in the message." />
        ) : (
          <ul className="space-y-1 text-xs">
            {analysis.authentication_results.map((line, i) => (
              <li key={i} className="font-mono break-all rounded bg-gray-50 px-2 py-1 text-gray-700">
                {line}
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

function misMatchNote(p: { status: string; claims: string[] }, mismatch: boolean) {
  if (mismatch) {
    return (
      <span className="rounded bg-red-50 px-1.5 py-0.5 text-[11px] font-medium text-red-700">
        header claim conflicts with verification
      </span>
    )
  }
  if (p.status.startsWith('verified_') && p.claims.length === 0) {
    return <span className="text-[11px] text-gray-400">no header claim to compare</span>
  }
  return null
}

// ── Headers / intel tabs ───────────────────────────────────────────────────
function HeadersTab({ analysis }: { analysis: AnalysisDetail }) {
  return (
    <div className="space-y-4">
      <HeaderForensicsPanel data={analysis.forensics} />
      <AnomaliesPanel data={analysis.forensics} />
      <Panel title="Full header counts (observed facts)">
        {Object.keys(analysis.header_counts).length === 0 ? (
          <EmptyStateInline icon="ℹ️" text="No headers were counted." />
        ) : (
          <div className="flex flex-wrap gap-2">
            {Object.entries(analysis.header_counts).map(([k, v]) => (
              <span key={k} className="rounded bg-gray-100 px-2 py-1 text-xs font-mono text-gray-700">
                {k}: {v}
              </span>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}

function IntelTab({ analysis }: { analysis: AnalysisDetail }) {
  const enr = analysis.enrichment

  return (
    <div className="space-y-4">
      <Panel
        title="IP & domain intelligence"
        status={
          enr.results.length > 0 ? (
            <span className="text-xs text-gray-400">{enr.results.length} lookups</span>
          ) : undefined
        }
      >
        {enr.degraded.length > 0 && (
          <div className="mb-3 rounded-md bg-orange-50 px-3 py-2 text-xs text-orange-800">
            Some providers were unavailable and skipped: {enr.degraded.join(', ')}
          </div>
        )}
        {enr.results.length === 0 ? (
          <EmptyStateInline
            icon="🌐"
            text={
              enr.degraded.length > 0
                ? 'No enrichment data was returned — required providers were unavailable.'
                : 'No external lookups ran for this message (no public candidate IPs or domains to enrich, or enrichment disabled).'
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase tracking-wide text-gray-400">
                  <th className="pb-2 pr-3">Indicator</th>
                  <th className="pb-2 pr-3">Provider</th>
                  <th className="pb-2 pr-3">Status</th>
                  <th className="pb-2 pr-3">Latency</th>
                  <th className="pb-2">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {enr.results.map((r, i) => (
                  <tr key={i} className="border-b border-gray-100 align-top last:border-0">
                    <td className="py-2.5 pr-3 font-mono text-xs break-all text-gray-800">
                      {r.ioc.ioc_value ?? JSON.stringify(r.ioc)}
                    </td>
                    <td className="py-2.5 pr-3 text-xs text-gray-600">{r.provider}</td>
                    <td className="py-2.5 pr-3"><StatusBadge kind={classifyStatus(r.status)} /></td>
                    <td className="py-2.5 pr-3 text-xs text-gray-500">{r.latency_ms} ms</td>
                    <td className="py-2.5 text-xs text-gray-500">
                      <EvidenceSummary evidence={r.evidence} />
                      <div className="mt-0.5 font-mono text-[11px] text-gray-300">{r.provenance}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs italic text-gray-400">
          External intelligence is an investigative indicator. It is not proof of who sent the
          message or where they are located.
        </p>
      </Panel>

      <IntelTabInner analysis={analysis} />
    </div>
  )
}

function EvidenceSummary({ evidence }: { evidence: Record<string, unknown> }) {
  if (evidence == null || Object.keys(evidence).length === 0) {
    return <span className="text-gray-400">no evidence returned</span>
  }
  const records = (evidence as { records?: Record<string, unknown> }).records
  if (records && typeof records === 'object') {
    return (
      <ul className="list-disc pl-4">
        {Object.entries(records as Record<string, unknown>).map(([k, v]) => (
          <li key={k}>
            <span className="font-mono">{k}</span>: {JSON.stringify(v)}
          </li>
        ))}
      </ul>
    )
  }
  return <span className="break-all">{JSON.stringify(evidence)}</span>
}

function IntelTabInner({ analysis }: { analysis: AnalysisDetail }) {
  return <IntelligenceDetailsPanel analysis={analysis} />
}

function EmptyStateInline({ icon, text }: { icon: string; text: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
      <span className="text-xl text-gray-400" aria-hidden>{icon}</span>
      <span>{text}</span>
    </div>
  )
}
