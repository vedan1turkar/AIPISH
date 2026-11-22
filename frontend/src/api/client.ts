// API client for the FastAPI backend.
//
// Base URL: configured backend URL. In dev, leave VITE_API_BASE empty and the
// Vite proxy forwards /api → FastAPI :8000. For other deployments set
// VITE_API_BASE to the absolute backend origin (e.g. http://127.0.0.1:8000).
import { clearSession, getToken, type SessionUser } from '../auth/session'

const RAW_BASE: string = import.meta.env.VITE_API_BASE ?? ''
export const API_BASE: string = RAW_BASE.replace(/\/+$/, '')

// ── Error envelope ──────────────────────────────────────────────────────────
export interface ApiErrorBody {
  error: { code: string; message: string; request_id?: string }
}

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

const LOGIN_PATH = '/api/v1/auth/login'

/** Every request goes through here: attaches the bearer token, and on 401 clears the session (→ login page). */
async function authedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  const token = getToken()
  if (token && path !== LOGIN_PATH) headers.set('Authorization', `Bearer ${token}`)
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, headers })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the analysis backend. Is it running?')
  }
  if (res.status === 401 && path !== LOGIN_PATH) {
    let code = ''
    try {
      code = ((await res.clone().json()) as ApiErrorBody).error?.code ?? ''
    } catch {
      /* ignore */
    }
    clearSession(
      code === 'TOKEN_EXPIRED' ? 'Your session expired. Sign in again.'
        : code === 'NOT_AUTHENTICATED' ? 'Sign in to continue.'
          : 'Your session is no longer valid. Sign in again.',
    )
  }
  return res
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await authedFetch(path, init)
  if (!res.ok) {
    let code = `HTTP_${res.status}`
    let message = `Request failed (HTTP ${res.status})`
    try {
      // FastAPI uniforms use {error:{code,message}}; plain HTTPException uses {detail}
      const body = (await res.json()) as
        | ApiErrorBody
        | { detail: { code: string; message: string } }
        | { detail: string }
      if ('error' in body && body.error?.message) {
        code = body.error.code
        message = body.error.message
      } else if (
        'detail' in body &&
        typeof body.detail === 'object' &&
        body.detail !== null &&
        'message' in body.detail
      ) {
        code = body.detail.code
        message = body.detail.message
      } else if ('detail' in body && typeof body.detail === 'string') {
        message = body.detail
      }
      code = String(code)
      message = String(message)
    } catch {
      /* non-JSON error body — keep generic text */
    }
    throw new ApiError(res.status, code, message)
  }
  return (await res.json()) as T
}

// ── Health ──────────────────────────────────────────────────────────────────
// P5g: anonymous liveness carries only the status; version / environment come from /system/info.
export interface HealthResponse {
  status: string
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>(`/api/v1/health`, { signal })
}

/** Readiness: {"status":"ok"} (200) or {"status":"unavailable"} (503, surfaced as an ApiError). */
export async function getReady(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>(`/api/v1/health/ready`, { signal })
}

export interface SystemInfo {
  version: string
  environment: string
  database: string
  schema_version: number
  db_connected: boolean
}

export async function getSystemInfo(signal?: AbortSignal): Promise<SystemInfo> {
  return request<SystemInfo>(`/api/v1/system/info`, { signal })
}

// ── Analyses ────────────────────────────────────────────────────────────────
export interface Address {
  display_name: string
  email: string
  domain: string
}

export interface UrlRecord {
  url: string
  host: string
  scheme: string
  in_html: boolean
  in_text: boolean
}

export interface AttachmentRecord {
  filename: string
  content_type: string
  size_bytes: number
  sha256: string
  is_inline: boolean
  content_id: string | null
}

export interface Finding {
  rule_id: string
  severity: 'low' | 'medium' | 'high' | string
  weight: number
  contribution: number
  knowledge: 'fact' | 'heuristic' | string
  title: string
  evidence: string
  rationale: string
}

export interface UnknownField {
  field: string
  reason: string
}

export interface Detection {
  score: number
  verdict: string
  findings: Finding[]
  unknowns: UnknownField[]
  observed_facts: string[]
}

export interface Inconsistency {
  rule_id: string
  severity: string
  evidence: string
  rationale: string
}

export interface ChainHop {
  index: number
  from_host: string | null
  from_ip: string | null
  from_ip_category: string | null
  by_host: string | null
  protocol: string | null
  tls: boolean
  timestamp: string | null
  trusted: boolean
  confidence: number
  confidence_reasons: string[]
  notes: string[]
}

export interface Forensics {
  relay_chain: ChainHop[]
  trusted_boundary_index: number | null
  candidate_ips: string[]
  earliest_candidate_ip: string | null
  verified_originating_ip: string | null
  inconsistencies: Inconsistency[]
  confidence_rules: string[]
  forgery_note: string
  disclaimer: string
}

export interface AuthStatus {
  protocol: string
  status: string
  claims: string[]
  reason: string | null
  detail: Record<string, unknown>
}

export interface Authentication {
  spf: AuthStatus
  dkim: AuthStatus
  dmarc: AuthStatus
  alignment: Record<string, string>
  status_legend: Record<string, string>
}

export interface EnrichmentRecord {
  provider: string
  ioc: { ioc_value?: string; ioc_kind?: string; [k: string]: unknown }
  status: string
  latency_ms: number
  evidence: Record<string, unknown>
  provenance: string
}

export interface Enrichment {
  results: EnrichmentRecord[]
  degraded: string[]
}

export interface AnalysisSummary {
  id: string
  created_at: string
  sha256: string
  size_bytes: number
  subject: string | null
  sender: Address | null
  received_count: number
  url_count: number
  attachment_count: number
  detection_score: number
  detection_verdict: string | null
  has_defects: boolean
  retention_state?: RetentionState         // P5e
  legal_hold?: boolean
  pii_masked?: boolean
  combined_level?: RiskLevel | null        // P5h: latest combined risk (additional result)
  combined_score?: number | null
  combined_confidence?: RiskConfidence | null
}

/** P5e retention state of an analysis. */
export type RetentionState = null | 'evidence_purged' | 'redacted'

export interface AnalysisDetail {
  id: string
  created_at: string
  sha256: string
  size_bytes: number
  subject: string | null
  from: Address | null
  to: Address[]
  cc: Address[]
  reply_to: Address[]
  return_path: string | null
  date: string | null
  message_id: string | null
  received_count: number
  authentication_results: string[]
  dkim_signature_count: number
  has_html_body: boolean
  body_text: string | null
  urls: UrlRecord[]
  attachments: AttachmentRecord[]
  header_counts: Record<string, number>
  detection: Detection
  forensics: Forensics
  authentication: Authentication
  enrichment: Enrichment
  parse_defects: string[]
  // P5e: retention + masking flags (masking is applied server-side for roles without pii:view)
  retention_state?: RetentionState
  redacted_at?: string | null
  legal_hold?: boolean
  redaction_note?: string | null
  pii_masked?: boolean
  body_restricted?: boolean
}

export async function uploadEml(
  file: File,
  signal?: AbortSignal,
): Promise<AnalysisDetail> {
  const form = new FormData()
  form.append('file', file, file.name)
  return request<AnalysisDetail>(`/api/v1/analyses`, {
    method: 'POST',
    body: form,
    signal,
  })
}

export async function listAnalyses(signal?: AbortSignal): Promise<AnalysisSummary[]> {
  return request<AnalysisSummary[]>(`/api/v1/analyses`, { signal })
}

export async function getAnalysis(id: string, signal?: AbortSignal): Promise<AnalysisDetail> {
  return request<AnalysisDetail>(`/api/v1/analyses/${encodeURIComponent(id)}`, { signal })
}

// ── Investigations (cases) ─────────────────────────────────────────────────
export interface CaseAnalysisRow {
  retention_state?: RetentionState         // P5e
  legal_hold?: boolean
  analysis_id: string
  sha256: string
  size_bytes: number
  subject: string | null
  from_domain: string | null
  threat_score: number
  verdict: string | null
  authentication_status: { spf: string; dkim: string; dmarc: string }
  relay_summary: {
    hops: number
    earliest_candidate_ip: string | null
    verified_originating_ip: string | null
  }
  enrichment: { providers_run: number | null; degraded: unknown[] }
  findings_count: number
  added_at: string
}

export interface InvestigationCase {
  id: string
  case_number: string
  title: string | null
  status: string
  created_at: string
  evidence_policy: { store_mode: string; key_required: boolean; retention_days: number; note: string }
  analyses: CaseAnalysisRow[]
  legal_hold?: boolean                     // P5e
}

export async function createInvestigation(analysisId: string): Promise<InvestigationCase> {
  return request<InvestigationCase>(`/api/v1/investigations/from-analysis/${encodeURIComponent(analysisId)}`, {
    method: 'POST',
  })
}

export async function listInvestigations(signal?: AbortSignal): Promise<InvestigationCase[]> {
  return request<InvestigationCase[]>(`/api/v1/investigations`, { signal })
}

export async function getInvestigation(id: string, signal?: AbortSignal): Promise<InvestigationCase> {
  return request<InvestigationCase>(`/api/v1/investigations/${encodeURIComponent(id)}`, { signal })
}

export interface IntegrityResult {
  analysis_id: string
  sha256_recorded: string
  result: 'match' | 'mismatch' | 'unavailable' | string
  detail: string
  policy: { store_mode: string; key_required: boolean; retention_days: number; note: string }
}

export async function verifyIntegrity(
  caseId: string,
  analysisId: string,
): Promise<IntegrityResult> {
  return request<IntegrityResult>(
    `/api/v1/investigations/${encodeURIComponent(caseId)}/evidence-integrity/${encodeURIComponent(analysisId)}`,
    { method: 'POST' },
  )
}

// ── PDF report ─────────────────────────────────────────────────────────────
/** Download the PDF. `assessmentId` / `intelRunId` pin the AI-assessment and threat-intel versions printed in it. */
export async function downloadReport(
  caseId: string,
  analysisId: string,
  assessmentId?: string | null,
  intelRunId?: string | null,
  attackId?: string | null,
  riskId?: string | null,
): Promise<void> {
  const params = new URLSearchParams()
  if (assessmentId) params.set('assessment_id', assessmentId)
  if (intelRunId) params.set('intel_run_id', intelRunId)
  if (attackId) params.set('attack_id', attackId)
  if (riskId) params.set('risk_id', riskId)
  const q = params.toString() ? `?${params.toString()}` : ''
  // Authenticated fetch → blob → download (a bare link could not carry the bearer token).
  const res = await authedFetch(
    `/api/v1/investigations/${encodeURIComponent(caseId)}/report/${encodeURIComponent(analysisId)}${q}`,
  )
  if (!res.ok) {
    let code = `HTTP_${res.status}`
    let message = `Report download failed (HTTP ${res.status})`
    try {
      const body = (await res.json()) as ApiErrorBody | { detail: { code: string; message: string } }
      if ('error' in body && body.error?.message) {
        code = body.error.code
        message = body.error.message
      } else if ('detail' in body && typeof body.detail === 'object' && body.detail?.message) {
        code = body.detail.code
        message = body.detail.message
      }
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, code, message)
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `forensic-report-${caseId.slice(0, 8)}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

// ── ML classification, SHAP and local-LLM assessment (P4) ──────────────────
// Shapes mirror the backend exactly (app/ml/inference.py, app/ml/explain.py,
// app/llm/service.py, app/api/llm_router.py). Most fields are optional because
// failure responses carry only {status, reason}; the UI never fills them in.
export type ComponentStatus =
  | 'ok'
  | 'unavailable'
  | 'timeout'
  | 'invalid_output'
  | 'error'
  | 'not_applicable'
  | string

export interface MlResult {
  status: ComponentStatus
  reused_from_assessment?: string
  label?: string | null
  confidence?: number | null
  probabilities?: Record<string, number>
  components?: Record<string, Record<string, number>>
  model_version?: string | null
  untrained_classes?: string[]
  reason?: string | null
}

export interface ShapContribution {
  feature: string
  group: string
  value?: number | string | null
  shap_value: number
  direction?: 'toward' | 'away' | string
  detail?: string
}

export interface ShapComponent {
  explainer: string
  output_space: string
  base_value: number
  output_value: number
  additivity_ok: boolean
  top_contributions: ShapContribution[]
  aggregated: ShapContribution[]
  ensemble_weight?: number
  background?: string
  redaction?: { withheld_terms: number; min_training_doc_freq: number }
}

export interface ShapExplanation {
  status: ComponentStatus
  method?: string
  shap_version?: string
  explained_label?: string
  model_version?: string
  components?: Record<string, ShapComponent>
  not_explained?: { component: string; reason: string }[]
  disclaimer?: string
  reason?: string | null
}

export interface EvidenceItem {
  id: string
  category: 'verified' | 'provider' | 'heuristic' | 'claimed' | 'model' | string
  source: string
  statement: string
}

export interface Recommendation {
  text: string
  kind: 'evidence_linked' | 'general' | string
  /** P4.2: 'system' (general template) | 'system_template' (evidence-linked template); P4.1: 'model' */
  origin: 'model' | 'system' | 'system_template' | string
  evidence_ids: string[]
  artefacts?: string[]
  category?: string
  model_suggestions?: string[]
  also_suggested_by_model?: boolean
}

export interface FinancialContext {
  detected: boolean
  evidence_signals: { evidence_id: string; term: string }[]
  email_text_terms: string[]
  ml_label_fraud: boolean
  warning: string | null
}

export interface SummaryFinding {
  statement: string
  evidence_ids: string[]
  evidence_categories?: string[]
  basis: 'verified' | 'inferred' | string
}

export interface ForensicSummary {
  status: ComponentStatus
  ai_generated?: boolean
  label?: string
  model?: { provider: string; name: string; digest: string | null; local: boolean }
  summary?: string | null
  assessment?: string | null
  findings?: SummaryFinding[]
  rejected_findings?: { statement: string; reason: string }[]
  recommended_actions?: string[]
  /** P4.1: grounded recommendations; absent on assessments generated before P4.1 */
  recommendations?: Recommendation[]
  rejected_recommendations?: { text: string; reason: string; category?: string | null }[]
  /** P4.2 deterministic payment/bank/invoice/supplier context; present even when the LLM failed */
  financial_context?: FinancialContext
  recommendation_policy?: string
  limitations?: string[]
  validation?: {
    summary_accepted: boolean
    assessment_accepted: boolean
    findings_accepted: number
    findings_rejected: number
    basis_downgraded: number
    flags: { field: string; problems: string[]; text?: string }[]
  } | null
  evidence?: EvidenceItem[]
  unavailable_information?: { check: string; reason: string }[]
  system_verdicts?: {
    rules?: { score: number; verdict: string }
    ml?: { label: string; confidence: number; model_version: string }
  }
  security?: {
    injection_patterns_detected: string[]
    redactions: Record<string, number>
    body_chars_sent: number
    endpoint_local_only: boolean
  }
  reason?: string | null
  attempts?: number
  latency_ms?: number
}

export interface Assessment {
  analysis_id: string
  /** P4.1 versioned history; absent on responses from older backends */
  assessment_id?: string
  version?: number
  source?: 'upload' | 'stored_analysis' | string
  generated_at?: string | null
  ml: MlResult | null
  explanation: ShapExplanation | null
  forensic_summary: ForensicSummary | null
}

export interface MlStatus {
  status: ComponentStatus
  reason?: string
  model_version?: string
  trained_classes?: string[]
  untrained_classes?: string[]
  components?: string[]
  ensemble_weights?: Record<string, number>
}

export interface LlmStatus {
  status: ComponentStatus
  reason?: string
  model?: string
  digest?: string
  local_only?: boolean
  timeout_seconds?: number
}

export async function getMlStatus(signal?: AbortSignal): Promise<MlStatus> {
  return request<MlStatus>(`/api/v1/ml/status`, { signal })
}

export async function getLlmStatus(signal?: AbortSignal): Promise<LlmStatus> {
  return request<LlmStatus>(`/api/v1/llm/status`, { signal })
}

/** Stored assessment, or null when it has never been generated for this analysis. */
export async function getAssessment(id: string, signal?: AbortSignal): Promise<Assessment | null> {
  try {
    return await request<Assessment>(`/api/v1/analyses/${encodeURIComponent(id)}/assessment`, { signal })
  } catch (err) {
    if (err instanceof ApiError && err.status === 404 && err.code === 'ASSESSMENT_NOT_GENERATED') return null
    throw err
  }
}

/** (Re)generate for a stored analysis. ML/SHAP need retained bytes (see hash_only). */
export async function generateAssessment(id: string, signal?: AbortSignal): Promise<Assessment> {
  return request<Assessment>(`/api/v1/analyses/${encodeURIComponent(id)}/forensic-summary`, {
    method: 'POST',
    signal,
  })
}

/** Upload + full analysis + ML/SHAP on the in-memory bytes + local-LLM summary. */
export async function uploadEmlWithAssessment(file: File, signal?: AbortSignal): Promise<Assessment> {
  const form = new FormData()
  form.append('file', file, file.name)
  return request<Assessment>(`/api/v1/llm/forensic-summary`, { method: 'POST', body: form, signal })
}

export interface AssessmentSummary {
  assessment_id: string
  version: number
  source: string
  generated_at: string | null
  ml_status: string | null
  ml_label: string | null
  summary_status: string | null
}

export async function listAssessments(id: string, signal?: AbortSignal): Promise<AssessmentSummary[]> {
  return request<AssessmentSummary[]>(`/api/v1/analyses/${encodeURIComponent(id)}/assessments`, { signal })
}

export async function getAssessmentVersion(id: string, assessmentId: string, signal?: AbortSignal): Promise<Assessment> {
  return request<Assessment>(
    `/api/v1/analyses/${encodeURIComponent(id)}/assessments/${encodeURIComponent(assessmentId)}`,
    { signal },
  )
}

// ── Threat intelligence (P5a) ───────────────────────────────────────────────
export type IntelStatus =
  | 'malicious_or_flagged'
  | 'reported_clean_no_flags'
  | 'record_found'
  | 'no_record'
  | 'provider_error'
  | 'rate_limited'
  | 'auth_failed'
  | 'timeout'
  | 'malformed_response'
  | 'not_permitted'
  | 'not_attempted_consent_disabled'
  | 'not_attempted_offline'
  | 'not_attempted_cap_reached'
  | 'missing_credentials'
  | 'not_applicable_indicator'
  | 'quota_exhausted'

export interface IntelResult {
  provider: string
  provider_label: string
  indicator: string
  indicator_type: string
  status: IntelStatus | string
  fetched_at: string | null
  expires_at: string | null
  cache_state: 'fresh' | 'stale' | 'none' | string
  source: string
  data: Record<string, unknown>
  error_code: string | null
  message: string
  cache_age_seconds: number | null
  retry_after_seconds: number | null
}

export interface IntelIndicator {
  indicator: string
  indicator_type: string
  origins: string[]
  eligible: boolean
  state: 'looked_up' | 'not_applicable_indicator' | 'not_attempted_cap_reached' | string
  rejection_reason: string | null
  message?: string
  results: IntelResult[]
}

export interface ThreatIntelRun {
  run_id: string
  analysis_id: string
  version: number
  created_at: string | null
  consent: { granted: boolean; decided_at: string; source: string; providers: string[] }
  offline: boolean
  simulated: boolean
  informational_only: boolean
  ioc_cap: number
  counts: { total: number; eligible: number; looked_up: number; rejected: number; cap_skipped: number }
  indicators: IntelIndicator[]
  provider_summary: Record<string, Record<string, number>>
  not_configured: Record<string, string>
  disclaimer: string
}

export interface IntelProviderStatus {
  label: string
  configured: boolean
  enabled: boolean
  requires_credentials: boolean
  note?: string
}

export interface IntelServiceStatus {
  offline: boolean
  simulated: boolean
  consent_required: boolean
  consent_default: boolean
  max_iocs_per_analysis: number
  informational_only: boolean
  providers: Record<string, IntelProviderStatus>
}

export async function getIntelStatus(signal?: AbortSignal): Promise<IntelServiceStatus> {
  return request<IntelServiceStatus>('/api/v1/intel/status', { signal })
}

/** Latest (or a pinned) stored threat-intel run; null when none has been run. */
export async function getThreatIntel(id: string, signal?: AbortSignal): Promise<ThreatIntelRun | null> {
  try {
    return await request<ThreatIntelRun>(`/api/v1/analyses/${encodeURIComponent(id)}/threat-intel`, { signal })
  } catch (err) {
    if (err instanceof ApiError && err.status === 404 && err.code === 'INTEL_NOT_RUN') return null
    throw err
  }
}

/** Run lookups. `consent: false` records the refusal and sends nothing. */
export async function runThreatIntel(
  id: string,
  body: { consent: boolean; source: 'upload' | 'on_demand'; providers?: string[] },
  signal?: AbortSignal,
): Promise<ThreatIntelRun> {
  return request<ThreatIntelRun>(`/api/v1/analyses/${encodeURIComponent(id)}/threat-intel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  })
}

// ── Authentication & user administration (P5b) ─────────────────────────────
export type { SessionUser }

export interface LoginResponse {
  access_token: string
  token_type: 'bearer'
  expires_at: string
  user: SessionUser
}

export interface Me extends SessionUser {
  permissions: string[]
}

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export async function login(username: string, password: string): Promise<LoginResponse> {
  return request<LoginResponse>(LOGIN_PATH, json({ username, password }))
}

/** Current user + permissions. `token` is used right after login, before it becomes the stored session. */
export async function getMe(token?: string): Promise<Me> {
  return request<Me>('/api/v1/auth/me', token ? { headers: { Authorization: `Bearer ${token}` } } : {})
}

export async function logout(): Promise<void> {
  await request<unknown>('/api/v1/auth/logout', { method: 'POST' })
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<LoginResponse> {
  return request<LoginResponse>(
    '/api/v1/auth/change-password',
    json({ current_password: currentPassword, new_password: newPassword }),
  )
}

export interface AdminUser {
  id: string
  username: string
  role: 'viewer' | 'analyst' | 'admin'
  is_active: boolean
  must_change_password: boolean
  created_at: string | null
  last_login_at: string | null
  locked: boolean
}

export interface TempPasswordResult {
  user: AdminUser
  temporary_password: string
  note: string
}

export async function listUsers(signal?: AbortSignal): Promise<AdminUser[]> {
  return request<AdminUser[]>('/api/v1/admin/users', { signal })
}

export async function createUser(username: string, role: AdminUser['role']): Promise<TempPasswordResult> {
  return request<TempPasswordResult>('/api/v1/admin/users', json({ username, role }))
}

export async function updateUser(
  id: string,
  changes: { role?: AdminUser['role']; is_active?: boolean },
): Promise<AdminUser> {
  return request<AdminUser>(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(changes),
  })
}

export async function resetUserPassword(id: string): Promise<TempPasswordResult> {
  return request<TempPasswordResult>(`/api/v1/admin/users/${encodeURIComponent(id)}/reset-password`, {
    method: 'POST',
  })
}

// ── Correlation, campaigns, search, case membership (P5c) ───────────────────
export interface AnalysisBrief {
  id: string
  created_at: string | null
  subject: string
  from_domain: string | null
  detection_score: number
  detection_verdict: string | null
  sha256: string
  combined_level?: RiskLevel | null        // P5h (search results)
  combined_score?: number | null
}

export interface EvidenceRef {
  analysis_id?: string
  role: string
  source_field: string
}

export interface SharedIndicator {
  entity_id: string
  type: string
  value: string
  roles?: string[]
  tier: 'strong' | 'medium' | 'weak' | string
  weight: number
  damped?: boolean
  df?: number
  evidence: EvidenceRef[]
  generic_reason?: string | null
}

export interface CampaignBrief {
  id: string
  label: string
  status: string
  confidence: 'high' | 'medium' | 'low' | string
  confidence_score: number
  member_count: number
  version: number
  merged_into: string | null
  created_at: string | null
  updated_at: string | null
}

export interface RelatedAnalysis {
  analysis: AnalysisBrief
  score: number
  qualifies: boolean
  confidence: string | null
  explanation: string
  indicators: SharedIndicator[]
  generic_overlaps: SharedIndicator[]
  independent_types: string[]
}

export interface Correlation {
  analysis_id: string
  status: 'ok' | 'error' | 'not_computed' | string
  entities: SharedIndicator[]
  related: RelatedAnalysis[]
  related_total: number
  generic_only_overlaps: { count: number; indicators: { type: string; value: string; reason: string; analyses: number }[] }
  campaigns: CampaignBrief[]
  rule: string
  disclaimer: string
}

export interface GraphNode {
  id: string
  kind: string
  label: string
  subject?: string
  analysis_id?: string
  verdict?: string | null
  score?: number
  tier?: string
  weight?: number
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  role: string
  source_field: string
  tier: string
}

export interface CampaignDetail extends CampaignBrief {
  members: AnalysisBrief[]
  reasons: {
    summary?: string[]
    shared_indicators?: (SharedIndicator & { analyses: string[] })[]
    links?: { a: string; b: string; score: number; explanation: string; indicators: { type: string; value: string; tier: string; weight: number }[] }[]
    rule?: string
    disclaimer?: string
  }
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
  disclaimer: string
}

export async function getCorrelation(id: string, signal?: AbortSignal): Promise<Correlation> {
  return request<Correlation>(`/api/v1/analyses/${encodeURIComponent(id)}/correlation`, { signal })
}

export async function listCampaigns(signal?: AbortSignal): Promise<{ items: CampaignBrief[]; disclaimer: string }> {
  return request(`/api/v1/campaigns`, { signal })
}

export async function getCampaign(id: string, signal?: AbortSignal): Promise<CampaignDetail> {
  return request<CampaignDetail>(`/api/v1/campaigns/${encodeURIComponent(id)}`, { signal })
}

export type SearchKind = 'all' | 'analysis' | 'case' | 'entity' | 'campaign'

export interface SearchParams {
  q?: string
  type?: SearchKind
  verdict?: string
  entity_type?: string
  date_from?: string
  date_to?: string
  limit?: number
  offset?: number
}

export interface SearchResponse {
  query: string
  type: SearchKind
  limit: number
  offset: number
  results: {
    analysis?: { total: number; items: AnalysisBrief[] }
    case?: { total: number; items: { id: string; case_number: string; title: string | null; status: string; created_at: string | null }[] }
    entity?: { total: number; items: { id: string; type: string; value: string; analyses: number }[] }
    campaign?: { total: number; items: CampaignBrief[] }
  }
}

export async function search(params: SearchParams, signal?: AbortSignal): Promise<SearchResponse> {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '' && v !== null) p.set(k, String(v))
  return request<SearchResponse>(`/api/v1/search?${p.toString()}`, { signal })
}

export interface CaseMember {
  analysis: AnalysisBrief
  campaigns: CampaignBrief[]
}

export interface CaseIndicator {
  entity_id: string
  type: string
  value: string
  case_analyses: string[]
  case_count: number
  df: number
  tier: string
  weight: number
  generic_reason: string | null
}

export async function listCaseAnalyses(caseId: string, signal?: AbortSignal): Promise<CaseMember[]> {
  return request<CaseMember[]>(`/api/v1/investigations/${encodeURIComponent(caseId)}/analyses`, { signal })
}

export async function addCaseAnalysis(caseId: string, analysisId: string): Promise<InvestigationCase> {
  return request<InvestigationCase>(`/api/v1/investigations/${encodeURIComponent(caseId)}/analyses`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analysis_id: analysisId }),
  })
}

export async function removeCaseAnalysis(caseId: string, analysisId: string): Promise<InvestigationCase> {
  return request<InvestigationCase>(
    `/api/v1/investigations/${encodeURIComponent(caseId)}/analyses/${encodeURIComponent(analysisId)}`,
    { method: 'DELETE' },
  )
}

export async function getCaseIndicators(
  caseId: string,
  signal?: AbortSignal,
): Promise<{ case_id: string; indicators: CaseIndicator[]; disclaimer: string }> {
  return request(`/api/v1/investigations/${encodeURIComponent(caseId)}/indicators`, { signal })
}

// ── MITRE ATT&CK mapping + source-type hypotheses (P5d) ─────────────────────
export interface AttackTechniqueMapping {
  technique_id: string
  name: string
  tactics: string[]
  url: string
  basis: 'observed' | 'inferred'
  confidence: 'low' | 'medium' | 'high'
  evidence_ids: string[]
  supporting_evidence_ids: string[]
  rationale: string
  mapping_rule_id: string
  limitations: string | null
}

export interface AttackEvidence {
  id: string
  kind: string
  category: string
  source_field: string
  statement: string
  tab: string
}

export interface SourceTypeHypothesis {
  hypothesis: string
  label: string
  band: 'not_indicated' | 'possible' | 'likely' | 'undetermined' | 'not_assessed'
  evidence_ids: string[]
  rationale: string
  missing_data: string[]
  reason?: string
}

export interface AttackMappingResult {
  mapping_id: string
  analysis_id: string
  version: number
  source: string
  created_at: string | null
  engine_version: string
  catalog_version: string
  attack_version: string
  catalog_verified: boolean
  inputs: { intel_run_id: string | null; intel_run_version: number | null; intel_simulated: boolean; ml_assessment_id: string | null }
  mappings: AttackTechniqueMapping[]
  empty_state: string | null
  source_type: SourceTypeHypothesis[]
  evidence: AttackEvidence[]
  disclaimer: string
  note: string
  new_version?: boolean
}

export interface AttackHistoryItem {
  mapping_id: string
  version: number
  source: string
  created_at: string | null
  technique_count: number
  intel_run_id: string | null
}

export async function getAttack(id: string, version?: number | null, signal?: AbortSignal): Promise<AttackMappingResult | null> {
  const q = version ? `?version=${encodeURIComponent(String(version))}` : ''
  try {
    return await request<AttackMappingResult>(`/api/v1/analyses/${encodeURIComponent(id)}/attack${q}`, { signal })
  } catch (err) {
    if (err instanceof ApiError && err.status === 404 && err.code === 'ATTACK_NOT_COMPUTED') return null
    throw err
  }
}

export async function getAttackHistory(id: string, signal?: AbortSignal): Promise<AttackHistoryItem[]> {
  return request<AttackHistoryItem[]>(`/api/v1/analyses/${encodeURIComponent(id)}/attack/history`, { signal })
}

export async function recomputeAttack(id: string): Promise<AttackMappingResult> {
  return request<AttackMappingResult>(`/api/v1/analyses/${encodeURIComponent(id)}/attack/recompute`, { method: 'POST' })
}

// ── Infrastructure geolocation + analytics (P5g) ────────────────────────────
export type GeoRole = 'origin_candidate' | 'untrusted_relay' | 'trusted_relay' | 'url_host_ip'
export type AnonymitySignal = 'tor' | 'vpn' | 'proxy' | 'relay' | 'hosting'

export interface GeoPoint {
  ip: string
  role: GeoRole
  roles: GeoRole[]
  hops?: number[]
  hop?: number | null
  via_host?: string | null
  lat: number
  lon: number
  country: string | null
  region: string | null
  city: string | null
  asn: string | null
  org: string | null
  isp: string | null
  source: string
  provider: string
  fetched_at: string | null
  stale: boolean
  simulated: boolean
  accuracy_note?: string
  members?: string[]
  member_count?: number
}

export interface GeoUnlocated {
  ip: string
  role: GeoRole
  roles: GeoRole[]
  hops?: number[]
  hop?: number | null
  via_host?: string | null
  country?: string | null
  asn?: string | null
  org?: string | null
  source?: string | null
  reason?: string
  members?: string[]
  member_count?: number
}

export interface AnonymityRow {
  ip: string
  role: GeoRole
  signals: Record<AnonymitySignal, { value: boolean | null; source: string | null }>
  simulated: boolean
  any_data: boolean
}

export interface GeoProvenance {
  lookups_performed: false
  intel_run?: { version: number; created_at: string | null; simulated: boolean; offline: boolean } | null
  enrichment_geo?: boolean
  simulated_present: boolean
  stale_present: boolean
  sources: string[]
}

export interface AnalysisGeo {
  analysis_id: string
  disclaimer: string
  accuracy_note: string
  relay_order_label: string
  points: GeoPoint[]
  unlocated: GeoUnlocated[]
  anonymity: AnonymityRow[]
  relay_order: string[]
  counts: { ips: number; located: number; unlocated: number }
  provenance: GeoProvenance
}

export interface CampaignGeo {
  campaign_id: string
  disclaimer: string
  accuracy_note: string
  points: GeoPoint[]
  unlocated: GeoUnlocated[]
  counts: { members: number; located: number; unlocated: number; truncated: boolean }
  provenance: GeoProvenance
}

export async function getAnalysisGeo(id: string, signal?: AbortSignal): Promise<AnalysisGeo> {
  return request<AnalysisGeo>(`/api/v1/analyses/${encodeURIComponent(id)}/geo`, { signal })
}

export async function getCampaignGeo(id: string, signal?: AbortSignal): Promise<CampaignGeo> {
  return request<CampaignGeo>(`/api/v1/campaigns/${encodeURIComponent(id)}/geo`, { signal })
}

export interface AnalyticsSummary {
  generated_at: string
  window: { days: number; since: string; total_analyses: number; analyses_considered: number; capped: boolean; max_window: number }
  verdicts: { verdict: string; count: number }[]
  ml_classes: { label: string; count: number }[]
  per_day: { date: string; count: number }[]
  score_histogram: { bucket: string; count: number }[]
  top_sender_domains: { domain: string; count: number; generic: boolean }[]
  geo: {
    coverage: { with_geo: number; analyses_considered: number }
    basis: string
    simulated_present: boolean
    countries: { country: string; count: number }[]
    asns: { asn: string; count: number }[]
  }
  attack_techniques: { technique_id: string; name: string; count: number }[]
  combined_levels?: { level: RiskLevel | 'not_computed'; count: number }[]   // P5h
  campaigns: { by_status: Record<string, number>; candidate_size_distribution: { bucket: string; count: number }[]; candidates: number }
  intel_coverage: { analyses_with_consented_lookups: number; analyses_considered: number; runs_total: number; simulated_runs: number }
}

export async function getAnalyticsSummary(days = 30, signal?: AbortSignal): Promise<AnalyticsSummary> {
  return request<AnalyticsSummary>(`/api/v1/analytics/summary?days=${encodeURIComponent(String(days))}`, { signal })
}

// ── Tamper-evident audit log, custody, retention (P5e) ──────────────────────
export interface AuditEventRow {
  seq: number | null
  id: string
  at: string | null
  action: string
  actor_id: string | null
  actor: string | null
  target_type: string | null
  target_id: string | null
  analysis_id: string | null
  case_id: string | null
  outcome: string | null
  source_ip: string | null
  detail: Record<string, unknown>
  hash_prefix: string
}

export interface AuditPage { items: AuditEventRow[]; total: number; page: number; page_size: number; actions: string[]; guarantee: string }
export interface AuditFilters { actor?: string; action?: string; target_type?: string; target_id?: string; outcome?: string; date_from?: string; date_to?: string }

function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

export async function getAuditEvents(f: AuditFilters, page = 1, pageSize = 50, signal?: AbortSignal): Promise<AuditPage> {
  return request<AuditPage>(`/api/v1/audit/events${qs({ ...f, page, page_size: pageSize })}`, { signal })
}

export interface AuditVerify { ok: boolean; checked: number; last_seq: number; last_hash: string; first_broken_seq: number | null; reason: string | null; guarantee: string }
export async function verifyAudit(signal?: AbortSignal): Promise<AuditVerify> {
  return request<AuditVerify>('/api/v1/audit/verify', { signal })
}

export interface AuditCheckpoint { seq: number; event_hash: string; created_at: string | null; by?: string | null; checkpoint_event_seq?: number }
export async function getAuditCheckpoint(signal?: AbortSignal): Promise<{ latest: AuditCheckpoint | null; guarantee: string; advice: string }> {
  return request('/api/v1/audit/checkpoint', { signal })
}
export async function createAuditCheckpoint(): Promise<{ checkpoint: AuditCheckpoint & { chain_ok: boolean }; latest: AuditCheckpoint | null }> {
  return request('/api/v1/audit/checkpoint', { method: 'POST' })
}

/** Authenticated export download (capped server-side and audited). */
export async function exportAudit(format: 'csv' | 'json', f: AuditFilters): Promise<void> {
  const res = await authedFetch(`/api/v1/audit/export${qs({ ...f, format })}`)
  if (!res.ok) throw new ApiError(res.status, `HTTP_${res.status}`, `Export failed (HTTP ${res.status})`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `aipish-audit.${format}`
  a.click()
  URL.revokeObjectURL(url)
}

export interface CustodyEntry { at: string | null; action: string; actor: string | null; outcome: string | null; case_id: string | null; detail: Record<string, unknown> }
export interface Custody {
  analysis_id: string; sha256: string; size_bytes: number; evidence_bytes_stored: boolean
  retention_state: RetentionState; redacted_at: string | null; legal_hold: boolean
  timeline: CustodyEntry[]; integrity_note: string; audit_guarantee: string
}
export async function getCustody(id: string, signal?: AbortSignal): Promise<Custody> {
  return request<Custody>(`/api/v1/analyses/${encodeURIComponent(id)}/custody`, { signal })
}

export interface RetentionPolicy { analysis_days: number; evidence_days: number; mode: 'redact' | 'delete'; grace_days: number; enabled: boolean; audit_events_purged: false; note: string }
export interface LegalHoldRow { id: string; target_type: 'analysis' | 'case'; target_id: string; reason: string; created_by: string | null; created_at: string; cleared_at: string | null; clear_reason: string | null; active: boolean }
export interface RetentionStatus {
  policy: RetentionPolicy; eligible_analyses: number; eligible_evidence_only: number; held_skipped: number
  eligible_ids: string[]; holds: LegalHoldRow[]; redacted_total: number
  last_run: { at: string; seq: number | null; detail: Record<string, unknown> } | null
  scheduler: string
}
export interface RetentionRunResult {
  dry_run: boolean; mode: string; policy: RetentionPolicy
  eligible_analyses: string[]; eligible_evidence_only: string[]; held_skipped: string[]
  redacted: string[]; deleted: string[]; evidence_purged: string[]; errors: { analysis_id: string; error: string }[]
}
export async function getRetentionStatus(signal?: AbortSignal): Promise<RetentionStatus> {
  return request<RetentionStatus>('/api/v1/admin/retention/status', { signal })
}
export async function runRetention(dryRun: boolean): Promise<RetentionRunResult> {
  return request<RetentionRunResult>('/api/v1/admin/retention/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dry_run: dryRun }),
  })
}
export async function setLegalHold(targetType: 'analysis' | 'case', targetId: string, reason: string): Promise<LegalHoldRow> {
  return request<LegalHoldRow>('/api/v1/admin/holds', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_type: targetType, target_id: targetId, reason }),
  })
}
export async function clearLegalHold(holdId: string, reason: string): Promise<LegalHoldRow> {
  return request<LegalHoldRow>(`/api/v1/admin/holds/${encodeURIComponent(holdId)}/clear`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reason }),
  })
}

// ── Explainable combined risk assessment (P5h) ──────────────────────────────
// An ADDITIONAL, separately labelled risk index (0-100): never replaces the rule verdict or the ML class.
export type RiskLevel = 'minimal' | 'low' | 'medium' | 'high' | 'critical' | 'indeterminate'
export type RiskConfidence = 'low' | 'medium' | 'high'
export type RiskComponentStatus = 'available' | 'unavailable' | 'not_run' | 'declined' | 'error'
export type RiskRole = 'primary' | 'floor' | 'corroboration' | 'context' | 'unavailable'

export interface RiskComponent {
  name: 'rules' | 'ml' | 'hard_evidence' | 'threat_intel' | 'campaign' | 'attack'
  label: string
  status: RiskComponentStatus
  value: unknown
  role: RiskRole
  effect: string | null
  evidence_ids: string[]
  reason: string
  cues?: { rule_id: string; fired: boolean; evidence_id: string | null }[]
  floors?: { id: string; rules: string[]; evidence_ids: string[]; floor: number; reason: string }[]
}

export interface RiskEvidence { id: string; source: string; ref: string; statement: string }

export interface RiskAssessment {
  risk_id: string
  analysis_id: string
  version: number
  source: string
  created_at: string | null
  engine_version: string
  config_version: string
  combined_score: number | null
  level: RiskLevel
  confidence: RiskConfidence
  agreement: 'agree' | 'partial' | 'conflict' | 'not_applicable'
  conflict: string | null
  flags: string[]
  components: RiskComponent[]
  evidence: RiskEvidence[]
  explanation: string[]
  bands: { edges: Record<string, number>; ml_thresholds: Record<string, number> }
  inputs: {
    detection_score: number | null
    detection_verdict: string | null
    ml_source: { kind: string | null; id: string | null; model_version: string | null; status: string }
    intel_run_id: string | null
    intel_simulated: boolean
    attack_mapping_id: string | null
    campaign_ids: string[]
  }
  disclaimers: string[]
  new_version?: boolean
}

export interface RiskHistoryItem {
  risk_id: string
  version: number
  source: string
  level: RiskLevel
  combined_score: number | null
  confidence: RiskConfidence
  engine_version: string
  created_at: string | null
}

export async function getRisk(id: string, version?: number | null, signal?: AbortSignal): Promise<RiskAssessment | null> {
  const q = version ? `?version=${encodeURIComponent(String(version))}` : ''
  try {
    return await request<RiskAssessment>(`/api/v1/analyses/${encodeURIComponent(id)}/risk${q}`, { signal })
  } catch (err) {
    if (err instanceof ApiError && err.status === 404 && err.code === 'RISK_NOT_COMPUTED') return null
    throw err
  }
}

export async function getRiskHistory(id: string, signal?: AbortSignal): Promise<RiskHistoryItem[]> {
  return request<RiskHistoryItem[]>(`/api/v1/analyses/${encodeURIComponent(id)}/risk/history`, { signal })
}

export async function recomputeRisk(id: string): Promise<RiskAssessment> {
  return request<RiskAssessment>(`/api/v1/analyses/${encodeURIComponent(id)}/risk/recompute`, { method: 'POST' })
}

// ── Risk-based alerts (P5f) ─────────────────────────────────────────────────
// Alerts are raised when an analysis is processed; this system does not monitor mailboxes in real time.
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'new' | 'acknowledged' | 'resolved'
export type AlertType = 'high_risk_analysis' | 'hard_evidence_floor' | 'review_conflict' | 'new_campaign' | 'campaign_growth'

export interface AlertSummaryFields {
  analysis_id?: string
  latest_analysis_id?: string
  analysis_ids?: string[]
  combined_level?: RiskLevel
  combined_score?: number | null
  rule_verdict?: string | null
  ml_class?: string | null
  floors?: string[]
  conflict?: string | null
  risk_version?: number
  campaign_id?: string
  campaign_label?: string
  campaign_confidence?: string
  member_count?: number
  previous_member_count?: number
}

export interface AlertItem {
  id: string
  type: AlertType
  type_label: string
  severity: AlertSeverity
  status: AlertStatus
  title: string
  analysis_id: string | null
  campaign_id: string | null
  risk_id: string | null
  summary: AlertSummaryFields
  occurrence_count: number
  created_at: string | null
  updated_at: string | null
  last_seen_at: string | null
  acknowledged_by: string | null
  acknowledged_at: string | null
  resolved_by: string | null
  resolved_at: string | null
  resolution_note: string | null
  delivery: { email?: { status: string; at?: string; reason?: string } }
  version: number
  analysis_redacted: boolean
}

export interface AlertHistoryEntry {
  id: string
  action: string
  actor: string | null
  note: string | null
  from_state: string | null
  to_state: string | null
  detail: Record<string, unknown>
  at: string | null
}

export interface AlertDetail extends AlertItem { history: AlertHistoryEntry[]; note: string }
export interface AlertList { items: AlertItem[]; total: number; page: number; page_size: number; note: string }
export interface AlertsSummary {
  by_status: Record<AlertStatus, number>
  open_by_severity: Record<AlertSeverity, number>
  new_by_severity: Record<AlertSeverity, number>
  new: number
  open: number
  enabled: boolean
  note: string
}
export interface AlertConfigView {
  enabled: boolean
  min_level: string
  floor_alerts: boolean
  conflict_alerts: boolean
  campaign_min_confidence: string
  growth_min_new_members: number
  growth_debounce_minutes: number
  email: {
    enabled: boolean; configured: boolean; min_severity: string; smtp_host: string | null; smtp_port: number
    smtp_security: string; smtp_username_set: boolean; smtp_password_set: boolean; from: string | null
    recipients: number; max_per_minute: number; timeout_seconds: number; app_base_url: string | null
  }
  trigger_note: string
}
export interface AlertFilters {
  status?: AlertStatus | 'open' | ''
  severity?: AlertSeverity | ''
  type?: AlertType | ''
  analysis_id?: string
  campaign_id?: string
  page?: number
  page_size?: number
}

export async function listAlerts(f: AlertFilters = {}, signal?: AbortSignal): Promise<AlertList> {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== '' && v !== null) p.set(k, String(v))
  const q = p.toString()
  return request<AlertList>(`/api/v1/alerts${q ? `?${q}` : ''}`, { signal })
}

export async function getAlertsSummary(signal?: AbortSignal): Promise<AlertsSummary> {
  return request<AlertsSummary>('/api/v1/alerts/summary', { signal })
}

export async function getAlert(id: string, signal?: AbortSignal): Promise<AlertDetail> {
  return request<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(id)}`, { signal })
}

export async function alertAction(id: string, action: 'acknowledge' | 'resolve' | 'reopen',
                                  body: { note?: string; version?: number } = {}): Promise<AlertDetail> {
  return request<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(id)}/${action}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
}

export async function getAlertConfig(signal?: AbortSignal): Promise<AlertConfigView> {
  return request<AlertConfigView>('/api/v1/admin/alerts/config', { signal })
}
