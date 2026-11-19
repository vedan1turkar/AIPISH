// API client for the FastAPI backend.
//
// Base URL: configured backend URL. In dev, leave VITE_API_BASE empty and the
// Vite proxy forwards /api → FastAPI :8000. For other deployments set
// VITE_API_BASE to the absolute backend origin (e.g. http://127.0.0.1:8000).
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

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, init)
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the analysis backend. Is it running?')
  }
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
export interface HealthResponse {
  status: string
  version: string
  env: string
  db_connected: boolean
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>(`/api/v1/health`, { signal })
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
}

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
export async function downloadReport(caseId: string, analysisId: string): Promise<void> {
  const res = await fetch(
    `${API_BASE}/api/v1/investigations/${encodeURIComponent(caseId)}/report/${encodeURIComponent(analysisId)}`,
  )
  if (!res.ok) {
    let code = `HTTP_${res.status}`
    let message = `Report download failed (HTTP ${res.status})`
    try {
      const body = (await res.json()) as { detail: { code: string; message: string } }
      if ('detail' in body && typeof body.detail === 'object' && body.detail?.message) {
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
