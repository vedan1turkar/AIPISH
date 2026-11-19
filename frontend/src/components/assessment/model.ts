/**
 * Pure view-model helpers for the ML / SHAP / local-LLM assessment.
 *
 * Rules: never fill in a value the backend did not send, never turn a
 * missing or failed component into a "legitimate"/"clean" result, and keep
 * every component's status visible.
 */
import type {
  EvidenceItem,
  ForensicSummary,
  MlResult,
  ShapComponent,
  ShapExplanation,
  SummaryFinding,
} from '../../api/client'

export interface ComponentState {
  status: string
  ran: boolean
  title: string
  message: string
}

const STATUS_TEXT: Record<string, { title: string; message: string }> = {
  ok: { title: 'Completed', message: '' },
  unavailable: { title: 'Unavailable', message: 'This component did not run.' },
  timeout: {
    title: 'Timed out',
    message: 'The local model did not answer within the time limit. No output was produced.',
  },
  invalid_output: {
    title: 'Invalid output',
    message: 'The model output failed validation and was discarded. Nothing from it is shown.',
  },
  error: { title: 'Error', message: 'This component failed while running. No result was produced.' },
  not_applicable: {
    title: 'Not applicable',
    message: 'The message is outside the model scope (for example an empty body).',
  },
  missing: {
    title: 'Not reported',
    message: 'The response did not include this component, so nothing is shown.',
  },
}

export function componentState(block: { status?: string; reason?: string | null } | null | undefined): ComponentState {
  const status = block?.status ?? 'missing'
  const meta = STATUS_TEXT[status] ?? { title: status, message: 'Unrecognised status; nothing is shown.' }
  const reason = block?.reason ? String(block.reason) : ''
  return {
    status,
    ran: status === 'ok',
    title: meta.title,
    message: [meta.message, reason].filter(Boolean).join(' Reason: '),
  }
}

/** True when ML/SHAP are unavailable because the raw bytes were not retained. */
export function isHashOnly(block: { reason?: string | null } | null | undefined): boolean {
  return /hash_only/.test(block?.reason ?? '')
}

export interface MlView {
  ok: boolean
  state: ComponentState
  label?: string
  score?: number
  probabilities: { label: string; value: number }[]
  modelVersion?: string
  untrained: string[]
}

export function mlView(ml: MlResult | null | undefined): MlView {
  const state = componentState(ml)
  const ok = state.ran && typeof ml?.label === 'string' && ml.label.length > 0
  if (state.ran && !ok) {
    state.message = 'The classifier reported success but returned no class, so no classification is shown.'
  }
  const probabilities = ok
    ? Object.entries(ml?.probabilities ?? {})
        .filter(([, v]) => typeof v === 'number' && Number.isFinite(v))
        .map(([label, value]) => ({ label, value }))
        .sort((a, b) => b.value - a.value)
    : []
  return {
    ok,
    state,
    label: ok ? (ml?.label ?? undefined) : undefined,
    score: ok && typeof ml?.confidence === 'number' ? ml.confidence : undefined,
    probabilities,
    modelVersion: ok ? (ml?.model_version ?? undefined) : undefined,
    untrained: ml?.untrained_classes ?? [],
  }
}

export interface ShapRow {
  feature: string
  group: string
  value: string
  shap: number
  direction: 'toward' | 'away' | 'aggregate'
  magnitudePct: number
  aggregated: boolean
}

export function shapRows(c: ShapComponent): ShapRow[] {
  const raw = [
    ...(c.top_contributions ?? []).map((r) => ({ r, aggregated: false })),
    ...(c.aggregated ?? []).map((r) => ({ r, aggregated: true })),
  ].filter(({ r }) => typeof r.shap_value === 'number' && Number.isFinite(r.shap_value))
  const max = Math.max(1e-12, ...raw.map(({ r }) => Math.abs(r.shap_value)))
  return raw.map(({ r, aggregated }) => ({
    feature: r.feature,
    group: r.group,
    value: r.value === null || r.value === undefined ? (r.detail ?? '') : String(r.value),
    shap: r.shap_value,
    direction: aggregated ? 'aggregate' : r.shap_value > 0 ? 'toward' : 'away',
    magnitudePct: Math.round((Math.abs(r.shap_value) / max) * 100),
    aggregated,
  }))
}

export interface ShapCoverage {
  explained: { name: string; weight?: number }[]
  notExplained: { component: string; reason: string }[]
  sentence: string
}

const COMPONENT_NAMES: Record<string, string> = {
  xgb: 'XGBoost',
  lr: 'logistic regression',
  transformer: 'DistilRoBERTa',
}

export function componentName(key: string): string {
  return COMPONENT_NAMES[key] ?? key
}

export function shapCoverage(ex: ShapExplanation | null | undefined): ShapCoverage {
  const explained = Object.entries(ex?.components ?? {}).map(([name, c]) => ({ name, weight: c.ensemble_weight }))
  const notExplained = ex?.not_explained ?? []
  const parts = explained.map((e) =>
    `${componentName(e.name)}${typeof e.weight === 'number' ? ` (ensemble weight ${e.weight})` : ''}`,
  )
  const missing = notExplained.map((n) => componentName(n.component))
  const sentence = explained.length
    ? `SHAP explains only the ${parts.join(' and ')} component of the ensemble, not the whole ensemble.` +
      (missing.length ? ` The ${missing.join(' and ')} component is not explained by SHAP.` : '')
    : 'No component was explained.'
  return { explained, notExplained, sentence }
}

export interface EvidenceRef {
  id: string
  item: EvidenceItem | null
}

export function evidenceIndex(fs: ForensicSummary | null | undefined): Map<string, EvidenceItem> {
  return new Map((fs?.evidence ?? []).map((e) => [e.id, e]))
}

export function findingRefs(f: SummaryFinding, index: Map<string, EvidenceItem>): EvidenceRef[] {
  return (f.evidence_ids ?? []).map((id) => ({ id, item: index.get(id) ?? null }))
}

export function basisKind(basis: string): 'verified' | 'inferred' {
  return basis === 'verified' ? 'verified' : 'inferred'
}

export const CATEGORY_TEXT: Record<string, { label: string; hint: string; className: string }> = {
  verified: {
    label: 'Observed / verified',
    hint: 'Measured from the message bytes, or re-verified locally',
    className: 'bg-emerald-50 text-emerald-800 ring-emerald-200',
  },
  provider: {
    label: 'Provider result',
    hint: 'Returned by an external threat-intelligence or geolocation provider',
    className: 'bg-teal-50 text-teal-800 ring-teal-200',
  },
  heuristic: {
    label: 'Heuristic',
    hint: 'A rule judgement on noisy evidence',
    className: 'bg-indigo-50 text-indigo-800 ring-indigo-200',
  },
  claimed: {
    label: 'Header claim',
    hint: 'Stated by the email headers. Not verified.',
    className: 'bg-sky-50 text-sky-800 ring-sky-200',
  },
  model: {
    label: 'Model output',
    hint: 'A statistical ML output or SHAP association. Not proof.',
    className: 'bg-violet-50 text-violet-800 ring-violet-200',
  },
}

export function categoryMeta(cat: string) {
  return CATEGORY_TEXT[cat] ?? { label: cat, hint: '', className: 'bg-gray-50 text-gray-700 ring-gray-200' }
}

export function formatScore(v: number | undefined): string {
  return typeof v === 'number' && Number.isFinite(v) ? v.toFixed(2) : 'n/a'
}
