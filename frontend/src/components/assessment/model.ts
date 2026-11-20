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
  Recommendation,
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

// ── P4.1: SHAP component interpretation (mirror of backend app/ml/shap_view.py) ──
export const ADDITIVITY_TOL = 1e-3

export interface ShapComponentView {
  name: string
  base?: number
  output?: number
  net?: number
  direction: 'toward' | 'away' | 'neutral' | 'unknown'
  netSentence: string
  divergenceNote: string | null
  shownSum: number
  remainder?: number
  hasRemainder: boolean
  displayedAdditivityOk: boolean
}

const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined)
const fmt4 = (v: number) => (v >= 0 ? '+' : '') + v.toFixed(4)

export function shapComponentView(
  key: string,
  c: ShapComponent,
  explainedLabel: string | undefined,
  ml: MlResult | null | undefined,
): ShapComponentView {
  const name = componentName(key)
  const base = num(c.base_value)
  const output = num(c.output_value)
  const rows = [...(c.top_contributions ?? []), ...(c.aggregated ?? [])].filter((r) => num(r.shap_value) !== undefined)
  const shownSum = rows.reduce((s, r) => s + r.shap_value, 0)
  const net = base !== undefined && output !== undefined ? output - base : undefined
  const remainder = net !== undefined ? net - shownSum : undefined
  const direction: ShapComponentView['direction'] =
    net === undefined ? 'unknown' : Math.abs(net) < ADDITIVITY_TOL ? 'neutral' : net > 0 ? 'toward' : 'away'
  const label = explainedLabel ?? 'the explained class'
  let netSentence: string
  if (net === undefined || base === undefined || output === undefined)
    netSentence = `The net ${name} contribution could not be determined (base or output missing).`
  else if (direction === 'neutral') netSentence = `The net ${name} contribution to '${label}' is approximately zero.`
  else
    netSentence = `Net ${name} contribution: its raw margin for '${label}' moved from ${fmt4(base)} to ${fmt4(output)} (${fmt4(net)}), i.e. ${direction === 'toward' ? 'toward' : 'away from'} '${label}' overall.`
  let divergenceNote: string | null = null
  if (direction === 'away' && ml?.label && ml.label === explainedLabel) {
    const probs = Object.entries(ml.components ?? {})
      .map(([k, v]) => [k, v?.[label]] as const)
      .filter(([, v]) => num(v) !== undefined)
    const detail = probs.length
      ? ` The ensemble score is a weighted average of component probabilities: ${probs
          .map(([k, v]) => `${componentName(k)} gave '${label}' ${(v as number).toFixed(4)}`)
          .join(', ')}${num(ml.confidence) !== undefined ? `, giving the ensemble score ${(ml.confidence as number).toFixed(4)}.` : '.'}`
      : ''
    divergenceNote =
      `For this email the ${name} raw margin for '${label}' ended below its baseline, i.e. its explained contribution moved away from '${label}', yet the whole ensemble still predicts '${label}'. ` +
      `A margin below baseline is not the same as ${name} rejecting '${label}': it is relative to the model's average output.${detail} ` +
      'The ensemble also includes DistilRoBERTa, which SHAP does not explain, so these SHAP values do not explain the ensemble prediction.'
  }
  return {
    name,
    base,
    output,
    net,
    direction,
    netSentence,
    divergenceNote,
    shownSum,
    remainder,
    hasRemainder: remainder !== undefined && Math.abs(remainder) >= ADDITIVITY_TOL,
    displayedAdditivityOk: remainder !== undefined && Math.abs(remainder) < ADDITIVITY_TOL,
  }
}

// ── P4.1: recommendations ──────────────────────────────────────────────
export interface RecommendationGroups {
  graded: boolean
  /** P4.2 constrained policy: all shown text is system-template text */
  constrained: boolean
  linked: Recommendation[]
  general: Recommendation[]
  rejected: { text: string; reason: string }[]
  legacy: string[]
}

export function recommendationGroups(fs: ForensicSummary | null | undefined): RecommendationGroups {
  const recs = fs?.recommendations
  if (!Array.isArray(recs))
    return { graded: false, constrained: false, linked: [], general: [], rejected: [], legacy: fs?.recommended_actions ?? [] }
  return {
    graded: true,
    constrained: fs?.recommendation_policy === 'p4.2-constrained',
    linked: recs.filter((r) => r.kind === 'evidence_linked'),
    general: recs.filter((r) => r.kind === 'general'),
    rejected: fs?.rejected_recommendations ?? [],
    legacy: [],
  }
}

export const PRIVACY_NOTE =
  'Before anything reaches the local model, secrets, account and card numbers, phone numbers, address local parts and URL paths are redacted. So are personal names taken from the From/To/Cc headers and names after greetings or sign-offs. Other personal names in the body are not reliably detected and may reach the local model. Nothing is sent to an external service.'

/** P4.2: the deterministic financial-context warning, or null (never invented). */
export function financialWarning(fs: ForensicSummary | null | undefined): { text: string; signals: string[] } | null {
  const f = fs?.financial_context
  if (!f?.detected || !f.warning) return null
  const label = (t: string) => ({ '[redacted_iban]': 'iban', '[redacted_card]': 'card number' })[t] ?? t
  const signals = [...new Set([...(f.evidence_signals ?? []).map((x) => x.term), ...(f.email_text_terms ?? [])].map(label))]
  return { text: f.warning, signals }
}
