// Verdict strip (P5u-1): the single focal element of an analysis. Rule-based and ML/AI results
// sit in separate, labelled cells. P5h adds the combined risk index as its own, separately labelled
// cell; it never replaces or changes the rule verdict or the ML class shown beside it.
import type { AnalysisDetail, Assessment, AttackMappingResult, IntegrityResult, InvestigationCase, RiskAssessment, ThreatIntelRun } from '../api/client'
import { LED, scoreTone, type Tone } from './ui'
import { LEVEL_TONE } from './risk/level'

function Cell({ label, children, sub, testid }: { label: string; children: React.ReactNode; sub?: React.ReactNode; testid: string }) {
  return (
    <div className="min-w-0 px-4 py-3" data-testid={testid}>
      <div className="font-mono text-xs uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-1 flex min-w-0 items-center gap-2 text-base font-medium text-fg">{children}</div>
      {sub && <div className="mt-0.5 truncate text-sm text-muted">{sub}</div>}
    </div>
  )
}

const BAND_RANK: Record<string, number> = { likely: 3, possible: 2, not_indicated: 1, undetermined: 0, not_assessed: 0 }

export default function VerdictStrip({ analysis, assessment, attack, intelRun, caseInfo, integrity, risk = null, riskLoading = false }: {
  analysis: AnalysisDetail
  risk?: RiskAssessment | null
  riskLoading?: boolean
  assessment: Assessment | null
  attack: AttackMappingResult | null
  intelRun: ThreatIntelRun | null
  caseInfo: InvestigationCase | null
  integrity: IntegrityResult | null
}) {
  const d = analysis.detection
  // ML class: the AI-assessment result when one exists, else the stored upload-time classification (P5h)
  const uploadMl = risk?.inputs.ml_source.kind === 'upload_classification'
    ? (risk.components.find((c) => c.name === 'ml')?.value as { label?: string; confidence?: number } | null) : null
  const ml = assessment?.ml?.status === 'ok' ? assessment.ml
    : uploadMl?.label ? { status: 'ok', label: uploadMl.label, confidence: uploadMl.confidence ?? null, model_version: null as string | null } : assessment?.ml
  const mlSub = assessment?.ml?.status === 'ok' ? `model ${assessment.ml.model_version ?? 'n/a'} · statistical`
    : uploadMl?.label ? 'upload-time classification · statistical' : 'run from the AI assessment tab'
  const top = attack?.source_type
    ?.filter((h) => h.band === 'likely' || h.band === 'possible')
    .sort((a, b) => BAND_RANK[b.band] - BAND_RANK[a.band])[0]
  const intelTone: Tone = !intelRun ? 'neutral' : !intelRun.consent.granted ? 'neutral' : intelRun.simulated ? 'warn' : 'ok'
  const intelText = !intelRun ? 'not run' : !intelRun.consent.granted ? 'declined' : `run v${intelRun.version}`
  const integrityText = integrity ? integrity.result : caseInfo ? (caseInfo.evidence_policy?.store_mode?.replace('_', '-') ?? 'case open') : 'no case'
  return (
    <section aria-label="Verdict summary" className="border border-line bg-surface">
      <div className="grid grid-cols-2 divide-x divide-y divide-line md:grid-cols-3 2xl:grid-cols-6 2xl:divide-y-0">
        <Cell label="Rule engine · score" testid="strip-rules"
              sub="18 deterministic rules; see Findings">
          <LED tone={scoreTone(d.score)} />
          <span className="font-mono text-xl font-semibold">{d.score}</span>
          <span className="truncate text-sm uppercase">{(d.verdict ?? 'unknown').replace(/_/g, ' ')}</span>
        </Cell>
        <Cell label="ML classifier · separate" testid="strip-ml" sub={mlSub}>
          {ml?.status === 'ok' && ml.label ? (
            <>
              <LED tone={ml.label === 'legitimate' ? 'ok' : 'danger'} />
              <span className="truncate uppercase">{ml.label}</span>
              <span className="font-mono text-sm text-muted">{(ml.confidence ?? 0).toFixed(4)}</span>
            </>
          ) : (
            <><LED tone="neutral" /><span className="text-muted">not assessed</span></>
          )}
        </Cell>
        <Cell label="Combined risk · index" testid="strip-risk"
              sub={risk ? `confidence ${risk.confidence}${risk.flags.includes('conflicting_signals') ? ' · conflicting signals' : ''} · not a probability`
                : riskLoading ? 'loading…' : 'not computed yet'}>
          {risk ? (
            <>
              <LED tone={LEVEL_TONE[risk.level]} />
              <span className="font-mono text-xl font-semibold">{risk.combined_score ?? '—'}</span>
              <span className="truncate text-sm uppercase">{risk.level}</span>
            </>
          ) : (
            <><LED tone="neutral" /><span className="text-muted">{riskLoading ? '…' : 'not computed'}</span></>
          )}
        </Cell>
        <Cell label="Source type · hypothesis" testid="strip-source"
              sub={top ? 'infrastructure hypothesis, not identity' : attack ? 'no likely/possible hypothesis' : 'mapping not computed'}>
          <LED tone={top ? (top.band === 'likely' ? 'danger' : 'warn') : 'neutral'} />
          <span className="truncate" title={top ? `${top.band}: ${top.label}` : undefined}>{top ? `${top.band}: ${top.label.replace(/^Possible /, '')}` : 'undetermined'}</span>
        </Cell>
        <Cell label="Threat intel" testid="strip-intel"
              sub={intelRun?.simulated ? 'SIMULATED provider data' : 'informational only, not scored'}>
          <LED tone={intelTone} /><span>{intelText}</span>
        </Cell>
        <Cell label="Evidence" testid="strip-evidence" sub={`sha256 ${analysis.sha256.slice(0, 16)}…`}>
          <LED tone={integrity?.result === 'match' ? 'ok' : integrity?.result === 'mismatch' ? 'danger' : 'neutral'} />
          <span className="truncate">{integrityText}</span>
        </Cell>
      </div>
    </section>
  )
}
