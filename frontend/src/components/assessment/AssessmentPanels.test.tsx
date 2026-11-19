/**
 * Rendering tests for the ML / SHAP / local-LLM assessment UI.
 * Fixture = the real backend response for docs/llm/sample_bec_injection.eml
 * (actual Mistral output), so field names are those the API really returns.
 * Rendered with react-dom/server: no DOM emulation dependency needed.
 */
import { describe, it, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import type { Assessment } from '../../api/client'
import real from './__fixtures__/assessment_ok.json'
import {
  AssessmentOverviewCard,
  AssessmentView,
  EvidencePanel,
  MlPanel,
  ShapPanel,
  SummaryPanel,
} from './AssessmentPanels'
import { componentState, evidenceIndex, findingRefs, mlView, shapCoverage, shapRows } from './model'

const OK = real as unknown as Assessment
const clone = (): Assessment => JSON.parse(JSON.stringify(OK))
const html = (el: JSX.Element) => renderToStaticMarkup(el)
const text = (el: JSX.Element) => html(el).replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, ' ')
const noop = () => undefined

const HASH_ONLY = {
  status: 'unavailable',
  reason: 'raw message not retained (CASE_EVIDENCE_STORE=hash_only); ML classification and SHAP need the original bytes',
}

describe('ML classification', () => {
  it('renders the predicted class, uncalibrated score caveat and per-class scores', () => {
    const t = text(<MlPanel ml={OK.ml} mlStatus={{ status: 'ok', ensemble_weights: { lr: 0, transformer: 0.5, xgb: 0.5 } }} />)
    expect(t).toContain('Predicted class fraud')
    expect(t).toContain('ensemble score 0.71')
    expect(t).toContain('uncalibrated')
    expect(t).toContain('not a certainty')
    expect(t).toContain('DistilRoBERTa 0.5 + XGBoost 0.5')
    expect(t).toContain('never predicted (no training data): suspicious')
    expect(t).toContain('aipish-email-v1@d8d583a30ffc')
  })

  it.each([
    [{ status: 'unavailable', reason: 'model files missing in aipish-email-v1: model_config.json' }, 'model files missing'],
    [{ status: 'error', reason: 'inference failed: ValueError' }, 'inference failed'],
    [{ status: 'not_applicable', reason: 'message outside model scope: empty_or_tiny_body' }, 'outside the model scope'],
  ])('shows %s without inventing a class', (ml, needle) => {
    const t = text(<MlPanel ml={ml} />)
    expect(t).toContain(needle)
    expect(t).toContain('does not mean "legitimate"')
    expect(t).not.toContain('Predicted class')
  })

  it('explains hash_only retention for stored analyses', () => {
    const t = text(<MlPanel ml={HASH_ONLY} />)
    expect(t).toContain('hash_only')
    expect(t).toContain('upload the .eml again')
  })

  it('treats ok-without-label and a missing block as no result (no fabrication)', () => {
    expect(mlView({ status: 'ok' }).ok).toBe(false)
    expect(text(<MlPanel ml={{ status: 'ok' }} />)).not.toContain('Predicted class')
    expect(text(<MlPanel ml={null} />)).toContain('Not reported')
  })
})

describe('SHAP explanation', () => {
  it('renders contributions with direction and magnitude, scoped to XGBoost only', () => {
    const out = html(<ShapPanel explanation={OK.explanation} />)
    const t = text(<ShapPanel explanation={OK.explanation} />)
    expect(t).toContain('SHAP explains only the XGBoost (ensemble weight 0.5) component of the ensemble')
    expect(t).toContain('The DistilRoBERTa component is not explained by SHAP')
    expect(t).toContain('n_url_hosts')
    expect(t).toContain('-2.007')
    expect(t).toContain('text_semantic_components')
    expect(out).toContain('data-direction="away"')
    expect(out).toContain('data-direction="toward"')
    expect(t).toContain(OK.explanation!.disclaimer!)            // non-causal disclaimer preserved verbatim
    expect(t).toContain('not causal')
  })

  it('scales bars by magnitude and keeps signs', () => {
    const rows = shapRows(OK.explanation!.components!.xgb)
    const top = rows.find((r) => r.feature === 'n_url_hosts')!
    expect(top.magnitudePct).toBe(100)
    expect(top.direction).toBe('away')
    expect(rows.find((r) => r.feature === 'digit_ratio')!.direction).toBe('toward')
    expect(rows.every((r) => r.magnitudePct >= 0 && r.magnitudePct <= 100)).toBe(true)
  })

  it('coverage sentence comes from the data', () => {
    const cov = shapCoverage(OK.explanation)
    expect(cov.explained.map((e) => e.name)).toEqual(['xgb'])
    expect(cov.notExplained[0].component).toBe('transformer')
  })

  it('unavailable / hash_only / empty components render as not run', () => {
    expect(text(<ShapPanel explanation={HASH_ONLY} />)).toContain('hash_only')
    const empty = text(<ShapPanel explanation={{ status: 'ok', components: {} }} />)
    expect(empty).toContain('SHAP returned no explained components')
    expect(empty).not.toContain('toward class →')
  })
})

describe('Mistral forensic summary', () => {
  it('renders summary, assessment, findings, actions and limitations as AI-generated', () => {
    const t = text(<SummaryPanel fs={OK.forensic_summary} />)
    expect(t).toContain('AI-generated')
    expect(t).toContain('never replaces the rule-engine verdict or the ML classification')
    expect(t).toContain(OK.forensic_summary!.assessment!)
    expect(t).toContain('Recommended actions')
    expect(t).toContain('Limitations (stated by the model)')
    expect(t).toContain('ollama / mistral:latest')
    expect(t).toContain('digest 6577803aa9a0')
    expect(t).toContain('prompt-injection attempt (ignore_instructions, role_override, verdict_steering)')
  })

  it('every finding shows its cited evidence IDs linked to the evidence list', () => {
    const out = html(<SummaryPanel fs={OK.forensic_summary} />)
    const findings = OK.forensic_summary!.findings!
    expect(findings.length).toBeGreaterThan(0)
    for (const f of findings) for (const id of f.evidence_ids) expect(out).toContain(`href="#evidence-${id}"`)
    const ev = html(<EvidencePanel fs={OK.forensic_summary} />)
    for (const f of findings) for (const id of f.evidence_ids) expect(ev).toContain(`id="evidence-${id}"`)
  })

  it('labels verified and inferred bases', () => {
    const t = text(<SummaryPanel fs={OK.forensic_summary} />)
    const bases = new Set(OK.forensic_summary!.findings!.map((f) => f.basis))
    expect(bases).toEqual(new Set(['verified', 'inferred']))
    expect(t).toContain('Verified')
    expect(t).toContain('Inferred')
  })

  it('flags evidence IDs that are not in the evidence list', () => {
    const fs = clone().forensic_summary!
    fs.findings = [{ statement: 'x', evidence_ids: ['E999'], basis: 'inferred' }]
    expect(text(<SummaryPanel fs={fs} />)).toContain('E999 (not in evidence list)')
    expect(findingRefs(fs.findings[0], evidenceIndex(fs))[0].item).toBeNull()
  })

  it('shows rejected findings with reasons, and withheld summary/assessment', () => {
    const fs = clone().forensic_summary!
    fs.rejected_findings = [{ statement: 'SPF passed for the sender.', reason: 'SPF described as passed/verified but it was not locally verified' }]
    fs.summary = null
    fs.assessment = null
    const t = text(<SummaryPanel fs={fs} />)
    expect(t).toContain('1 model statement(s) rejected by validation')
    expect(t).toContain('not locally verified')
    expect(t).toContain('summary was withheld')
    expect(t).toContain('assessment was withheld')
  })

  it.each([
    ['timeout', 'did not answer within the time limit'],
    ['invalid_output', 'failed validation and was discarded'],
    ['unavailable', 'did not run'],
  ])('%s renders a failure state with no summary content', (status, needle) => {
    const fs = { ...clone().forensic_summary!, status, summary: null, assessment: null, findings: [], reason: `reason for ${status}` }
    const t = text(<SummaryPanel fs={fs} />)
    expect(t).toContain(needle)
    expect(t).toContain(`reason for ${status}`)
    expect(t).not.toContain('Findings (each cites evidence)')
    expect(componentState(fs).ran).toBe(false)
  })

  it('a stale "ok" status is not trusted for a missing block', () => {
    const t = text(<SummaryPanel fs={undefined} />)
    expect(t).toContain('Not reported')
    expect(t).not.toContain('Summary')
  })
})

describe('evidence list and separation of verdicts', () => {
  it('evidence list shows categories and unavailable checks as not passed', () => {
    const t = text(<EvidencePanel fs={OK.forensic_summary} />)
    expect(t).toContain('The analysis pipeline builds this list; the language model does not.')
    expect(t).toContain('Header claim')
    expect(t).toContain('Model output')
    expect(t).toContain('Checks that did not run or returned nothing (not passed)')
    expect(t).toContain('spf')
  })

  it('assessment view keeps ML, SHAP, LLM and evidence as separate panels', () => {
    const out = html(
      <AssessmentView assessment={OK} loading={false} error={null} generating={false} generateError={null} onGenerate={noop} />,
    )
    for (const title of ['ML classification', 'SHAP feature contributions', 'AI-generated forensic interpretation', 'Evidence list (deterministic)'])
      expect(out).toContain(title)
    expect(out).toContain('remain the primary record')
    expect(out).toContain('upload (original bytes available)')
  })

  it('not-generated state offers generation and explains the ML/SHAP limits', () => {
    const t = text(
      <AssessmentView assessment={null} loading={false} error={null} generating={false} generateError={null} onGenerate={noop} />,
    )
    expect(t).toContain('No AI assessment has been generated')
    expect(t).toContain('Generate AI forensic summary')
    expect(t).not.toContain('Predicted class')
  })

  it('failed API request is shown as an error, not as an empty success', () => {
    const t = text(
      <AssessmentView assessment={null} loading={false} error="Cannot reach the analysis backend." generating={false} generateError={null} onGenerate={noop} />,
    )
    expect(t).toContain('Could not load the stored assessment: Cannot reach the analysis backend.')
    expect(t).not.toContain('Generate AI forensic summary')
  })

  it('stored analysis under hash_only: ML/SHAP unavailable, summary still shown', () => {
    const a = { ...clone(), source: 'stored_analysis', ml: HASH_ONLY, explanation: { ...HASH_ONLY, components: {} } }
    const t = text(<AssessmentView assessment={a} loading={false} error={null} generating={false} generateError={null} onGenerate={noop} />)
    expect(t.match(/hash_only/g)!.length).toBeGreaterThanOrEqual(2)
    expect(t).not.toContain('Predicted class')
    expect(t).toContain('AI-generated forensic interpretation')
  })

  it('overview card is separate and never invents a label', () => {
    expect(text(<AssessmentOverviewCard assessment={OK} loading={false} onOpen={noop} />)).toContain('fraud (0.71 score)')
    const none = text(<AssessmentOverviewCard assessment={null} loading={false} onOpen={noop} />)
    expect(none).toContain('No ML / SHAP / AI assessment has been generated')
    const failed = text(<AssessmentOverviewCard assessment={{ ...clone(), ml: HASH_ONLY }} loading={false} onOpen={noop} />)
    expect(failed).toContain('Unavailable')
    expect(failed).not.toContain('legitimate')
  })

  it('special characters in model text are rendered as text, never as markup', () => {
    const fs = clone().forensic_summary!
    fs.summary = '<img src=x onerror=alert(1)> & <b>bold</b>'
    const out = html(<SummaryPanel fs={fs} />)
    expect(out).not.toContain('<img src=x')
    expect(out).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })
})
