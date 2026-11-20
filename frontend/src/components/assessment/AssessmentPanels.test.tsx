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
  FinancialWarning,
  EvidencePanel,
  MlPanel,
  ShapPanel,
  SummaryPanel,
} from './AssessmentPanels'
import {
  componentState,
  evidenceIndex,
  findingRefs,
  mlView,
  recommendationGroups,
  shapComponentView,
  shapCoverage,
  shapRows,
} from './model'

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

describe('P4.1 SHAP interpretation', () => {
  it('explains that XGBoost moved away from the class while the ensemble still predicts it', () => {
    const t = text(<ShapPanel explanation={OK.explanation} ml={OK.ml} />)
    expect(t).toContain("moved from -0.0098 to -0.9326 (-0.9228), i.e. away from 'fraud' overall")
    expect(t).toContain('Why the ensemble still predicts this class')
    expect(t).toContain("XGBoost gave 'fraud' 0.4211")
    expect(t).toContain("DistilRoBERTa gave 'fraud' 0.9997")
    expect(t).toContain('do not explain the ensemble prediction')
    expect(t).toContain('raw-margin space')
    expect(t).toContain('they are not probabilities')
    expect(t).toContain(OK.explanation!.disclaimer!)
  })

  it('labels the aggregated semantic contribution and checks additivity', () => {
    const t = text(<ShapPanel explanation={OK.explanation} ml={OK.ml} />)
    expect(t).toContain('text_semantic_components')
    expect(t).toContain('aggregate of 100 TF-IDF SVD components, summed; not an individual word or phrase')
    expect(t).toContain('+0.979')
    expect(t).toContain('Additivity: base -0.01 + sum of contributions -0.92 = output -0.93 (check passed')
  })

  it('mirrors the backend view model exactly', () => {
    const view = shapComponentView('xgb', OK.explanation!.components!.xgb, 'fraud', OK.ml)
    expect(view.direction).toBe('away')
    expect(Math.abs(view.shownSum - (view.net ?? 0))).toBeLessThan(1e-3)
    expect(view.hasRemainder).toBe(false)
  })
})

describe('P4.1 recommendations', () => {
  const graded = () => {
    const fs = clone().forensic_summary!
    fs.recommendations = [
      { text: 'Investigate the URL provided in the email.', kind: 'evidence_linked', origin: 'model', evidence_ids: ['E4'] },
      { text: 'Alert the recipient.', kind: 'general', origin: 'model', evidence_ids: [] },
      { text: 'Preserve the original .eml file.', kind: 'general', origin: 'system', evidence_ids: [] },
    ]
    fs.rejected_recommendations = [{ text: 'Investigate the phone number provided in the email.',
      reason: 'asserts a detail of the email (phone number) that no deterministic evidence item establishes' }]
    return fs
  }

  it('separates evidence-linked, general and rejected recommendations', () => {
    const out = html(<SummaryPanel fs={graded()} />)
    const t = text(<SummaryPanel fs={graded()} />)
    expect(t).toContain('Evidence-linked recommendations')
    expect(t).toContain('General investigative recommendations (not established by a specific evidence item)')
    expect(out).toContain('href="#evidence-E4"')
    expect(t).toContain('(system)')
    expect(t).toContain('(model)')
    expect(t).toContain('1 model suggestion(s) rejected as unsafe or unsupported')
    expect(t).toContain('no deterministic evidence item establishes')
  })

  it('older assessments without grounding are labelled as unchecked', () => {
    const g = recommendationGroups(OK.forensic_summary)
    expect(g.graded).toBe(false)
    expect(text(<SummaryPanel fs={OK.forensic_summary} />)).toContain('generated before recommendation grounding')
  })

  it('states the name-redaction limitation', () => {
    expect(text(<SummaryPanel fs={OK.forensic_summary} />)).toContain('Other personal names in the body are not reliably detected')
  })
})

describe('P4.1 live fixture (real local-Mistral output, versioned + grounded)', () => {
  it('renders grounded recommendations whose evidence IDs all exist', async () => {
    const live = (await import('./__fixtures__/assessment_p41_live.json')).default as unknown as Assessment
    const fs = live.forensic_summary!
    const ids = new Set((fs.evidence ?? []).map((e) => e.id))
    for (const r of fs.recommendations ?? []) for (const id of r.evidence_ids) expect(ids.has(id)).toBe(true)
    const t = text(<SummaryPanel fs={fs} />)
    expect(t).toContain('General investigative recommendations')
    expect(t).not.toContain('generated before recommendation grounding')
    expect(live.version).toBe(1)
    expect(text(<ShapPanel explanation={live.explanation} ml={live.ml} />)).toContain('Why the ensemble still predicts this class')
  })
})

describe('P4.2 constrained recommendations', () => {
  const GENERAL = [
    { text: 'Verify any unusual payment, bank-detail, invoice or supplier request through a previously established, independently verified communication channel.', kind: 'general', origin: 'system', category: 'independent_verification', evidence_ids: [] },
    { text: 'Do not reply to the suspicious email, and do not use telephone numbers, links, attachments or contact details contained in it for verification.', kind: 'general', origin: 'system', category: 'do_not_use_email_contacts', evidence_ids: [] },
  ]
  const fin = {
    detected: true, evidence_signals: [{ evidence_id: 'E3', term: 'wire' }], email_text_terms: ['iban'], ml_label_fraud: true,
    warning: 'This email concerns payments, bank details, invoices or suppliers. Do not act on it.',
  }
  const p42 = (over: Record<string, unknown> = {}) => ({
    ...clone().forensic_summary!,
    recommendation_policy: 'p4.2-constrained',
    financial_context: fin,
    recommendations: [
      { text: 'Investigate the mismatch between the From and Reply-To domains as a possible reply-diversion attempt. Do not send anything to either address.', kind: 'evidence_linked', origin: 'system_template', category: 'reply_to_mismatch', evidence_ids: ['E7'], model_suggestions: ['Investigate the Reply-To mismatch.'] },
      ...GENERAL,
    ],
    rejected_recommendations: [{ text: 'Reply to the sender to confirm the wire transfer.', reason: 'unsafe: replies to the suspicious email', category: 'unsafe' }],
    ...over,
  })

  it('labels template advice, never presents general advice as a finding, and shows rejection reasons openly', () => {
    const out = html(<SummaryPanel fs={p42()} />)
    const t = text(<SummaryPanel fs={p42()} />)
    expect(t).toContain('Evidence-linked recommendations (system template; evidence IDs chosen deterministically, not by the model)')
    expect(t).toContain('General recommendations (system templates: standard practice, not findings, not AI-discovered)')
    expect(t).toContain('1 model suggestion(s) rejected as unsafe or unsupported. Shown for transparency; do not follow.')
    expect(t).toContain('unsafe: replies to the suspicious email')
    expect(out).toMatch(/<details open=""/)
    expect(out).toContain('href="#evidence-E7"')
    expect(t).not.toContain('(model)')
  })

  it('shows the independent-verification warning prominently in the AI tab', () => {
    const a = { ...clone(), forensic_summary: p42() }
    const out = html(<AssessmentView assessment={a} loading={false} error={null} generating={false} generateError={null} onGenerate={() => undefined} />)
    expect(out).toContain('data-testid="financial-warning"')
    expect(out).toContain('role="alert"')
    expect(out.indexOf('financial-warning')).toBeLessThan(out.indexOf('>ML classification</h2>'))
    expect(text(<FinancialWarning fs={p42()} />)).toContain('Signals: wire, iban')
  })

  it('no warning without detected financial context (never invented)', () => {
    expect(html(<FinancialWarning fs={p42({ financial_context: { ...fin, detected: false, warning: null } })} />)).toBe('')
    expect(html(<FinancialWarning fs={clone().forensic_summary} />)).toBe('')
  })

  it('general advice and the warning still render when the LLM did not run', () => {
    const failed = p42({ status: 'timeout', summary: null, assessment: null, findings: [], recommendations: GENERAL, rejected_recommendations: [] })
    const t = text(<SummaryPanel fs={failed} />)
    expect(t).toContain('did not answer within the time limit')
    expect(t).toContain('General recommendations (system templates')
    expect(t).not.toContain('Evidence-linked recommendations')
    expect(text(<FinancialWarning fs={failed} />)).toContain('Independent verification required')
  })
})
