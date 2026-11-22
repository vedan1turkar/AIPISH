// Parser cross-check (P5k-lite, R43): a second, independent parser (mail-parser) over the same bytes.
// Informational only — it never changes the rule score, ML output, combined risk or alerts.
import type { AnalysisDetail, CrosscheckStatus } from '../../api/client'
import { DataTable, EmptyLine, KV, Panel, StatusTag, type Tone } from '../ui'

const STATUS: Record<CrosscheckStatus, { tone: Tone; text: string }> = {
  agree: { tone: 'ok', text: 'agree' },
  minor_differences: { tone: 'neutral', text: 'minor differences' },
  security_relevant_differences: { tone: 'warn', text: 'security-relevant differences' },
  unavailable: { tone: 'neutral', text: 'unavailable' },
}
export const CROSSCHECK_EXPLAINER =
  'Two independent parsers read the same bytes. Differences can indicate parser-differential evasion (a gateway and a ' +
  'mail client seeing different senders, attachments or MIME structure) but are often harmless decoding differences. ' +
  'This check does not change the score, ML output, combined risk or alerts.'

export default function ParserCrosscheckPanel({ analysis }: { analysis: AnalysisDetail }) {
  const cc = analysis.parser_crosscheck
  const redacted = analysis.retention_state === 'redacted'
  const st = cc ? STATUS[cc.status] ?? STATUS.unavailable : null
  return (
    <Panel title="Parser cross-check · informational" bodyClassName="p-0"
           status={redacted ? <StatusTag tone="warn">redacted</StatusTag> : st ? <StatusTag tone={st.tone}>{st.text}</StatusTag> : undefined}>
      <div data-testid="parser-crosscheck">
        {redacted ? (
          <div className="p-3"><EmptyLine>Parser cross-check: redacted per retention policy.</EmptyLine></div>
        ) : !cc ? (
          <div className="p-3"><EmptyLine>Not recorded for this analysis (it was stored before the cross-check existed).</EmptyLine></div>
        ) : (
          <>
            <dl className="px-3 pt-2">
              <KV label="Parsers" mono>{cc.primary} · {cc.secondary} {cc.secondary_version ?? ''}</KV>
              {cc.compared && (
                <KV label="Compared" mono>
                  hops {cc.compared.received_hops.join(' / ')} · attachments {cc.compared.attachments.join(' / ')} · body parts {cc.compared.body_parts.join(' / ')}
                </KV>)}
              {cc.status === 'unavailable' && <KV label="Reason">{cc.reason ?? 'not reported'}</KV>}
            </dl>
            {cc.differences.length > 0 ? (
              <DataTable
                label="Parser differences"
                rows={cc.differences}
                rowKey={(d) => d.evidence_id}
                columns={[
                  { key: 'id', header: 'ID', mono: true, render: (d) => d.evidence_id },
                  { key: 'field', header: 'Field', mono: true, className: 'whitespace-nowrap', render: (d) => d.field },
                  { key: 'sev', header: 'Severity', render: (d) => (
                    <StatusTag tone={d.severity === 'security_relevant' ? 'warn' : 'neutral'}>{d.severity.replace('_', ' ')}</StatusTag>) },
                  { key: 'desc', header: 'Description', className: 'w-full', render: (d) => d.description },
                ]}
              />
            ) : cc.status !== 'unavailable' ? (
              <div className="px-3"><EmptyLine>Both parsers produced the same normalised view of every compared field.</EmptyLine></div>
            ) : null}
          </>
        )}
        <p className="border-t border-line px-3 py-2 text-sm text-muted">{CROSSCHECK_EXPLAINER}</p>
      </div>
    </Panel>
  )
}
