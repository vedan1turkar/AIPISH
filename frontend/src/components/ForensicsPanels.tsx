import type { Forensics, AnalysisDetail } from '../api/client'
import {
  EmptyState,
  MetaRow,
  Panel,
  SeverityChip,
  StatusBadge,
  formatDate,
} from './ui'

export function HeaderForensicsPanel({ data }: { data: Forensics }) {
  const chain = data.relay_chain ?? []
  return (
    <Panel
      title="Header forensics"
      status={
        chain.length > 0 ? (
          <span className="text-xs text-muted">{chain.length} hop{chain.length === 1 ? '' : 's'}</span>
        ) : undefined
      }
    >
      <div className="space-y-4">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Relay path</h3>
          {chain.length === 0 ? (
            <div className="mt-2">
              <EmptyState
                title="No relay hops found"
                hint="No Received headers are present. The message's transport path cannot be reconstructed from the available evidence."
              />
            </div>
          ) : (
            <ol className="mt-2 border-y border-line">
              {chain.map((hop, i) => (
                <li
                  key={hop.index ?? i}
                  className={`relative border-b border-l-2 border-b-line py-2 pl-10 pr-2 last:border-b-0 ${
                    hop.trusted ? 'border-l-ok' : 'border-l-transparent'
                  }`}
                >
                  <span
                    className={`absolute left-2 top-2 flex h-5 min-w-[1.5rem] items-center justify-center border font-mono text-xs ${
                      hop.trusted ? 'border-ok-line text-ok' : 'border-line-strong text-muted'
                    }`}
                  >
                    {hop.index ?? i + 1}
                  </span>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="font-mono text-sm text-fg">
                      {hop.from_ip ?? hop.from_host ?? 'unknown'}
                    </span>
                    {hop.from_ip_category && (
                      <span className="text-xs text-muted">{hop.from_ip_category}</span>
                    )}
                    {hop.tls && (
                      <span className=" bg-ok-weak px-1.5 py-0.5 text-xs text-ok border border-ok-line">
                        TLS
                      </span>
                    )}
                    <span className="ml-auto"><StatusBadge kind={hop.trusted ? 'verified' : 'inferred'} /></span>
                  </div>
                  {hop.by_host && <p className="mt-1 text-xs text-muted">received by <span className="font-mono">{hop.by_host}</span></p>}
                  {hop.timestamp && <p className="text-xs text-muted">{formatDate(hop.timestamp)}</p>}
                  {hop.confidence_reasons.length > 0 && (
                    <ul className="mt-1 list-disc pl-4 text-xs text-muted">
                      {hop.confidence_reasons.map((r, j) => (
                        <li key={j}>{r}</li>
                      ))}
                    </ul>
                  )}
                  {hop.notes.length > 0 && (
                    <ul className="mt-1 list-disc pl-4 text-xs text-warn">
                      {hop.notes.map((n, j) => (
                        <li key={j}>{n}</li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ol>
          )}
        </div>

        <div className="grid gap-x-6 gap-y-0 sm:grid-cols-2">
          <MetaRow label="Trusted boundary">
            {data.trusted_boundary_index != null ? `hop ${data.trusted_boundary_index}` : <span className="text-muted">not determined</span>}
          </MetaRow>
          <MetaRow label="Candidate IPs">
            {data.candidate_ips.length > 0 ? (
              <span className="font-mono text-xs">{data.candidate_ips.join(', ')}</span>
            ) : (
              <span className="text-muted">none observed</span>
            )}
          </MetaRow>
          <MetaRow label="Earliest candidate sender">
            {data.earliest_candidate_ip ? (
              <>
                <span className="font-mono">{data.earliest_candidate_ip}</span>{' '}
                <StatusBadge kind="inferred" title="Earliest IP seen in Received chain — reconstructed, may be forged" />
              </>
            ) : (
              <span className="text-muted">not determined</span>
            )}
          </MetaRow>
          <MetaRow label="Verified originating IP">
            {data.verified_originating_ip ? (
              <>
                <span className="font-mono">{data.verified_originating_ip}</span>{' '}
                <StatusBadge kind="verified" title="Confirmed independently (e.g. via SPF correlation)" />
              </>
            ) : (
              <span className="text-muted">not confirmed</span>
            )}
          </MetaRow>
        </div>

        {data.forgery_note && (
          <p className=" bg-surface-2 px-3 py-2 text-xs text-muted">{data.forgery_note}</p>
        )}
        {data.disclaimer && (
          <p className="text-xs italic text-muted">{data.disclaimer}</p>
        )}
      </div>
    </Panel>
  )
}

export function AnomaliesPanel({ data }: { data: Forensics }) {
  const incs = data.inconsistencies ?? []
  return (
    <Panel
      title="Header anomalies"
      status={
        incs.length > 0 ? (
          <span className="text-xs text-muted">{incs.length} finding{incs.length === 1 ? '' : 's'}</span>
        ) : undefined
      }
    >
      {incs.length === 0 ? (
        <EmptyState
          title="No header anomalies detected"
          hint="Received-chain structure, address relationships and timestamp order looked internally consistent."
        />
      ) : (
        <ul className="divide-y divide-line">
          {incs.map((inc, i) => (
            <li key={inc.rule_id ?? i} className="py-2.5 first:pt-0 last:pb-0">
              <div className="flex items-center gap-2">
                <SeverityChip severity={inc.severity} />
                <span className="font-mono text-xs text-muted">{inc.rule_id}</span>
              </div>
              <p className="mt-1 font-mono text-sm text-fg">{inc.evidence}</p>
              <p className="mt-0.5 text-sm text-muted">{inc.rationale}</p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

export function IntelligenceDetailsPanel({
  analysis,
}: {
  analysis: AnalysisDetail
}) {
  // Deep-dive rows (URLs / attachments metadata) — always honest about presence.
  return (
    <Panel title="Extracted indicators (observed facts)">
      <div className="space-y-4">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">URLs</h3>
          {analysis.urls.length === 0 ? (
            <p className="mt-1 text-sm text-muted">None extracted from the message body.</p>
          ) : (
            <ul className="mt-1 divide-y divide-line">
              {analysis.urls.map((u, i) => (
                <li key={i} className="flex flex-wrap items-center gap-x-3 py-1.5 text-xs">
                  <span className="font-mono break-all text-fg">{u.url}</span>
                  {u.in_text && <span className="text-muted">text part</span>}
                  {u.in_html && <span className="text-muted">HTML part</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Attachments (metadata only)</h3>
          {analysis.attachments.length === 0 ? (
            <p className="mt-1 text-sm text-muted">No attachments detected.</p>
          ) : (
            <ul className="mt-1 divide-y divide-line">
              {analysis.attachments.map((a, i) => (
                <li key={i} className="py-1.5 text-xs text-fg">
                  <span className="font-medium">{a.filename || '(unnamed)'}</span>{' '}
                  <span className="text-muted">
                    — {a.content_type}, {formatBytes(a.size_bytes)}, sha256 {a.sha256.slice(0, 12)}…
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Panel>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
