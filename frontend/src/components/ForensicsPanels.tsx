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
          <span className="text-xs text-gray-400">{chain.length} hop{chain.length === 1 ? '' : 's'}</span>
        ) : undefined
      }
    >
      <div className="space-y-4">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Relay path</h3>
          {chain.length === 0 ? (
            <div className="mt-2">
              <EmptyState
                icon="🔀"
                title="No relay hops found"
                hint="No Received headers are present. The message's transport path cannot be reconstructed from the available evidence."
              />
            </div>
          ) : (
            <ol className="mt-2 space-y-2">
              {chain.map((hop, i) => (
                <li
                  key={hop.index ?? i}
                  className={`relative rounded-lg border p-3 pl-9 ${
                    hop.trusted ? 'border-emerald-200 bg-emerald-50/40' : 'border-gray-200 bg-white'
                  }`}
                >
                  <span
                    className={`absolute left-3 top-3 flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold text-white ${
                      hop.trusted ? 'bg-emerald-500' : 'bg-gray-400'
                    }`}
                  >
                    {hop.index ?? i + 1}
                  </span>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="font-mono text-sm text-gray-900">
                      {hop.from_ip ?? hop.from_host ?? 'unknown'}
                    </span>
                    {hop.from_ip_category && (
                      <span className="text-xs text-gray-400">{hop.from_ip_category}</span>
                    )}
                    {hop.tls && (
                      <span className="rounded bg-teal-50 px-1.5 py-0.5 text-[11px] text-teal-700 ring-1 ring-inset ring-teal-200">
                        TLS
                      </span>
                    )}
                    <span className="ml-auto"><StatusBadge kind={hop.trusted ? 'verified' : 'inferred'} /></span>
                  </div>
                  {hop.by_host && <p className="mt-1 text-xs text-gray-500">received by <span className="font-mono">{hop.by_host}</span></p>}
                  {hop.timestamp && <p className="text-xs text-gray-400">{formatDate(hop.timestamp)}</p>}
                  {hop.confidence_reasons.length > 0 && (
                    <ul className="mt-1 list-disc pl-4 text-xs text-gray-400">
                      {hop.confidence_reasons.map((r, j) => (
                        <li key={j}>{r}</li>
                      ))}
                    </ul>
                  )}
                  {hop.notes.length > 0 && (
                    <ul className="mt-1 list-disc pl-4 text-xs text-amber-700">
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
            {data.trusted_boundary_index != null ? `hop ${data.trusted_boundary_index}` : <span className="text-gray-400">not determined</span>}
          </MetaRow>
          <MetaRow label="Candidate IPs">
            {data.candidate_ips.length > 0 ? (
              <span className="font-mono text-xs">{data.candidate_ips.join(', ')}</span>
            ) : (
              <span className="text-gray-400">none observed</span>
            )}
          </MetaRow>
          <MetaRow label="Earliest candidate sender">
            {data.earliest_candidate_ip ? (
              <>
                <span className="font-mono">{data.earliest_candidate_ip}</span>{' '}
                <StatusBadge kind="inferred" title="Earliest IP seen in Received chain — reconstructed, may be forged" />
              </>
            ) : (
              <span className="text-gray-400">not determined</span>
            )}
          </MetaRow>
          <MetaRow label="Verified originating IP">
            {data.verified_originating_ip ? (
              <>
                <span className="font-mono">{data.verified_originating_ip}</span>{' '}
                <StatusBadge kind="verified" title="Confirmed independently (e.g. via SPF correlation)" />
              </>
            ) : (
              <span className="text-gray-400">not confirmed</span>
            )}
          </MetaRow>
        </div>

        {data.forgery_note && (
          <p className="rounded-md bg-gray-50 px-3 py-2 text-xs text-gray-600">{data.forgery_note}</p>
        )}
        {data.disclaimer && (
          <p className="text-xs italic text-gray-400">{data.disclaimer}</p>
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
          <span className="text-xs text-gray-400">{incs.length} finding{incs.length === 1 ? '' : 's'}</span>
        ) : undefined
      }
    >
      {incs.length === 0 ? (
        <EmptyState
          icon="✔️"
          title="No header anomalies detected"
          hint="Received-chain structure, address relationships and timestamp order looked internally consistent."
        />
      ) : (
        <ul className="space-y-2">
          {incs.map((inc, i) => (
            <li key={inc.rule_id ?? i} className="rounded-lg border border-gray-200 p-3">
              <div className="flex items-center gap-2">
                <SeverityChip severity={inc.severity} />
                <span className="font-mono text-xs text-gray-400">{inc.rule_id}</span>
              </div>
              <p className="mt-1.5 text-sm text-gray-800">{inc.evidence}</p>
              <p className="mt-1 text-xs text-gray-500">{inc.rationale}</p>
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
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">URLs</h3>
          {analysis.urls.length === 0 ? (
            <p className="mt-1 text-sm text-gray-400">None extracted from the message body.</p>
          ) : (
            <ul className="mt-1 divide-y divide-gray-100">
              {analysis.urls.map((u, i) => (
                <li key={i} className="flex flex-wrap items-center gap-x-3 py-1.5 text-xs">
                  <span className="font-mono break-all text-gray-800">{u.url}</span>
                  {u.in_text && <span className="text-gray-400">text part</span>}
                  {u.in_html && <span className="text-gray-400">HTML part</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Attachments (metadata only)</h3>
          {analysis.attachments.length === 0 ? (
            <p className="mt-1 text-sm text-gray-400">No attachments detected.</p>
          ) : (
            <ul className="mt-1 divide-y divide-gray-100">
              {analysis.attachments.map((a, i) => (
                <li key={i} className="py-1.5 text-xs text-gray-800">
                  <span className="font-medium">{a.filename || '(unnamed)'}</span>{' '}
                  <span className="text-gray-400">
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
