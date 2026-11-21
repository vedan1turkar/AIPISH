// P5e: retention / legal-hold / masking state, always as text-paired tags (never colour alone).
import type { RetentionState } from '../../api/client'
import { StatusTag } from '../ui'

export const REDACTED_TEXT = 'content redacted per retention policy'
export const RESTRICTED_TEXT = 'restricted for your role'

export function RetentionTags({ state, held }: { state?: RetentionState; held?: boolean }) {
  if (!state && !held) return null
  return (
    <span className="inline-flex flex-wrap gap-1" data-testid="retention-tags">
      {state === 'redacted' && <StatusTag tone="warn" title={REDACTED_TEXT}>redacted</StatusTag>}
      {state === 'evidence_purged' && <StatusTag tone="neutral" title="Stored evidence bytes removed per retention policy; the SHA-256 is kept">evidence purged</StatusTag>}
      {held && <StatusTag tone="accent" title="Legal hold: exempt from retention and erasure">legal hold</StatusTag>}
    </span>
  )
}

/** A field value the server masked for this role ("restricted") or removed by retention (null on a redacted record). */
export function Restricted({ reason = 'role' }: { reason?: 'role' | 'retention' }) {
  return (
    <StatusTag tone="neutral" title={reason === 'role' ? RESTRICTED_TEXT : REDACTED_TEXT}>
      {reason === 'role' ? 'restricted' : 'redacted'}
    </StatusTag>
  )
}
