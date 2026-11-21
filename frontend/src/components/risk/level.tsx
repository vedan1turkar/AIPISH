// Combined risk level (P5h): shared tone map and compact tag. Always paired with text; never a probability.
import type { RiskLevel } from '../../api/client'
import { StatusTag, type Tone } from '../ui'

export const LEVEL_TONE: Record<RiskLevel, Tone> = {
  minimal: 'ok', low: 'neutral', medium: 'warn', high: 'danger', critical: 'danger', indeterminate: 'neutral',
}

export function RiskLevelTag({ level, score }: { level?: RiskLevel | null; score?: number | null }) {
  if (!level) return <span className="text-muted">not computed</span>
  return (
    <StatusTag tone={LEVEL_TONE[level]} title="Combined risk index (0-100), not a probability">
      {level}{typeof score === 'number' ? ` ${score}` : ''}
    </StatusTag>
  )
}
