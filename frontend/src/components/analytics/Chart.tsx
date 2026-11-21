// Token-themed Plotly chart (P5g). Plotly is loaded lazily (its own chunk) the first time a chart renders.
// Every chart has a text summary (aria-label), a data-table toggle, and degrades to the table if Plotly
// cannot load. No mode bar, no logo links, no animation, square bars, transparent background.
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Button, EmptyLine, Panel } from '../ui'
import { CHART_THEME } from '../graph/style'

export interface Series { x: (string | number)[]; y: number[]; colors?: string[]; name?: string }

export interface ChartProps {
  title: string
  summary: string                 // text alternative read by assistive tech
  kind: 'bar' | 'hbar' | 'line'
  series: Series
  table: { headers: [string, string]; rows: [ReactNode, ReactNode][] }
  className?: string
  height?: number
  note?: ReactNode
  empty?: string
}

let plotlyPromise: Promise<typeof import('plotly.js-basic-dist-min').default> | null = null
export function loadPlotly() {
  plotlyPromise ??= import('plotly.js-basic-dist-min').then((m) => m.default)
  return plotlyPromise
}

function layout(kind: ChartProps['kind'], height: number, n: number, max: number): Record<string, unknown> {
  const axis = {
    color: CHART_THEME.text, gridcolor: CHART_THEME.grid, linecolor: CHART_THEME.axis, zerolinecolor: CHART_THEME.axis,
    tickfont: { family: CHART_THEME.font, size: 10, color: CHART_THEME.text }, automargin: true, fixedrange: true,
  }
  // counts are integers: whole-number ticks only (no 0.5 steps on small values)
  const counts = { tickformat: 'd', dtick: Math.max(1, Math.ceil(max / 5)), rangemode: 'tozero' }
  return {
    height, autosize: true, showlegend: false, bargap: n <= 3 ? 0.55 : 0.25, dragmode: false, hovermode: 'closest',
    paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)',
    font: { family: CHART_THEME.font, size: 11, color: CHART_THEME.text },
    margin: { l: kind === 'hbar' ? 8 : 36, r: 12, t: 6, b: kind === 'hbar' ? 24 : 36 },
    hoverlabel: { bgcolor: 'rgba(16,22,29,0.95)', bordercolor: CHART_THEME.axis,
                  font: { family: CHART_THEME.font, size: 11, color: CHART_THEME.strong } },
    xaxis: { ...axis, showgrid: kind === 'hbar', ...(kind === 'line' ? { type: 'category', nticks: Math.min(n, 8) } : {}),
             ...(kind === 'hbar' ? counts : {}) },
    yaxis: { ...axis, showgrid: kind !== 'hbar', ...(kind === 'hbar' ? { autorange: 'reversed', type: 'category' } : counts) },
    transition: { duration: 0 },
  }
}

function traces(kind: ChartProps['kind'], s: Series): unknown[] {
  if (kind === 'line') {
    return [{ type: 'scatter', mode: 'lines+markers', x: s.x, y: s.y, line: { color: CHART_THEME.bar, width: 1.5, shape: 'linear' },
              marker: { color: CHART_THEME.bar, size: 4, symbol: 'square' }, hovertemplate: '%{x}: %{y}<extra></extra>' }]
  }
  const colors = s.colors ?? s.x.map(() => CHART_THEME.bar)
  return [{
    type: 'bar', orientation: kind === 'hbar' ? 'h' : 'v',
    x: kind === 'hbar' ? s.y : s.x, y: kind === 'hbar' ? s.x : s.y,
    marker: { color: colors, line: { width: 0 } },
    hovertemplate: kind === 'hbar' ? '%{y}: %{x}<extra></extra>' : '%{x}: %{y}<extra></extra>',
    text: s.y.map(String), textposition: 'outside', cliponaxis: false,
    textfont: { family: CHART_THEME.font, size: 10, color: CHART_THEME.strong },
  }]
}

export default function Chart({ title, summary, kind, series, table, className = '', height = 220, note, empty }: ChartProps) {
  const el = useRef<HTMLDivElement>(null)
  const [asTable, setAsTable] = useState(false)
  const [failed, setFailed] = useState(false)
  const hasData = series.y.some((v) => v > 0)

  useEffect(() => {
    const node = el.current
    if (!node || asTable || !hasData) return
    let alive = true
    loadPlotly().then((Plotly) => {
      if (!alive) return
      void Plotly.react(node, traces(kind, series),
                        layout(kind, kind === 'hbar' ? Math.max(height, 26 * series.x.length + 40) : height, series.x.length,
                               Math.max(0, ...series.y)),
                        { displayModeBar: false, displaylogo: false, responsive: true, staticPlot: false, showTips: false,
                          showLink: false, sendData: false, showEditInChartStudio: false, typesetMath: false })
    }).catch(() => alive && setFailed(true))
    return () => {
      alive = false
      void loadPlotly().then((Plotly) => Plotly.purge(node)).catch(() => undefined)
    }
  }, [kind, series, asTable, hasData, height])

  const showTable = asTable || failed
  return (
    <Panel title={title} className={className}
           status={hasData ? (
             <Button size="sm" variant="ghost" aria-pressed={asTable} onClick={() => setAsTable((v) => !v)}
                     aria-label={`${asTable ? 'Show chart' : 'Show data table'} for ${title}`}>
               {asTable ? 'chart' : 'table'}
             </Button>) : undefined}>
      {!hasData ? <EmptyLine>{empty ?? 'No data in this window.'}</EmptyLine> : showTable ? (
        <div>
          {failed && <p className="mb-2 text-sm text-muted">The chart could not be drawn; showing the data table.</p>}
          <table className="w-full text-sm" aria-label={`${title} data`}>
            <thead><tr className="font-mono text-xs uppercase tracking-wider text-muted">
              <th className="h-7 border-b border-line text-left font-normal">{table.headers[0]}</th>
              <th className="h-7 border-b border-line text-right font-normal">{table.headers[1]}</th>
            </tr></thead>
            <tbody>
              {table.rows.map(([a, b], i) => (
                <tr key={i} className="border-b border-line last:border-0">
                  <td className="py-1 pr-2">{a}</td><td className="py-1 text-right font-mono">{b}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div ref={el} className="aipish-chart w-full" role="img" aria-label={summary} data-testid="chart" />
      )}
      {note && <div className="mt-2 text-sm text-muted">{note}</div>}
    </Panel>
  )
}
