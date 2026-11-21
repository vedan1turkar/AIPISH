// Minimal typing for the lazily imported Plotly basic bundle (P5g): only what Chart.tsx uses.
declare module 'plotly.js-basic-dist-min' {
  interface PlotlyBasic {
    react(el: HTMLElement, data: unknown[], layout?: Record<string, unknown>, config?: Record<string, unknown>): Promise<unknown>
    purge(el: HTMLElement): void
    Plots: { resize(el: HTMLElement): void }
  }
  const Plotly: PlotlyBasic
  export default Plotly
}
