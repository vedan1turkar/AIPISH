// @vitest-environment jsdom
// P5u-1: design-system primitives + source guards (square corners, no emoji, radius scale).
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import {
  Button, CodeBlock, DataTable, EmptyLine, KV, LED, Mono, Panel, SeverityChip, StatCell, StatusBadge, StatusTag, Tabs,
} from './index'
import tailwindConfig from '../../../tailwind.config.js'

afterEach(cleanup)

describe('primitives', () => {
  it('StatusTag pairs a square LED with a text label for every tone', () => {
    for (const tone of ['neutral', 'accent', 'ok', 'warn', 'danger'] as const) {
      const { container, unmount } = render(<StatusTag tone={tone}>label {tone}</StatusTag>)
      const tag = container.firstElementChild as HTMLElement
      expect(tag.dataset.tone).toBe(tone)
      expect(tag.textContent).toBe(`label ${tone}`)                      // meaning is in the text
      expect(tag.querySelector('[data-tone]')?.className).toContain('h-2 w-2')   // square LED
      unmount()
    }
  })

  it('StatusBadge and SeverityChip keep their text labels (never colour alone)', () => {
    render(<><StatusBadge kind="verified_fail" /><SeverityChip severity="high" /></>)
    expect(screen.getByText('Verified — fail')).toBeTruthy()
    expect(screen.getByText('High')).toBeTruthy()
  })

  it('Button variants and disabled state', () => {
    const onClick = vi.fn()
    render(<><Button variant="primary" onClick={onClick}>Go</Button><Button variant="danger" disabled>Stop</Button></>)
    fireEvent.click(screen.getByText('Go'))
    expect(onClick).toHaveBeenCalledOnce()
    expect(screen.getByText('Go').className).toContain('bg-accent')
    expect((screen.getByText('Stop') as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText('Stop').className).toContain('text-danger')
  })

  it('Panel renders a title strip with a meta slot and is labelled for assistive tech', () => {
    render(<Panel title="Relay path" status={<span>4 hops</span>}><p>body</p></Panel>)
    const panel = screen.getByRole('region', { name: 'Relay path' })
    expect(panel.querySelector('h2')?.className).toContain('uppercase')
    expect(panel.textContent).toContain('4 hops')
  })

  it('Tabs: aria-selected, click and arrow-key navigation', () => {
    const onChange = vi.fn()
    render(<Tabs label="Sections" active="a" onChange={onChange}
                 items={[{ id: 'a', label: 'Alpha' }, { id: 'b', label: 'Beta' }]} />)
    expect(screen.getByRole('tablist', { name: 'Sections' })).toBeTruthy()
    expect(screen.getByRole('tab', { name: 'Alpha' }).getAttribute('aria-selected')).toBe('true')
    fireEvent.keyDown(screen.getByRole('tab', { name: 'Alpha' }), { key: 'ArrowRight' })
    expect(onChange).toHaveBeenLastCalledWith('b')
    fireEvent.click(screen.getByRole('tab', { name: 'Beta' }))
    expect(onChange).toHaveBeenLastCalledWith('b')
  })

  it('EmptyLine is one compact line; CodeBlock is collapsed by default', () => {
    render(<><EmptyLine action={<button>Upload</button>}>No analyses yet.</EmptyLine><CodeBlock label="raw headers">{'Received: x'}</CodeBlock></>)
    expect(screen.getByTestId('empty-line').tagName).toBe('P')
    expect(screen.queryByText('Received: x')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /raw headers/ }))
    expect(screen.getByText('Received: x')).toBeTruthy()
  })

  it('KV, StatCell and DataTable (sticky mono header, right-aligned numbers, empty line)', () => {
    const { rerender } = render(
      <>
        <dl><KV label="From">alice@example.test</KV></dl>
        <StatCell label="Analyses" value={42} tone="ok" sub="last 100" />
        <DataTable label="t" rows={[{ id: 'x', n: 7 }]} rowKey={(r) => r.id}
                   columns={[{ key: 'id', header: 'Id', mono: true, render: (r) => r.id },
                             { key: 'n', header: 'Count', align: 'right', render: (r) => r.n }]} />
      </>,
    )
    expect(screen.getByText('From').tagName).toBe('DT')
    expect(screen.getByTestId('stat-cell').textContent).toContain('42')
    const th = screen.getByRole('columnheader', { name: 'Count' })
    expect(th.className).toContain('text-right')
    expect(th.closest('thead')?.className).toContain('sticky')
    rerender(<DataTable label="t" rows={[]} rowKey={() => ''} columns={[]} empty="Nothing here." />)
    expect(screen.getByText('Nothing here.')).toBeTruthy()
  })

  it('Mono copies its full value on click (display may be shortened)', async () => {
    const writeText = vi.fn(() => Promise.resolve())
    Object.assign(navigator, { clipboard: { writeText } })
    render(<Mono display="abcd…">abcdef0123456789</Mono>)
    fireEvent.click(screen.getByRole('button', { name: 'Copy abcdef0123456789' }))
    expect(writeText).toHaveBeenCalledWith('abcdef0123456789')
    expect(screen.getByText('abcd…')).toBeTruthy()
  })

  it('LED is a square status light', () => {
    const { container } = render(<LED tone="danger" />)
    expect(container.firstElementChild?.getAttribute('aria-hidden')).toBe('true')
    expect(container.firstElementChild?.className).toContain('bg-danger')
  })
})

// ── source guards ────────────────────────────────────────────────────────
// every non-test source file under src, as raw text (Vite glob — no Node APIs needed)
const RAW = import.meta.glob(['/src/**/*.{ts,tsx,css}', '!/src/**/*.test.{ts,tsx}'],
                             { query: '?raw', import: 'default', eager: true }) as Record<string, string>

describe('design-rule guards', () => {
  it('no rounded-lg/xl/2xl/3xl/full (or md / bare rounded) classes anywhere in src', () => {
    // Allow-list: none. Small badges may use rounded-sm (2px); LEDs are square.
    const bad: string[] = []
    expect(Object.keys(RAW).length).toBeGreaterThan(30)
    for (const [f, text] of Object.entries(RAW)) {
      for (const m of text.matchAll(/(?<![\w-])rounded(?:-(?:t|b|l|r|tl|tr|bl|br))?(?:-(md|lg|xl|2xl|3xl|full))?(?![\w-])/g)) {
        if (m[1] || m[0] === 'rounded') bad.push(`${f}: ${m[0]}`)
      }
    }
    expect(bad).toEqual([])
  })

  it('no emoji pictographs in UI source', () => {
    const bad: string[] = []
    for (const [f, text] of Object.entries(RAW)) {
      if (/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}]/u.test(text) || text.includes('\u{FE0F}')) bad.push(f)
    }
    expect(bad).toEqual([])
  })

  it('radius scale resolves every rounded-* utility to 0, sm to 2px; shadows off', () => {
    const t = (tailwindConfig as { theme: { borderRadius: Record<string, string>; boxShadow: Record<string, string> } }).theme
    for (const [k, v] of Object.entries(t.borderRadius)) expect(v).toBe(k === 'sm' ? '2px' : '0')
    for (const [k, v] of Object.entries(t.boxShadow)) if (k !== 'pop') expect(v).toBe('none')
  })
})
