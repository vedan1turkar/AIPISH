// @vitest-environment jsdom
// P5u-1: design-system primitives + source guards (square corners, no emoji, radius scale).
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import {
  Button, CodeBlock, DataTable, EmptyLine, KV, LED, Mono, PageNotice, Panel, SeverityChip, StatCell, StatusBadge, StatusTag, Tabs,
} from './index'
import { KIND_SHAPE, ShapeLegend, baseStyle, shapeFor } from '../graph/style'
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

  it('DataTable: sortable headers toggle asc/desc with aria-sort; compact pagination', () => {
    const rows = Array.from({ length: 30 }, (_, i) => ({ id: `r${String(i).padStart(2, '0')}`, n: (i * 7) % 30 }))
    render(<DataTable label="Rows" rows={rows} rowKey={(r) => r.id} pageSize={10} rowTestId={() => 'data-row'}
                      columns={[{ key: 'id', header: 'Id', mono: true, render: (r) => r.id },
                                { key: 'n', header: 'N', align: 'right', sortValue: (r) => r.n, render: (r) => String(r.n) }]} />)
    expect(screen.getAllByTestId('data-row')).toHaveLength(10)
    const th = screen.getByRole('columnheader', { name: 'N' })
    expect(th.getAttribute('aria-sort')).toBe('none')
    expect(screen.getByRole('columnheader', { name: 'Id' }).getAttribute('aria-sort')).toBeNull()   // not sortable
    fireEvent.click(screen.getByRole('button', { name: 'N' }))
    expect(th.getAttribute('aria-sort')).toBe('ascending')
    expect(screen.getAllByTestId('data-row')[0].textContent).toContain('0')
    fireEvent.click(th.querySelector('button')!)
    expect(th.getAttribute('aria-sort')).toBe('descending')
    expect(screen.getAllByTestId('data-row')[0].lastElementChild?.textContent).toBe('29')
    const nav = screen.getByRole('navigation', { name: 'Rows pagination' })
    expect(nav.textContent).toContain('1–10 of 30')
    expect((screen.getByRole('button', { name: 'Prev' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(nav.textContent).toContain('11–20 of 30')
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('DataTable without pageSize renders every row and no pager', () => {
    render(<DataTable label="All" rows={[{ id: 'a' }, { id: 'b' }]} rowKey={(r) => r.id} columns={[{ key: 'id', header: 'Id', render: (r) => r.id }]} />)
    expect(screen.getAllByRole('row')).toHaveLength(3)
    expect(screen.queryByRole('navigation')).toBeNull()
  })

  it('PageNotice: labelled region, status code, one line and actions', () => {
    render(<PageNotice title="Page not found" code="404" actions={<Button>Go</Button>}>Nothing here.</PageNotice>)
    const r = screen.getByRole('region', { name: 'Page not found' })
    expect(r.textContent).toContain('404')
    expect(r.textContent).toContain('Nothing here.')
    expect(screen.getByRole('button', { name: 'Go' })).toBeTruthy()
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

  it('no legacy Tailwind palette classes (gray-500, bg-white, red-50…) anywhere in src: semantic tokens only', () => {
    const PALETTE = /(?<![\w-])(?:[a-z-]+:)*(?:bg|text|border|ring|divide|fill|stroke|outline|placeholder|decoration|from|via|to|shadow|accent|caret)-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}(?![\w-])|(?<![\w-])(?:bg|text|border)-white(?![\w-])/g
    const bad: string[] = []
    for (const [f, text] of Object.entries(RAW)) for (const m of text.matchAll(PALETTE)) bad.push(`${f}: ${m[0]}`)
    expect(bad).toEqual([])
  })

  it('hex colours live only in the token sources (index.css) and the graph theme module', () => {
    const bad: string[] = []
    for (const [f, text] of Object.entries(RAW)) {
      if (f.endsWith('/index.css') || f.endsWith('/graph/style.tsx')) continue
      for (const m of text.matchAll(/['"`(:\s]#[0-9a-fA-F]{6}\b/g)) bad.push(`${f}: ${m[0].trim()}`)
    }
    expect(bad).toEqual([])
  })

  it('guards cover the whole tree (every page, graph and shell module is scanned)', () => {
    const files = Object.keys(RAW)
    for (const must of ['/src/App.tsx', '/src/components/UploadPage.tsx', '/src/components/HistoryPage.tsx',
      '/src/components/cases/CasePage.tsx', '/src/components/correlation/CampaignsPage.tsx', '/src/components/search/SearchPage.tsx',
      '/src/components/admin/AdminUsersPage.tsx', '/src/components/trace/TraceView.tsx', '/src/components/graph/style.tsx',
      '/src/components/auth/LoginPage.tsx', '/src/components/auth/ChangePasswordPage.tsx', '/src/index.css']) {
      expect(files).toContain(must)
    }
  })

  it('radius scale resolves every rounded-* utility to 0, sm to 2px; shadows off', () => {
    const t = (tailwindConfig as { theme: { borderRadius: Record<string, string>; boxShadow: Record<string, string> } }).theme
    for (const [k, v] of Object.entries(t.borderRadius)) expect(v).toBe(k === 'sm' ? '2px' : '0')
    for (const [k, v] of Object.entries(t.boxShadow)) if (k !== 'pop') expect(v).toBe('none')
  })
})

describe('graph theme', () => {
  it('shapes: analyses/messages are rectangles, IPs diamonds, domains squares; no hexagon, ellipse or rounded shapes', () => {
    expect(shapeFor('message').shape).toBe('rectangle')
    expect(shapeFor('analysis').shape).toBe('rectangle')
    expect(shapeFor('ip').shape).toBe('diamond')
    expect(shapeFor('public_ip').shape).toBe('diamond')
    const d = shapeFor('sender_domain')
    expect([d.shape, d.width === d.height]).toEqual(['rectangle', true])
    for (const k of [...Object.keys(KIND_SHAPE), 'unknown_kind']) {
      expect(shapeFor(k).shape).toMatch(/^(rectangle|diamond)$/)
    }
  })

  it('base stylesheet: 1px borders, mono labels, muted 1px edges, accent selection', () => {
    const css = baseStyle() as { selector: string; style: Record<string, unknown> }[]
    const by = (s: string) => css.find((c) => c.selector === s)!.style
    expect(by('node')['border-width']).toBe(1)
    expect(String(by('node')['font-family'])).toContain('IBM Plex Mono')
    expect(by('edge').width).toBe(1)
    expect(by('edge')['line-color']).toBe('#3a4757')
    expect(by(':selected')['border-color']).toBe('#4cc9f0')
  })

  it('legend renders a shape glyph and a text label per kind', () => {
    render(<ShapeLegend items={[{ kind: 'ip', label: 'IP address' }, { kind: 'domain', label: 'domain' }]} />)
    const list = screen.getByRole('list', { name: 'Node types' })
    expect(list.textContent).toBe('IP addressdomain')
    expect(list.querySelectorAll('svg')).toHaveLength(2)
  })
})
