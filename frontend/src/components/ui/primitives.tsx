// AIPISH UI primitives (P5u-1). Square, bordered, tonal — see docs/frontend/design-system.md.
// Colour is only used for status (always paired with text) and the single cyan accent.
import { useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react'

export type Tone = 'neutral' | 'accent' | 'ok' | 'warn' | 'danger'

const LED_BG: Record<Tone, string> = {
  neutral: 'bg-muted', accent: 'bg-accent', ok: 'bg-ok', warn: 'bg-warn', danger: 'bg-danger',
}
const TAG: Record<Tone, string> = {
  neutral: 'border-line-strong text-muted bg-surface-2',
  accent: 'border-accent-line text-accent bg-accent-weak',
  ok: 'border-ok-line text-ok bg-ok-weak',
  warn: 'border-warn-line text-warn bg-warn-weak',
  danger: 'border-danger-line text-danger bg-danger-weak',
}

/** Square status light. Always rendered next to a text label (never colour alone). */
export function LED({ tone = 'neutral', className = '' }: { tone?: Tone; className?: string }) {
  return <span aria-hidden className={`inline-block h-2 w-2 shrink-0 ${LED_BG[tone]} ${className}`} data-tone={tone} />
}

/** Text label + square LED. `tone` carries status; the text carries the meaning. */
export function StatusTag({ tone = 'neutral', children, title, led = true }: {
  tone?: Tone; children: ReactNode; title?: string; led?: boolean
}) {
  return (
    <span title={title} data-tone={tone}
          className={`inline-flex h-5 items-center gap-1.5 whitespace-nowrap rounded-sm border px-1.5 font-mono text-xs uppercase tracking-wide ${TAG[tone]}`}>
      {led && <LED tone={tone} />}
      {children}
    </span>
  )
}

export const Badge = StatusTag

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'
const BTN: Record<ButtonVariant, string> = {
  primary: 'border-accent bg-accent text-bg hover:bg-accent-hover hover:border-accent-hover disabled:border-line disabled:bg-surface-2 disabled:text-muted',
  secondary: 'border-line-strong bg-surface-2 text-fg hover:bg-surface-3 disabled:text-muted',
  danger: 'border-danger-line bg-danger-weak text-danger hover:bg-surface-3 disabled:text-muted',
  ghost: 'border-transparent bg-transparent text-muted hover:bg-surface-3 hover:text-fg disabled:text-muted',
}

export function Button({ variant = 'secondary', size = 'md', className = '', ...rest }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: 'sm' | 'md' }) {
  const sz = size === 'sm' ? 'h-7 px-2 text-sm' : 'h-8 px-3 text-sm'
  return (
    <button {...rest}
            className={`inline-flex items-center justify-center gap-1.5 whitespace-nowrap border font-medium transition-colors disabled:cursor-not-allowed ${sz} ${BTN[variant]} ${className}`} />
  )
}

/** Uppercase mono label used for panel titles, table headers and field labels. */
export function Label({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono text-xs uppercase tracking-wider text-muted ${className}`}>{children}</span>
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block font-mono text-xs uppercase tracking-wider text-muted">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-sm text-muted">{hint}</span>}
    </label>
  )
}

const CONTROL = 'h-8 w-full border border-line-strong bg-bg px-2 text-sm text-fg placeholder:text-muted hover:border-muted focus-visible:border-accent'

export function Input({ className = '', ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...rest} className={`${CONTROL} ${className}`} />
}

export function Select({ className = '', children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...rest} className={`${CONTROL} pr-6 ${className}`}>{children}</select>
}

/** Key-value "register" row: label column + value column, aligned across a panel. */
export function KV({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[minmax(5rem,9rem)_1fr] gap-3 border-b border-line py-1.5 last:border-0">
      <dt className="font-mono text-xs uppercase leading-5 tracking-wider text-muted">{label}</dt>
      <dd className={`min-w-0 break-words text-sm text-fg ${mono ? 'font-mono' : ''}`}>{children}</dd>
    </div>
  )
}

export function StatCell({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: Tone }) {
  return (
    <div className="min-w-0 px-4 py-3" data-testid="stat-cell">
      <div className="flex items-center gap-1.5">
        {tone && <LED tone={tone} />}
        <Label>{label}</Label>
      </div>
      <div className="mt-1 font-mono text-xl font-semibold text-fg">{value}</div>
      {sub && <div className="mt-0.5 text-sm text-muted">{sub}</div>}
    </div>
  )
}

export interface TabItem<T extends string> { id: T; label: string }

/** Square tab strip; active tab = tonal fill + accent top rule. Arrow keys move between tabs. */
export function Tabs<T extends string>({ items, active, onChange, label }: {
  items: TabItem<T>[]; active: T; onChange: (id: T) => void; label: string
}) {
  return (
    <div role="tablist" aria-label={label} className="flex overflow-x-auto border-b border-line">
      {items.map((t, i) => {
        const on = t.id === active
        return (
          <button key={t.id} role="tab" aria-selected={on} tabIndex={on ? 0 : -1}
                  onClick={() => onChange(t.id)}
                  onKeyDown={(e) => {
                    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
                    const next = items[(i + (e.key === 'ArrowRight' ? 1 : items.length - 1)) % items.length]
                    onChange(next.id)
                    ;(e.currentTarget.parentElement?.children[items.indexOf(next)] as HTMLElement | undefined)?.focus()
                  }}
                  className={`-mb-px whitespace-nowrap border-x border-t px-3 py-1.5 text-sm ${
 on ? 'border-line border-t-accent bg-surface text-fg' : 'border-transparent text-muted hover:bg-surface-3 hover:text-fg'
 }`}>
            {t.label}
          </button>
        )
      })}
    </div>
  )
}

/** One-line empty state: what is missing, why, what to do next. Never a tall blank box. */
export function EmptyLine({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <p className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1 text-sm text-muted" data-testid="empty-line">
      <span className="font-mono text-xs text-muted" aria-hidden>--</span>
      <span>{children}</span>
      {action}
    </p>
  )
}

/** Raw dumps (headers, hex, JSON): collapsed by default. */
export function CodeBlock({ children, label = 'raw', defaultOpen = false }: { children: string; label?: string; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-line">
      <button onClick={() => setOpen(!open)} aria-expanded={open}
              className="flex w-full items-center justify-between bg-surface-2 px-3 py-1 font-mono text-xs uppercase tracking-wider text-muted hover:bg-surface-3">
        <span>{label}</span><span>{open ? 'hide' : 'show'}</span>
      </button>
      {open && <pre className="max-h-96 overflow-auto bg-bg p-3 font-mono text-sm leading-5 text-fg">{children}</pre>}
    </div>
  )
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="border border-line-strong bg-surface-2 px-1 font-mono text-xs text-fg">{children}</kbd>
}

/** Mono value (IP, hash, domain, evidence id) that copies itself on click. */
export function Mono({ children, copy = true, className = '', display }: {
  children: string; copy?: boolean; className?: string; display?: string
}) {
  const [done, setDone] = useState(false)
  if (!copy) return <span className={`font-mono text-sm ${className}`}>{children}</span>
  return (
    <button type="button" title={done ? 'Copied' : 'Click to copy'} aria-label={`Copy ${children}`}
            onClick={() => {
              void navigator.clipboard?.writeText(children).then(() => setDone(true), () => undefined)
              window.setTimeout(() => setDone(false), 1200)
            }}
            className={`max-w-full break-all text-left font-mono text-sm text-fg hover:bg-surface-3 ${className}`}>
      {display ?? children}
    </button>
  )
}

/** Compact loading placeholder rows (no spinners blocking layout). */
export function SkeletonRows({ rows = 3 }: { rows?: number }) {
  return (
    <div aria-busy="true" aria-label="loading" role="status" className="space-y-2 py-1">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="h-3 w-full bg-surface-2" />)}
    </div>
  )
}

export interface Column<R> {
  key: string
  header: string
  render: (row: R) => ReactNode
  align?: 'left' | 'right'
  mono?: boolean
  className?: string
}

/** Dense table: sticky header, 34px rows, mono header labels, right-aligned numbers. */
export function DataTable<R>({ columns, rows, rowKey, empty, maxHeight, label }: {
  columns: Column<R>[]; rows: R[]; rowKey: (r: R) => string; empty?: ReactNode; maxHeight?: string; label?: string
}) {
  if (rows.length === 0) return <EmptyLine>{empty ?? 'No rows.'}</EmptyLine>
  return (
    <div className="overflow-auto" style={maxHeight ? { maxHeight } : undefined}>
      <table className="w-full border-collapse text-sm" aria-label={label}>
        <thead className="sticky top-0 z-[1] bg-surface">
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col"
                  className={`h-8 border-b border-line px-3 font-mono text-xs font-normal uppercase tracking-wider text-muted ${c.align === 'right' ? 'text-right' : 'text-left'}`}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={rowKey(r)} className="h-row border-b border-line last:border-0 hover:bg-surface-2">
              {columns.map((c) => (
                <td key={c.key}
                    className={`px-3 py-1 align-middle ${c.align === 'right' ? 'text-right' : ''} ${c.mono ? 'font-mono' : ''} ${c.className ?? ''}`}>
                  {c.render(r)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
