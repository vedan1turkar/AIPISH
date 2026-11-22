// Persistent bottom status bar (P5u-1): API health, ML model, and — only for roles allowed to
// read them — LLM and threat-intel configuration. Polls every 30 s; failures show as text.
import { useEffect, useState } from 'react'
import { ApiError, getIntelStatus, getLlmStatus, getMlStatus, getReady, getSystemInfo } from '../../api/client'
import { useAuth } from '../../auth/AuthContext'
import { LED, type Tone } from '../ui'

export const POLL_MS = 30_000
const APP_VERSION = typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : '0.1.0'

interface Cell { key: string; label: string; value: string; tone: Tone }

function clock(d: Date): string {
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })
}

interface Snapshot { cells: Cell[]; backend: string | null }
interface Poller { snap: Snapshot; listeners: Set<(s: Snapshot) => void>; timer: number; alive: boolean }
const EMPTY: Snapshot = { cells: [], backend: null }

// P5z.1: one shared poller per permission set. The status bar and the Overview's system panel both use this
// hook; before, each mounted its own poller, and each restarted whenever the session object was refreshed
// (a new `can` identity), so /health/ready, /system/info and /ml/status were requested several times per load.
// The poller starts with its first user and stops when the last one unmounts.
const pollers = new Map<string, Poller>()

function startPoller(key: string, canMl: boolean, canConfig: boolean, poll: number): Poller {
  const p: Poller = { snap: EMPTY, listeners: new Set(), timer: 0, alive: true }
  const publish = (next: Snapshot) => {
    if (!p.alive) return
    p.snap = next
    p.listeners.forEach((fn) => fn(next))
  }
  const run = async () => {
    const out: Cell[] = []
    // P5g: liveness from the anonymous readiness probe; version from the authenticated /system/info.
    try {
      const h = await getReady()
      out.push({ key: 'api', label: 'API', value: h.status === 'ok' ? 'ok' : h.status, tone: h.status === 'ok' ? 'ok' : 'warn' })
    } catch (err) {
      const answered = err instanceof ApiError && err.status > 0          // 503 = backend up, database not ready
      out.push({ key: 'api', label: 'API', value: answered ? 'unavailable' : 'unreachable', tone: answered ? 'warn' : 'danger' })
    }
    try {
      const info = await getSystemInfo()
      publish({ ...p.snap, backend: info.version })
    } catch {
      /* version cell keeps its last value */
    }
    if (canMl) {
      try {
        const m = await getMlStatus()
        out.push({ key: 'ml', label: 'ML', value: m.status === 'ok' ? `ok ${m.model_version ?? ''}`.trim() : m.status, tone: m.status === 'ok' ? 'ok' : 'warn' })
      } catch {
        out.push({ key: 'ml', label: 'ML', value: 'status unavailable', tone: 'warn' })
      }
    }
    if (canConfig) {
      try {
        const l = await getLlmStatus()
        out.push({ key: 'llm', label: 'LLM', value: l.status === 'ok' ? `ok ${l.model ?? ''}`.trim() : l.status, tone: l.status === 'ok' ? 'ok' : 'warn' })
      } catch {
        out.push({ key: 'llm', label: 'LLM', value: 'status unavailable', tone: 'warn' })
      }
      try {
        const i = await getIntelStatus()
        const mode = i.offline ? 'offline' : i.simulated ? 'simulated' : 'live'
        out.push({ key: 'intel', label: 'INTEL', value: mode, tone: i.offline || i.simulated ? 'warn' : 'ok' })
      } catch {
        out.push({ key: 'intel', label: 'INTEL', value: 'status unavailable', tone: 'warn' })
      }
    }
    publish({ ...p.snap, cells: out })
  }
  pollers.set(key, p)
  void run()
  p.timer = window.setInterval(() => void run(), poll)
  return p
}

export function useSystemStatus(poll = POLL_MS) {
  const { can } = useAuth()
  const canMl = can('ml:status')
  const canConfig = can('config:status')
  const key = `${canMl}|${canConfig}|${poll}`
  const [snap, setSnap] = useState<Snapshot>(() => pollers.get(key)?.snap ?? EMPTY)
  useEffect(() => {
    const p = pollers.get(key) ?? startPoller(key, canMl, canConfig, poll)
    p.listeners.add(setSnap)
    setSnap(p.snap)
    return () => {
      p.listeners.delete(setSnap)
      if (p.listeners.size === 0) {
        p.alive = false
        window.clearInterval(p.timer)
        if (pollers.get(key) === p) pollers.delete(key)
      }
    }
  }, [key, canMl, canConfig, poll])
  return snap
}

export default function StatusBar() {
  const { session } = useAuth()
  const { cells, backend } = useSystemStatus()
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), POLL_MS)
    return () => window.clearInterval(t)
  }, [])
  return (
    <footer role="contentinfo" aria-label="System status"
            className="fixed inset-x-0 bottom-0 z-20 flex h-7 items-center gap-0 overflow-x-auto border-t border-line bg-surface font-mono text-xs text-muted">
      {cells.map((c) => (
        <span key={c.key} data-testid={`status-${c.key}`} className="flex h-full items-center gap-1.5 whitespace-nowrap border-r border-line px-3">
          <LED tone={c.tone} />
          <span className="uppercase">{c.label}</span>
          <span className="text-fg">{c.value}</span>
        </span>
      ))}
      <span className="ml-auto hidden h-full items-center whitespace-nowrap border-l border-line px-3 xl:flex" data-testid="status-user">
        {session?.user.username}@{session?.user.role}
      </span>
      <span className="hidden h-full items-center whitespace-nowrap border-l border-line px-3 xl:flex" data-testid="status-version">
        ui {APP_VERSION}{backend ? ` · api ${backend}` : ''}
      </span>
      <span className="ml-auto flex h-full items-center whitespace-nowrap border-l border-line px-3 xl:ml-0" data-testid="status-time">{clock(now)}</span>
    </footer>
  )
}
