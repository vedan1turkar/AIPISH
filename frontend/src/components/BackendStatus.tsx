import { useEffect, useState } from 'react'
import { getHealth, type HealthResponse } from '../api/client'

type State =
  | { kind: 'loading' }
  | { kind: 'ok'; data: HealthResponse }
  | { kind: 'error'; message: string }

export default function BackendStatus() {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    getHealth(controller.signal)
      .then((data) => setState({ kind: 'ok', data }))
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        setState({ kind: 'error', message: err instanceof Error ? err.message : 'Unknown error' })
      })
    return () => controller.abort()
  }, [])

  if (state.kind === 'loading') {
    return (
      <span className="whitespace-nowrap rounded-full bg-gray-100 px-2 py-0.5 text-[11px] text-gray-400">
        backend…
      </span>
    )
  }
  if (state.kind === 'error') {
    return (
      <span
        title={`Backend unreachable: ${state.message}`}
        className="whitespace-nowrap rounded-full bg-red-100 px-2 py-0.5 text-[11px] font-medium text-red-700"
      >
        ⚠ backend offline
      </span>
    )
  }
  const degraded = !state.data.db_connected || state.data.status !== 'ok'
  return (
    <span
      title={`v${state.data.version} · env ${state.data.env} · db ${
        state.data.db_connected ? 'connected' : 'unavailable'
      }`}
      className={`whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium ${
        degraded ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-700'
      }`}
    >
      {degraded ? '⚠ backend degraded' : '● backend online'}
    </span>
  )
}
