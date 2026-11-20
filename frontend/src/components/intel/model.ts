// Threat-intel display model (P5a). Each backend status keeps its own label,
// icon and colour. Statuses are never merged, and "no record" or "no flags" is
// never worded as clean or safe.
import type { IntelResult } from '../../api/client'
import { formatDate } from '../ui'

export interface StatusMeta {
  label: string
  icon: string
  className: string
  hint: string
}

const NOT_PROOF = 'This is not proof of safety.'

export const INTEL_STATUS_META: Record<string, StatusMeta> = {
  malicious_or_flagged: {
    label: 'Flagged by provider', icon: 'FLG',
    className: 'bg-danger-weak text-danger border-danger-line',
    hint: 'The provider reported this indicator as malicious, abusive or anonymising.',
  },
  reported_clean_no_flags: {
    label: 'No flags reported', icon: 'CLR',
    className: 'bg-surface-2 text-fg border-line-strong',
    hint: `The provider returned data with no flags. ${NOT_PROOF}`,
  },
  record_found: {
    label: 'Record found, no verdict', icon: 'REC',
    className: 'bg-accent-weak text-accent border-accent-line',
    hint: `The provider returned details but gives no reputation verdict. ${NOT_PROOF}`,
  },
  no_record: {
    label: 'No record / no reports', icon: 'NIL',
    className: 'bg-surface-2 text-fg border-line-strong',
    hint: `Nothing was found at this provider. ${NOT_PROOF}`,
  },
  provider_error: {
    label: 'Provider error', icon: 'ERR',
    className: 'bg-warn-weak text-warn border-warn-line',
    hint: 'The provider returned an error, so there is no result.',
  },
  rate_limited: {
    label: 'Rate limited', icon: 'RTL',
    className: 'bg-warn-weak text-warn border-warn-line',
    hint: 'The provider or local rate limit was reached, so this was not looked up.',
  },
  quota_exhausted: {
    label: 'Daily quota exhausted', icon: 'QTA',
    className: 'bg-warn-weak text-warn border-warn',
    hint: 'The daily quota is used up, so this was not looked up.',
  },
  auth_failed: {
    label: 'Credential rejected', icon: 'AUT',
    className: 'bg-danger-weak text-danger border-danger-line',
    hint: 'The provider rejected the configured credential.',
  },
  timeout: {
    label: 'Timed out', icon: 'TMO',
    className: 'bg-warn-weak text-warn border-warn-line',
    hint: 'The provider did not respond in time.',
  },
  malformed_response: {
    label: 'Unreadable response', icon: 'BAD',
    className: 'bg-warn-weak text-warn border-warn',
    hint: 'The provider response could not be read, so nothing is shown.',
  },
  not_permitted: {
    label: 'Not permitted', icon: 'NPM',
    className: 'bg-accent-weak text-accent border-accent-line',
    hint: 'The provider plan or policy does not allow this lookup.',
  },
  not_attempted_consent_disabled: {
    label: 'Not run: no consent', icon: 'CNS',
    className: 'bg-accent-weak text-accent border-accent-line',
    hint: 'External lookups were not consented to for this analysis.',
  },
  not_attempted_offline: {
    label: 'Not run: offline mode', icon: 'OFF',
    className: 'bg-surface-2 text-fg border-line-strong',
    hint: 'Offline mode blocks external calls, and no cached result exists.',
  },
  not_attempted_cap_reached: {
    label: 'Not looked up: cap reached', icon: 'CAP',
    className: 'bg-surface-2 text-fg border-line-strong',
    hint: 'The per-analysis indicator cap was reached.',
  },
  missing_credentials: {
    label: 'Not run: no credential', icon: 'KEY',
    className: 'bg-surface-2 text-fg border-line-strong',
    hint: 'No credential is configured for this provider.',
  },
  not_applicable_indicator: {
    label: 'Not applicable', icon: 'N/A',
    className: 'bg-surface-2 text-muted border-line',
    hint: 'This indicator is not eligible for lookup (for example a private IP or an internal domain), so it was never sent.',
  },
}

export function statusMeta(status: string): StatusMeta {
  return (
    INTEL_STATUS_META[status] ?? {
      label: status.replace(/_/g, ' '), icon: '???', className: 'bg-surface-2 text-fg border-line-strong',
      hint: 'Unrecognised status.',
    }
  )
}

// Normalised fields worth showing per provider (label, data key).
const FIELDS: Record<string, [string, string][]> = {
  virustotal: [
    ['Malicious engines', 'malicious'], ['Suspicious engines', 'suspicious'], ['Engines total', 'engines_total'],
    ['Reputation', 'reputation'], ['Last analysis', 'last_analysis_date'], ['AS owner', 'as_owner'],
    ['ASN', 'asn'], ['Country', 'country'], ['Registrar', 'registrar'], ['Created', 'creation_date'],
    ['File type', 'type_description'], ['Tags', 'tags'],
  ],
  abuseipdb: [
    ['Abuse confidence', 'abuse_confidence_score'], ['Total reports', 'total_reports'],
    ['Distinct reporters', 'distinct_reporters'], ['Country', 'country_code'], ['ISP', 'isp'],
    ['Usage type', 'usage_type'], ['Last reported', 'last_reported_at'], ['Flag threshold', 'flag_threshold'],
  ],
  shodan: [
    ['Open ports', 'open_ports'], ['Org', 'org'], ['ISP', 'isp'], ['ASN', 'asn'], ['Hostnames', 'hostnames'],
    ['Tags', 'tags'], ['Country', 'country'], ['City', 'city'], ['Known CVEs', 'known_vulnerability_count'],
    ['Last update', 'last_update'],
  ],
  ipinfo: [
    ['Country', 'country'], ['Region', 'region'], ['City', 'city'], ['Org / ASN', 'org'], ['Hostname', 'hostname'],
    ['VPN', 'is_vpn'], ['Proxy', 'is_proxy'], ['Tor', 'is_tor'], ['Relay', 'is_relay'], ['Hosting', 'is_hosting'],
  ],
  tor_exit_list: [['In exit list', 'listed'], ['List size', 'list_size'], ['List fetched', 'list_fetched_at']],
}

const MAX_TEXT = 160

/** Provider strings are untrusted: render as plain text (React escapes them), truncated. */
export function displayValue(v: unknown): string | null {
  if (v === null || v === undefined || v === '') return null
  if (Array.isArray(v)) return v.length ? v.slice(0, 12).map((x) => String(x)).join(', ').slice(0, MAX_TEXT) : null
  if (typeof v === 'boolean') return v ? 'yes' : 'no'
  if (typeof v === 'object') return null
  const s = String(v)
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s)) return formatDate(s)
  return s.length > MAX_TEXT ? `${s.slice(0, MAX_TEXT - 1)}…` : s
}

export function factsFor(r: IntelResult): [string, string][] {
  const out: [string, string][] = []
  for (const [label, key] of FIELDS[r.provider] ?? []) {
    const shown = displayValue(r.data?.[key])
    if (shown !== null) out.push([label, shown])
  }
  return out
}

export function cacheLabel(r: IntelResult): string | null {
  if (r.cache_state === 'fresh') return 'Cached (fresh)'
  if (r.cache_state === 'stale') return 'STALE cache'
  return null
}

export function ageText(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return 'unknown age'
  if (seconds < 3600) return `${Math.max(1, Math.floor(seconds / 60))} min old`
  if (seconds < 172800) return `${Math.floor(seconds / 3600)} h old`
  return `${Math.floor(seconds / 86400)} d old`
}

export const ORDER_PROVIDERS = ['virustotal', 'abuseipdb', 'shodan', 'ipinfo', 'tor_exit_list']
