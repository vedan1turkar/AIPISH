// Shared labels for infrastructure-geo surfaces (P5g). Text always accompanies colour.
import type { AnonymitySignal, GeoRole } from '../../api/client'

export const ROLE_LABEL: Record<GeoRole, string> = {
  origin_candidate: 'origin candidate',
  untrusted_relay: 'untrusted relay',
  trusted_relay: 'trusted relay',
  url_host_ip: 'URL host IP',
}

export const ROLES: GeoRole[] = ['origin_candidate', 'untrusted_relay', 'trusted_relay', 'url_host_ip']

export const SIGNAL_LABEL: Record<AnonymitySignal, string> = {
  tor: 'Tor', vpn: 'VPN', proxy: 'Proxy', relay: 'Relay', hosting: 'Hosting',
}

export const SIGNALS: AnonymitySignal[] = ['tor', 'vpn', 'proxy', 'relay', 'hosting']

/** The mandatory text on every map / geo surface (matches the backend's DISCLAIMER). */
export const GEO_DISCLAIMER =
  "Approximate infrastructure location from IP data. It is not the sender's physical location and does not identify a person. VPN, proxy, hosting and Tor distort results."

export const MAP_ATTRIBUTION = 'Outline: Natural Earth (public domain) via world-atlas · Map: Leaflet (BSD-2-Clause) · no map tiles or external requests'
