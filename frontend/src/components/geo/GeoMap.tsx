// Infrastructure map (P5g). Lazy-loaded chunk: Leaflet + a bundled Natural Earth world outline.
// No tile server and no network requests: the only layer is the vector outline shipped in the build.
// Markers are diamonds (IPs, matching the graph legend), coloured by role and always paired with text
// (legend, table, side panel). The relay-order line is OFF by default and labelled as not a route.
import { useEffect, useRef } from 'react'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { feature } from 'topojson-client'
import type { Topology, GeometryCollection } from 'topojson-specification'
import world from 'world-atlas/countries-110m.json'
import type { GeoPoint } from '../../api/client'
import { GraphControls, MAP_THEME, ROLE_COLOR } from '../graph/style'
import { ROLE_LABEL } from './labels'

export interface GeoMapProps {
  points: GeoPoint[]
  selected: string | null
  onSelect: (ip: string) => void
  relayOrder?: string[]
  showRelayOrder?: boolean
  label: string
}

const reducedMotion = () => typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

const outline = (() => {
  const topo = world as unknown as Topology<{ countries: GeometryCollection }>
  return feature(topo, topo.objects.countries)
})()

function icon(p: GeoPoint, selected: boolean): L.DivIcon {
  const hop = p.hop != null ? `<span class="geo-hop">${p.hop}</span>` : ''
  const count = p.member_count && p.member_count > 1 ? `<span class="geo-hop">×${p.member_count}</span>` : ''
  return L.divIcon({
    className: `geo-marker${selected ? ' geo-marker-selected' : ''}`,
    html: `<span class="geo-diamond" style="background:${ROLE_COLOR[p.role] ?? ROLE_COLOR.url_host_ip}"></span>${hop}${count}`,
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  })
}

export default function GeoMap({ points, selected, onSelect, relayOrder = [], showRelayOrder = false, label }: GeoMapProps) {
  const el = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const markers = useRef<Map<string, L.Marker>>(new Map())
  const routeRef = useRef<L.Polyline | null>(null)
  const selectRef = useRef(onSelect)
  selectRef.current = onSelect

  const fit = () => {
    const map = mapRef.current
    if (!map) return
    if (points.length === 0) map.fitWorld({ animate: false })
    else if (points.length === 1) map.setView([points[0].lat, points[0].lon], 3, { animate: false })
    else map.fitBounds(L.latLngBounds(points.map((p) => [p.lat, p.lon] as [number, number])).pad(0.4),
                       { maxZoom: 4, animate: false })
  }

  // map + outline, once
  useEffect(() => {
    if (!el.current) return
    const still = reducedMotion()
    const map = L.map(el.current, {
      zoomControl: false, attributionControl: false, minZoom: 1, maxZoom: 7, zoomSnap: 0.5,
      worldCopyJump: false, maxBounds: [[-85, -200], [85, 200]], maxBoundsViscosity: 1,
      zoomAnimation: !still, fadeAnimation: !still, markerZoomAnimation: !still, inertia: !still,
      keyboard: true, renderer: L.svg(),
    })
    L.geoJSON(outline, {
      interactive: false,
      style: { fillColor: MAP_THEME.land, fillOpacity: 1, color: MAP_THEME.border, weight: 0.6 },
    }).addTo(map)
    mapRef.current = map
    const onResize = () => map.invalidateSize()
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(onResize) : null
    ro?.observe(el.current)
    return () => {
      ro?.disconnect()
      map.remove()
      mapRef.current = null
      markers.current.clear()
    }
  }, [])

  // markers (rebuilt when the data changes)
  useEffect(() => {
    const map = mapRef.current
    if (!map) return
    markers.current.forEach((m) => m.remove())
    markers.current.clear()
    for (const p of points) {
      const m = L.marker([p.lat, p.lon], {
        icon: icon(p, false), keyboard: true, riseOnHover: true,
        title: `${p.ip} · ${ROLE_LABEL[p.role] ?? p.role}${p.simulated ? ' · SIMULATED' : ''}`,
        alt: `${p.ip}, ${ROLE_LABEL[p.role] ?? p.role}`,
      })
      m.on('click', () => selectRef.current(p.ip))
      m.addTo(map)
      markers.current.set(p.ip, m)
    }
    fit()
  }, [points])   // fit() reads the same points; intentionally not a dependency

  // selection highlight
  useEffect(() => {
    for (const p of points) markers.current.get(p.ip)?.setIcon(icon(p, p.ip === selected))
    const sel = points.find((p) => p.ip === selected)
    if (sel && mapRef.current && !mapRef.current.getBounds().contains([sel.lat, sel.lon])) {
      mapRef.current.panTo([sel.lat, sel.lon], { animate: !reducedMotion() })
    }
  }, [selected, points])

  // optional relay-order line (dashed; never implies a physical path)
  useEffect(() => {
    const map = mapRef.current
    routeRef.current?.remove()
    routeRef.current = null
    if (!map || !showRelayOrder) return
    const coords = relayOrder.map((ip) => points.find((p) => p.ip === ip)).filter((p): p is GeoPoint => !!p)
      .map((p) => [p.lat, p.lon] as [number, number])
    if (coords.length < 2) return
    routeRef.current = L.polyline(coords, { color: MAP_THEME.route, weight: 1, dashArray: '4 4', interactive: false }).addTo(map)
  }, [showRelayOrder, relayOrder, points])

  const zoom = (f: number) => {
    const map = mapRef.current
    if (map) map.setZoom(map.getZoom() + (f > 1 ? 1 : -1), { animate: !reducedMotion() })
  }

  return (
    <div className="relative h-full min-h-[380px] w-full">
      <div ref={el} className="aipish-map absolute inset-0 z-0" role="application" aria-label={label} data-testid="geo-map" />
      {/* z-0 above gives Leaflet's panes (z 400) their own stacking context, so these stay on top */}
      <GraphControls onZoom={zoom} onFit={fit} />
    </div>
  )
}
