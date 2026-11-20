/** @type {import('tailwindcss').Config} */
// AIPISH design tokens (P5u-1). Every colour is a CSS variable defined in src/index.css.
// See docs/frontend/design-system.md.
const v = (name) => `var(--${name})`

// Status families (text/fill/line/weak). Shades map so the legacy light-theme pattern
// "bg-x-50 text-x-800 ring-x-300" renders as dark tint + light text + mid line.
const family = (k) => ({
  DEFAULT: v(k), 50: v(`${k}-weak`), 100: v(`${k}-weak`), 200: v(`${k}-line`), 300: v(`${k}-line`),
  400: v(k), 500: v(k), 600: v(k), 700: v(k), 800: v(k), 900: v(k), 950: v(k),
  weak: v(`${k}-weak`), line: v(`${k}-line`),
})
// Neutral ramp (legacy gray/slate/zinc names resolve onto the dark surfaces).
const neutral = {
  50: v('surface-2'), 100: v('surface-2'), 200: v('line'), 300: v('line-strong'), 400: v('muted'),
  500: v('muted'), 600: v('muted'), 700: v('fg'), 800: v('fg'), 900: v('fg'), 950: v('fg'),
}

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      inherit: 'inherit',
      // semantic tokens (use these in new code)
      bg: v('bg'), surface: v('surface'), 'surface-2': v('surface-2'), 'surface-3': v('surface-3'),
      line: v('line'), 'line-strong': v('line-strong'), fg: v('fg'), muted: v('muted'),
      accent: family('accent'), 'accent-hover': v('accent-hover'), ok: family('ok'), warn: family('warn'), danger: family('danger'),
      // compatibility layer for components not yet migrated (removed in part 2)
      white: v('surface'), black: '#000000',
      gray: neutral, slate: neutral, zinc: neutral, neutral, stone: neutral,
      red: family('danger'), rose: family('danger'), pink: family('danger'),
      amber: family('warn'), yellow: family('warn'), orange: family('warn'), fuchsia: family('warn'),
      emerald: family('ok'), green: family('ok'), teal: family('ok'), lime: family('ok'),
      sky: family('accent'), blue: family('accent'), indigo: family('accent'), cyan: family('accent'),
      violet: family('accent'), purple: family('accent'),
    },
    fontFamily: {
      sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
      mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
    },
    // four sizes only: 11 mono label · 13 meta/table · 14 body · 18–20 headline
    fontSize: {
      xs: ['11px', '16px'], sm: ['13px', '20px'], base: ['14px', '22px'],
      lg: ['18px', '26px'], xl: ['20px', '28px'], '2xl': ['20px', '28px'], '3xl': ['20px', '28px'],
    },
    fontWeight: { normal: '400', medium: '500', semibold: '600', bold: '600', extrabold: '600' },
    // square UI: every rounded-* utility resolves to 0 (sm = 2px, small badges only)
    borderRadius: { none: '0', sm: '2px', DEFAULT: '0', md: '0', lg: '0', xl: '0', '2xl': '0', '3xl': '0', full: '0' },
    boxShadow: { none: 'none', sm: 'none', DEFAULT: 'none', md: 'none', lg: 'none', xl: 'none', '2xl': 'none',
                 inner: 'none', pop: `1px 1px 0 0 ${v('line-strong')}` },
    backdropBlur: { none: '0' },
    extend: {
      maxWidth: { content: '1680px' },
      height: { row: '34px' },
    },
  },
  plugins: [],
}
