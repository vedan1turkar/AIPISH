/** @type {import('tailwindcss').Config} */
// AIPISH design tokens (P5u-1). Every colour is a CSS variable defined in src/index.css.
// See docs/frontend/design-system.md.
const v = (name) => `var(--${name})`

// Status families: base colour, dark tint (badge/alert fill) and mid tint (borders).
const family = (k) => ({ DEFAULT: v(k), weak: v(`${k}-weak`), line: v(`${k}-line`) })

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
      black: '#000000',
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
