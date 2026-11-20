// Type for importing the Tailwind config in tests (design-rule guard).
declare module '*/tailwind.config.js' {
  const config: { theme: { borderRadius: Record<string, string>; boxShadow: Record<string, string> } & Record<string, unknown> }
  export default config
}
