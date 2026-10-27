// Where the browser opens an app. The apps API sends `url` / `sandbox_url`:
// the app's own address when app isolation is on, else the path on this host.
// An older server sends neither, so fall back to the path.
export interface AppAddresses {
  slug: string
  url?: string | null
  sandbox_url?: string | null
}

export function appOpenUrl(app: AppAddresses, env: 'production' | 'sandbox'): string {
  if (env === 'sandbox') return app.sandbox_url || `/${app.slug}-sandbox`
  return app.url || `/${app.slug}`
}
