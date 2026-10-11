import { useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { AppTabs } from '../pages/AppTabs'
import { useAppTabs } from './AppTabsContext'
import { adminApi } from '../adminApi'

/**
 * v2.15.0: mounted once, above the routes — so the app tabs (and their iframes)
 * stay alive as you move around the dashboard. Covers the content area (below
 * the topbar, right of the sidebar) and is shown only on /launch; hidden
 * elsewhere with display:none, which keeps the iframes mounted and warm.
 */
export function PersistentAppTabs() {
  const { openTabs, addTab, removeTab, updateTab } = useAppTabs()
  const location = useLocation()
  const navigate = useNavigate()

  const onLaunch = location.pathname === '/launch' || location.pathname.startsWith('/launch/')
  const m = location.pathname.match(/^\/launch\/([^/]+)/)
  const urlSlug = m ? decodeURIComponent(m[1]) : null
  const activeSlug = urlSlug ?? (openTabs.length ? openTabs[openTabs.length - 1].slug : null)

  // Direct load / refresh / bookmark of /launch/:slug — the tab was never
  // opened via the sidebar, so add it here, named by its slug for now.
  useEffect(() => {
    if (urlSlug && !openTabs.some(t => t.slug === urlSlug)) {
      addTab({ slug: urlSlug, name: urlSlug })
    }
  }, [urlSlug]) // eslint-disable-line react-hooks/exhaustive-deps

  // A tab opened by slug alone (the direct load above, or Catalog's "Open
  // /<slug>/") kept showing the slug for good: the comment here said AppFrame
  // would supply the name, but nothing ever wrote it back to the tab. Fill in
  // the app's name and icon from the app list the caller can see.
  const unnamed = openTabs.filter(t => t.name === t.slug).map(t => t.slug).join(',')
  useEffect(() => {
    if (!unnamed) return
    adminApi.get<{ apps: { slug: string; name?: string; has_icon?: boolean }[] }>('/api/apps')
      .then(r => {
        for (const slug of unnamed.split(',')) {
          const app = r?.apps?.find(a => a.slug === slug)
          if (app?.name) updateTab(slug, { name: app.name, hasIcon: !!app.has_icon })
        }
      })
      .catch(() => {})
  }, [unnamed]) // eslint-disable-line react-hooks/exhaustive-deps

  const onSelect = (slug: string) => navigate(`/launch/${slug}`)
  const onClose = (slug: string) => {
    removeTab(slug)
    if (slug === activeSlug) {
      const rest = openTabs.filter(t => t.slug !== slug)
      navigate(rest.length ? `/launch/${rest[rest.length - 1].slug}` : '/launch')
    }
  }

  return (
    <div className="persistent-app-tabs" style={{ display: onLaunch ? 'flex' : 'none' }}>
      <AppTabs tabs={openTabs} activeSlug={activeSlug} onSelect={onSelect} onClose={onClose} />
    </div>
  )
}
