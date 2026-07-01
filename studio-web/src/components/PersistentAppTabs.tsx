import { useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { AppTabs } from '../pages/AppTabs'
import { useAppTabs } from './AppTabsContext'

/**
 * v2.15.0: mounted once, above the routes — so the app tabs (and their iframes)
 * stay alive as you move around the dashboard. Covers the content area (below
 * the topbar, right of the sidebar) and is shown only on /launch; hidden
 * elsewhere with display:none, which keeps the iframes mounted and warm.
 */
export function PersistentAppTabs() {
  const { openTabs, addTab, removeTab } = useAppTabs()
  const location = useLocation()
  const navigate = useNavigate()

  const onLaunch = location.pathname === '/launch' || location.pathname.startsWith('/launch/')
  const m = location.pathname.match(/^\/launch\/([^/]+)/)
  const urlSlug = m ? decodeURIComponent(m[1]) : null
  const activeSlug = urlSlug ?? (openTabs.length ? openTabs[openTabs.length - 1].slug : null)

  // Direct load / refresh / bookmark of /launch/:slug — the tab was never
  // opened via the sidebar, so add it here. AppFrame fetches the real name;
  // the tab shows the slug until then.
  useEffect(() => {
    if (urlSlug && !openTabs.some(t => t.slug === urlSlug)) {
      addTab({ slug: urlSlug, name: urlSlug })
    }
  }, [urlSlug]) // eslint-disable-line react-hooks/exhaustive-deps

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
