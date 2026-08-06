import { AppFrame } from './AppFrame'
import { AppPicker } from '../components/AppPicker'

/**
 * v2.15.0: multi-app tabs. Renders a tab strip plus one <AppFrame> per open app,
 * all kept mounted (hidden except the active one) so switching tabs is instant
 * and never reloads. Mounted persistently in Layout, so the iframes stay alive
 * even while you're on other dashboard pages.
 */

export interface OpenApp { slug: string; name: string; hasIcon?: boolean }

interface Props {
  tabs: OpenApp[]
  activeSlug: string | null
  onSelect: (slug: string) => void
  onClose: (slug: string) => void
}

export function AppTabs({ tabs, activeSlug, onSelect, onClose }: Props) {
  // v2.32.0: with nothing open, show the apps this user can actually open as
  // tiles instead of telling them to go find the sidebar. `onSelect` already
  // navigates to /launch/<slug>, which opens the tab.
  if (tabs.length === 0) {
    return <AppPicker onOpen={onSelect} />
  }
  return (
    <div className="app-tabs">
      <div className="app-tabs-bar" role="tablist">
        {tabs.map(t => (
          <div
            key={t.slug}
            role="tab"
            aria-selected={t.slug === activeSlug}
            className={'app-tab' + (t.slug === activeSlug ? ' active' : '')}
            onClick={() => onSelect(t.slug)}
            title={t.name}
          >
            {t.hasIcon && <img className="app-tab-ico" src={`/api/apps/${t.slug}/icon`} alt="" />}
            <span className="app-tab-name">{t.name}</span>
            <button
              className="app-tab-close"
              onClick={e => { e.stopPropagation(); onClose(t.slug) }}
              aria-label={`Close ${t.name}`}
              title={`Close ${t.name}`}
            >×</button>
          </div>
        ))}
      </div>
      <div className="app-tabs-body">
        {tabs.map(t => (
          <AppFrame key={t.slug} slug={t.slug} active={t.slug === activeSlug} onClose={() => onClose(t.slug)} />
        ))}
      </div>
    </div>
  )
}
