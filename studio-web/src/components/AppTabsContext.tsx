import { createContext, useContext, useState, type ReactNode } from 'react'
import type { OpenApp } from '../pages/AppTabs'

/**
 * v2.15.0: open-apps state shared between the sidebar (which opens tabs) and the
 * persistent tab host (which renders them). Lives above the router so the tab
 * set — and the live iframes it drives — survive navigating around the app.
 */
interface Ctx {
  openTabs: OpenApp[]
  addTab: (app: OpenApp) => void
  removeTab: (slug: string) => void
}

const AppTabsContext = createContext<Ctx | null>(null)

export function AppTabsProvider({ children }: { children: ReactNode }) {
  const [openTabs, setOpenTabs] = useState<OpenApp[]>([])
  const addTab = (app: OpenApp) =>
    setOpenTabs(t => (t.some(x => x.slug === app.slug) ? t : [...t, app]))
  const removeTab = (slug: string) =>
    setOpenTabs(t => t.filter(x => x.slug !== slug))
  return (
    <AppTabsContext.Provider value={{ openTabs, addTab, removeTab }}>
      {children}
    </AppTabsContext.Provider>
  )
}

export function useAppTabs(): Ctx {
  const c = useContext(AppTabsContext)
  if (!c) throw new Error('useAppTabs must be used within AppTabsProvider')
  return c
}
