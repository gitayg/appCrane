import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { adminApi } from '../../adminApi'
import { useMe, isAdmin } from '../../hooks/useMe'
import { PAGE_CSS } from '../../pages/AppManager'
import './appManage.css'
import { TABS, type AppDetail, type ManageCtx, type ManagedApp, type Msg, type TabId } from './types'
import { ManageHeader } from './ManageHeader'
import { OverviewTab } from './OverviewTab'
import { ReleasesTab } from './ReleasesTab'
import { EnvVarsTab } from './EnvVarsTab'
import { AccessTab } from './AccessTab'
import { NetworkTab } from './NetworkTab'
import { SecurityTab } from './SecurityTab'
import { ResourcesTab } from './ResourcesTab'
import { UsageTab } from './UsageTab'
import { LogsTab } from './LogsTab'

const ADMIN_TABS: TabId[] = ['releases', 'usage']

/** /app?slug=<slug>&tab=<tab>: one page for everything about one app. */
export function AppManagePage({ slug }: { slug: string }) {
  const [params, setParams] = useSearchParams()
  const me = useMe()
  const [app, setApp] = useState<ManagedApp | null>(null)
  const [detail, setDetail] = useState<AppDetail | null>(null)
  const [missing, setMissing] = useState(false)
  const [reload, setReload] = useState(0)
  const [msg, setMsg] = useState<Msg | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const onMsg = useCallback((m: Msg) => {
    setMsg(m)
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => setMsg(null), 6000)
  }, [])
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])

  useEffect(() => {
    let cancelled = false
    setMissing(false)
    adminApi.get<{ apps: ManagedApp[] }>('/api/apps')
      .then(r => {
        if (cancelled) return
        const a = (r.apps || []).find(x => x.slug === slug) || null
        setApp(a)
        setMissing(!a)
      })
      .catch(() => { if (!cancelled) setMissing(true) })
    adminApi.get<AppDetail>(`/api/apps/${slug}`)
      .then(d => { if (!cancelled) setDetail(d) })
      .catch(() => { if (!cancelled) setDetail(null) })
    return () => { cancelled = true }
  }, [slug, reload])

  const isPlatformAdmin = isAdmin(me)
  const role = app?.app_role
  const canAdmin = isPlatformAdmin || role === 'owner' || role === 'admin'
  const isOwner = role === 'owner'

  const requested = (params.get('tab') || 'overview') as TabId
  const visibleTabs = TABS.filter(t => canAdmin || !ADMIN_TABS.includes(t.id))
  const tab: TabId = visibleTabs.some(t => t.id === requested) ? requested : 'overview'

  const setTab = useCallback((t: TabId, extra?: Record<string, string>) => {
    const next = new URLSearchParams({ slug })
    if (t !== 'overview') next.set('tab', t)
    for (const [k, v] of Object.entries(extra || {})) next.set(k, v)
    setParams(next)
  }, [slug, setParams])

  const refresh = useCallback(() => setReload(n => n + 1), [])
  const patchApp = useCallback((p: Partial<ManagedApp>) => setApp(a => (a ? { ...a, ...p } : a)), [])

  if (missing) {
    return (
      <div className="app-manager am2"><style>{PAGE_CSS}</style>
        <div className="am2-wrap"><div className="am2-empty">App “{slug}” was not found, or you do not have access to it. <a href="/applications">Back to apps</a></div></div>
      </div>
    )
  }
  if (!app) {
    return <div className="app-manager am2"><style>{PAGE_CSS}</style><div className="am2-wrap"><div className="am2-empty">Loading…</div></div></div>
  }

  const ctx: ManageCtx = { slug, app, detail, isPlatformAdmin, canAdmin, isOwner, reload, refresh, onMsg, setTab, patchApp }

  return (
    <div className="app-manager am2">
      <style>{PAGE_CSS}</style>
      <div className="am2-wrap">
        <nav className="am2-crumb" aria-label="Breadcrumb"><a href="/applications">Apps</a> / {app.name}</nav>
        <ManageHeader ctx={ctx} />
        <div className="am2-tabs" role="tablist" aria-label="App sections">
          {visibleTabs.map(t => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              className={'am2-tab' + (tab === t.id ? ' active' : '')}
              onClick={() => setTab(t.id)}
            >{t.label}</button>
          ))}
        </div>
        {msg && <div className={'am-msg ' + (msg.ok ? 'msg-ok' : 'msg-err')}>{msg.text}</div>}
        <div role="tabpanel">
          {tab === 'overview' && <OverviewTab ctx={ctx} />}
          {tab === 'releases' && <ReleasesTab ctx={ctx} />}
          {tab === 'env' && <EnvVarsTab ctx={ctx} />}
          {tab === 'access' && <AccessTab ctx={ctx} />}
          {tab === 'network' && <NetworkTab ctx={ctx} />}
          {tab === 'security' && <SecurityTab ctx={ctx} />}
          {tab === 'resources' && <ResourcesTab ctx={ctx} />}
          {tab === 'usage' && <UsageTab ctx={ctx} />}
          {tab === 'logs' && <LogsTab ctx={ctx} />}
        </div>
      </div>
    </div>
  )
}
