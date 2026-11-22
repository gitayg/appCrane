import { useCallback, useEffect, useState } from 'react'
import { adminApi, ApiError } from '../../adminApi'
import { LiteracyAck } from './LiteracyAck'
import { AI_USE_LABELS, type AiActView, type AiUse, type LiteracyStatement } from './types'

/** Manage page: the app's AI use, its transparency notice and the LLM log retention that applies. */
export function AiUseCard({ slug, onMsg }: { slug: string; onMsg: (m: { text: string; ok: boolean }) => void }) {
  const [data, setData] = useState<AiActView | null>(null)
  const [use, setUse] = useState<AiUse | ''>('')
  const [category, setCategory] = useState('')
  const [noticeOn, setNoticeOn] = useState(false)
  const [noticeText, setNoticeText] = useState('')
  const [pendingAck, setPendingAck] = useState<LiteracyStatement | null>(null)
  const [busy, setBusy] = useState(false)

  const base = `/api/apps/${encodeURIComponent(slug)}`
  const load = useCallback(() => {
    adminApi.get<AiActView>(`${base}/ai-act`).then(r => {
      setData(r)
      setUse(r.ai.ai_use || '')
      setCategory(r.ai.annex_iii_category || '')
      setNoticeOn(r.notice.enabled)
      setNoticeText(r.notice.custom_text ? r.notice.text : '')
    }).catch(() => setData(null))
  }, [base])
  useEffect(() => { setPendingAck(null); load() }, [load])

  async function saveUse() {
    if (!use) return
    setBusy(true)
    try {
      const r = await adminApi.put<AiActView & { intake_back_to_review?: boolean }>(`${base}/ai-use`, { ai_use: use, annex_iii_category: use === 'annex_iii' ? category : null })
      onMsg({ text: r.intake_back_to_review ? 'AI use saved; the intake is back with a platform admin for approval' : 'AI use saved', ok: true })
      load()
    } catch (e) {
      if (e instanceof ApiError && e.code === 'AI_LITERACY_ACK_REQUIRED') setPendingAck(e.details.statement as LiteracyStatement)
      else onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function saveNotice() {
    setBusy(true)
    try {
      await adminApi.put(`${base}/ai-notice`, { enabled: noticeOn, text: noticeText })
      onMsg({ text: 'Notice saved. The identity response carries it now; the container env changes on the next deploy.', ok: true })
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!data) return null
  const guidance = use ? data.options.guidance[use] : null
  return (
    <>
      <h2 className="am-h2">AI use</h2>
      <div className="am-card">
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <select className="am-input" disabled={!data.can_edit} value={use} onChange={e => setUse(e.target.value as AiUse)}>
            <option value="" disabled>Not answered</option>
            {data.options.ai_uses.map(u => <option key={u} value={u}>{AI_USE_LABELS[u]}</option>)}
          </select>
          {use === 'annex_iii' && (
            <select className="am-input" disabled={!data.can_edit} value={category} onChange={e => setCategory(e.target.value)}>
              <option value="" disabled>Annex III area</option>
              {data.options.annex_iii_categories.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
            </select>
          )}
          {data.can_edit && <button className="btn btn-sm" disabled={busy || !use || (use === 'annex_iii' && !category)} onClick={saveUse}>Save</button>}
        </div>
        {data.ai.locked && <div style={{ fontSize: '.8rem', color: 'var(--dim)', marginTop: 8 }}>A platform admin set this answer; only a platform admin can change it.</div>}
        {data.ai.review_required && <div style={{ fontSize: '.8rem', color: 'var(--orange)', marginTop: 8 }}>The AI use was lowered; production waits for a platform admin to approve the intake.</div>}
        {guidance && <div style={{ fontSize: '.8rem', color: 'var(--orange)', marginTop: 8 }}>{guidance}</div>}
        {pendingAck && <LiteracyAck statement={pendingAck} onCancel={() => setPendingAck(null)} onDone={() => { setPendingAck(null); saveUse() }} />}
        <div style={{ fontSize: '.8rem', color: 'var(--dim)', marginTop: 8 }}>
          LLM gateway logs kept {data.retention.llm_gateway_logs_days} days
          {data.retention.floor_applied ? ` (the platform setting is ${data.retention.configured_days}; apps using AI keep at least ${data.retention.ai_floor_days})` : ''}.
          {data.literacy.acknowledged ? ` You acknowledged AI-literacy statement ${data.literacy.statement.version}.` : ''}
        </div>

        <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
          <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '.85rem' }}>
            <input type="checkbox" disabled={!data.can_edit} checked={noticeOn} onChange={e => setNoticeOn(e.target.checked)} />
            Show users a notice that they are interacting with an AI system
          </label>
          <input className="am-input" style={{ width: '100%', marginTop: 6 }} disabled={!data.can_edit || !noticeOn} maxLength={data.notice.max_length}
            placeholder={data.notice.default_text} value={noticeText} onChange={e => setNoticeText(e.target.value)} />
          <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 4 }}>
            AppCrane does not change the app's pages. The app reads ai_notice from /api/identity/verify, or APPCRANE_AI_NOTICE and APPCRANE_AI_NOTICE_TEXT from its environment, and shows the text.
          </div>
          {data.can_edit && <button className="btn btn-sm btn-dim" style={{ marginTop: 6 }} disabled={busy} onClick={saveNotice}>Save notice</button>}
        </div>
      </div>
    </>
  )
}
