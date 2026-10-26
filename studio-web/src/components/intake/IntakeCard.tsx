import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { ClassificationBadge } from './ClassificationBadge'
import { IntakeForm } from './IntakeForm'
import { EMPTY_INTAKE, type IntakeDraft, type IntakeGate, type IntakeRow, type Level } from './types'

interface Resp {
  intake: IntakeRow | null
  classification: { level: Level; locked: boolean; has_intake: boolean }
  gate: IntakeGate
  can_edit: boolean
  can_review: boolean
}

function toDraft(r: Resp): IntakeDraft {
  const i = r.intake
  return i ? {
    purpose: i.purpose || '', data_classification: i.data_classification, personal_data: i.personal_data,
    external_integrations: i.external_integrations || '', access: i.access_notes || '',
  } : { ...EMPTY_INTAKE, data_classification: r.classification.level }
}

/** Manage page: the app's intake, its classification and whether production is open. */
export function IntakeCard({ slug, onMsg }: { slug: string; onMsg: (m: { text: string; ok: boolean }) => void }) {
  const [data, setData] = useState<Resp | null>(null)
  const [draft, setDraft] = useState<IntakeDraft | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    adminApi.get<Resp>(`/api/apps/${encodeURIComponent(slug)}/intake`)
      .then(r => { setData(r); setError('') })
      .catch(e => setError((e as Error).message))
  }, [slug])
  useEffect(() => { setDraft(null); load() }, [load])

  async function save() {
    if (!draft) return
    setBusy(true)
    try {
      await adminApi.put(`/api/apps/${encodeURIComponent(slug)}/intake`, draft)
      onMsg({ text: 'Intake submitted', ok: true })
      setDraft(null)
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function review(decision: 'approve' | 'reject') {
    const comment = window.prompt(decision === 'approve' ? 'Comment (optional)' : 'Why is it rejected? The owner sees this.') ?? null
    if (comment === null) return
    try {
      await adminApi.post(`/api/apps/${encodeURIComponent(slug)}/intake/review`, { decision, comment })
      onMsg({ text: `Intake ${decision === 'approve' ? 'approved' : 'rejected'}`, ok: true })
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    }
  }

  if (error) return null
  if (!data) return null
  const i = data.intake
  const statusColor = data.gate.ok ? 'var(--green)' : i?.status === 'rejected' ? 'var(--red)' : 'var(--orange)'
  return (
    <>
      <h2 className="am-h2">Intake and data classification</h2>
      <div className="am-card">
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
          <ClassificationBadge level={data.classification.level} />
          <span style={{ color: statusColor, fontSize: '.85rem' }}>{data.gate.message}</span>
        </div>
        {i?.review_comment && <div style={{ fontSize: '.8rem', color: 'var(--dim)', marginBottom: 8 }}>Reviewer: {i.review_comment}</div>}
        {draft ? (
          <>
            <IntakeForm value={draft} onChange={setDraft} lockedLevel={data.classification.locked && !data.can_review} />
            <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
              <button className="btn btn-sm" disabled={busy} onClick={save}>Submit</button>
              <button className="btn btn-sm btn-dim" onClick={() => setDraft(null)}>Cancel</button>
            </div>
          </>
        ) : (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {data.can_edit && <button className="btn btn-sm btn-dim" onClick={() => setDraft(toDraft(data))}>{i ? 'Edit and resubmit' : 'Fill in intake'}</button>}
            {data.can_review && i && i.status !== 'approved' && <button className="btn btn-sm" onClick={() => review('approve')}>Approve</button>}
            {data.can_review && i && i.status !== 'rejected' && <button className="btn btn-sm btn-dim" onClick={() => review('reject')}>Reject</button>}
          </div>
        )}
      </div>
    </>
  )
}
