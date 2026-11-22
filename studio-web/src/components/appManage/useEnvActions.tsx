import { useState } from 'react'
import { adminApi } from '../../adminApi'
import { RedeployWarning, fetchRedeployRisk, type RedeployRisk } from '../RedeployWarning'
import { errText } from './format'
import type { EnvName, Msg } from './types'

/**
 * Deploy, promote, roll back and restart, with the same confirmations the old
 * /app page and the apps list used: one confirm, and the RedeployWarning modal
 * only when the server says state is at risk.
 */
export function useEnvActions(slug: string, onMsg: (m: Msg) => void, refresh: () => void) {
  const [pending, setPending] = useState<{ env: EnvName; risk: RedeployRisk; label: string | null } | null>(null)

  async function send(env: EnvName, acknowledged: boolean, label: string | null) {
    onMsg({ text: 'Deploying…', ok: true })
    try {
      const body: Record<string, unknown> = acknowledged ? { acknowledge_data_loss: true } : {}
      if (label) body.label = label
      const d = await adminApi.post<{ message?: string }>(`/api/apps/${slug}/deploy/${env}`, body)
      onMsg({ text: d.message || 'Deploy started', ok: true })
      setTimeout(refresh, 3000)
    } catch (e) {
      onMsg({ text: errText(e), ok: false })
    }
  }

  async function deploy(env: EnvName) {
    if (!confirm(`Deploy ${slug} to ${env}?`)) return
    const raw = prompt('Release label (optional, e.g. rules=v3). Letters, digits and . _ = - only.', '')
    if (raw === null) return
    const label = raw.trim() || null
    const risk = await fetchRedeployRisk(adminApi, slug, env)
    if (risk === null) {
      if (!confirm(`AppCrane could not check what redeploying ${slug} (${env}) would destroy.\n\nDeploying replaces the container, and any path this app persists that AppCrane is not mounting is lost. Proceed anyway?`)) return
      return send(env, false, label)
    }
    if (!risk.at_risk) return send(env, false, label)
    setPending({ env, risk, label })
  }

  async function promote() {
    if (!confirm('Promote sandbox code to production? (env vars and data stay separate)')) return
    try {
      const d = await adminApi.post<{ message?: string }>(`/api/apps/${slug}/promote`)
      onMsg({ text: d.message || 'Promoted', ok: true })
    } catch (e) {
      onMsg({ text: errText(e), ok: false })
    }
    setTimeout(refresh, 3000)
  }

  async function rollback(env: EnvName, deploymentId?: number) {
    const what = deploymentId ? `release #${deploymentId}` : 'the previous version'
    if (!confirm(`Roll back ${slug} ${env} to ${what}?`)) return
    try {
      const d = await adminApi.post<{ message?: string }>(`/api/apps/${slug}/rollback/${env}`, deploymentId ? { deployment_id: deploymentId } : {})
      onMsg({ text: d.message || 'Rolled back', ok: true })
      setTimeout(refresh, 2000)
    } catch (e) {
      onMsg({ text: errText(e), ok: false })
    }
  }

  async function restart(env: EnvName) {
    if (!confirm(`Restart ${slug} ${env}? The container is recreated with the current env vars.`)) return
    try {
      await adminApi.post(`/api/apps/${slug}/restart/${env}`)
      onMsg({ text: `Restarting ${env}`, ok: true })
      setTimeout(refresh, 3000)
    } catch (e) {
      onMsg({ text: errText(e), ok: false })
    }
  }

  const modal = pending && (
    <RedeployWarning
      risk={pending.risk}
      onCancel={() => setPending(null)}
      onConfirm={() => { const p = pending; setPending(null); void send(p.env, true, p.label) }}
    />
  )

  return { deploy, promote, rollback, restart, modal }
}
