// What the API's limits_applied says about a CPU/memory change, in words.
// The new limits reach running containers at once; a container that was not
// updated (busy near the new limit, or Docker refused) gets them at the next
// deploy or restart.

export interface LimitApply { env: string; applied: boolean; reason?: string }

export function limitsAppliedText(results: LimitApply[] | undefined | null): { text: string; ok: boolean } {
  if (!results) return { text: 'Resource limits saved. They apply when the container is next created: redeploy or restart.', ok: true }
  const done = results.filter(r => r.applied).map(r => r.env)
  const skipped = results.filter(r => !r.applied && r.reason !== 'not running')
  const parts: string[] = []
  if (done.length) parts.push(`Applied now to ${done.join(' and ')}.`)
  for (const r of skipped) parts.push(`${r.env}: not changed yet (${r.reason}).`)
  if (!parts.length) parts.push('Saved. No container is running; the limits apply when it starts.')
  return { text: `Resource limits saved. ${parts.join(' ')}`, ok: skipped.length === 0 }
}
