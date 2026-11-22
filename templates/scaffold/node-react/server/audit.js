// Write an audit event to AppCrane (POST /api/service/audit/events).
//
// Authenticated by this app's APPCRANE_SERVICE_TOKEN over CRANE_INTERNAL_URL,
// both injected by AppCrane; the call works from the server only. The action
// must be registered on the app first (app page > Audit events). Pass the
// incoming request as `req` to record the signed-in user as the actor: the
// signed X-AppCrane-* headers are forwarded and AppCrane checks them. Without
// `req` the actor is the app itself.
//
//   await auditEvent('invoice.paid', { req, targets: [{ type: 'invoice', id }], metadata: { amount } });

export async function auditEvent(action, { req, targets, metadata, actor, occurredAt, idempotencyKey } = {}) {
  const base = process.env.CRANE_INTERNAL_URL;
  const token = process.env.APPCRANE_SERVICE_TOKEN;
  if (!base || !token) throw new Error('audit: CRANE_INTERNAL_URL / APPCRANE_SERVICE_TOKEN are not set (not running on AppCrane)');
  const identity = {};
  for (const [k, v] of Object.entries(req?.headers || {})) if (k.startsWith('x-appcrane-') && typeof v === 'string') identity[k] = v;
  const body = {
    action, targets, metadata, actor, occurred_at: occurredAt, idempotency_key: idempotencyKey,
    ...(Object.keys(identity).length ? { identity } : {}),
    context: req ? { location: req.ip?.replace(/^::ffff:/, ''), user_agent: req.headers?.['user-agent'] } : undefined,
  };
  const res = await fetch(`${base.replace(/\/+$/, '')}/api/service/audit/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-appcrane-service-token': token },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`audit: ${res.status} ${json.error?.code || ''} ${json.error?.message || ''}`.trim());
  return json.event;
}
