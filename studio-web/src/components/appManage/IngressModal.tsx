import { useState } from 'react'
import { adminApi } from '../../adminApi'
import type { ManagedApp } from './types'

// The ingress dialog from the apps list (Applications.tsx), as its own
// component so the manage page's Network tab can open it. Same copy, same
// confirmations, same request body; only platform admins get controls.

type IngressType = 'http' | 'tcp' | 'dual'
const PUBLIC_PORT_MIN = 1024
const PUBLIC_PORT_MAX = 65535
const AUTO_PORT_RANGE = '31000-31999'
const PUBLIC_PORT_RANGE = '1024-65535'
const CONTROL_PLANE_PORT = 3000
const CONTROL_PLANE_MAPPING = 'container:3000'
export const publishesPort = (t?: string): boolean => t === 'tcp' || t === 'dual'

export function IngressModal({ app, isPlatformAdmin, onClose, onSaved }: {
  app: ManagedApp
  isPlatformAdmin: boolean
  onClose: () => void
  onSaved: (next: Partial<ManagedApp>) => void
}) {
  const [ingressDraft, setIngressDraft] = useState<{ type: IngressType; port: string; dataPort: string; sandboxPort: string }>({
    type: publishesPort(app.ingress_type) ? app.ingress_type as IngressType : 'http',
    port: app.public_port ? String(app.public_port) : '',
    dataPort: app.data_plane_port ? String(app.data_plane_port) : '',
    sandboxPort: app.sandbox_public_port ? String(app.sandbox_public_port) : '',
  })
  const [ingressBusy, setIngressBusy] = useState(false)

  async function save() {
    const { type, port: portRaw, dataPort: dataPortRaw, sandboxPort: sandboxPortRaw } = ingressDraft
    const body: { ingress_type: IngressType; public_port?: number; sandbox_public_port?: number | null; data_plane_port?: number | null } = { ingress_type: type }
    // Leaving 'dual' DROPS the data plane, and the server refuses the flip
    // unless the request says so. That refusal exists because 'tcp' publishes
    // container port 3000: without an explicit null, flipping a dual app to tcp
    // would silently repoint the same host port from the data plane onto the
    // HTTP control plane. Sending it here is what makes the transition
    // reachable from the dashboard at all — the confirm below names the change.
    if (type !== 'dual' && app.data_plane_port != null) body.data_plane_port = null
    if (publishesPort(type) && portRaw.trim()) {
      const n = parseInt(portRaw.trim(), 10)
      if (!Number.isFinite(n) || n < PUBLIC_PORT_MIN || n > PUBLIC_PORT_MAX) {
        alert(`Public port must be a number between ${PUBLIC_PORT_MIN} and ${PUBLIC_PORT_MAX}.`); return
      }
      body.public_port = n
    }
    if (type === 'dual') {
      const raw = dataPortRaw.trim()
      // Not defaulted. The publish has to target SOME container port, and the
      // only other one in the container is the HTTP control plane — guessing
      // would publish that raw, which is the one outcome this whole feature
      // exists to prevent.
      if (!raw) { alert('A dual app needs a data plane port — the container-side port the raw publish targets. AppCrane will not guess one.'); return }
      const n = parseInt(raw, 10)
      if (!Number.isFinite(n) || n < PUBLIC_PORT_MIN || n > PUBLIC_PORT_MAX) {
        alert(`Data plane port must be a number between ${PUBLIC_PORT_MIN} and ${PUBLIC_PORT_MAX}.`); return
      }
      if (n === CONTROL_PLANE_PORT) {
        alert(`Data plane port cannot be ${CONTROL_PLANE_PORT}. That is this container's HTTP control plane — the port Caddy proxies to. Publishing it raw would put the app's ordinary HTTP origin on the host with no TLS, no AppCrane sign-in, no identity headers and no request audit. Give the data plane its own listener on another port inside the container.`); return
      }
      body.data_plane_port = n
    }
    // v2.46.0: the sandbox container's own host port. Sent ONLY when the field
    // changed — omitted means "leave sandbox alone", and an empty box on an app
    // that has one means drop it. A second published port is a second door with
    // no forward_auth, so it must never appear as a side effect of editing
    // something else in this panel.
    const sandboxRaw = sandboxPortRaw.trim()
    const currentSandbox = app.sandbox_public_port ?? null
    if (publishesPort(type)) {
      if (!sandboxRaw && currentSandbox !== null) {
        body.sandbox_public_port = null
      } else if (sandboxRaw) {
        const n = parseInt(sandboxRaw, 10)
        if (!Number.isFinite(n) || n < PUBLIC_PORT_MIN || n > PUBLIC_PORT_MAX) {
          alert(`Sandbox port must be a number between ${PUBLIC_PORT_MIN} and ${PUBLIC_PORT_MAX}.`); return
        }
        if (n !== currentSandbox) body.sandbox_public_port = n
      }
    } else if (currentSandbox !== null) {
      body.sandbox_public_port = null
    }
    setIngressBusy(true)
    try {
      const r = await adminApi.put<{ app?: ManagedApp; error?: { message?: string } }>(`/api/apps/${app.slug}`, body)
      if (r?.error) { alert('Failed: ' + (r.error.message || 'unknown')); return }
      const next = {
        ingress_type: r?.app?.ingress_type ?? type,
        public_port: r?.app?.public_port ?? null,
        data_plane_port: r?.app?.data_plane_port ?? null,
        sandbox_public_port: r?.app?.sandbox_public_port ?? null,
        pending_port_release: r?.app?.pending_port_release ?? null,
      }
      onSaved(next)
      setIngressDraft({
        type: next.ingress_type,
        port: next.public_port ? String(next.public_port) : '',
        dataPort: next.data_plane_port ? String(next.data_plane_port) : '',
        sandboxPort: next.sandbox_public_port ? String(next.sandbox_public_port) : '',
      })
    } catch (e) {
      alert('Failed: ' + (e as Error).message)
    } finally {
      setIngressBusy(false)
    }
  }

  const curType: IngressType = publishesPort(app.ingress_type) ? app.ingress_type as IngressType : 'http'
    const isTcp = curType === 'tcp'
    const isDual = curType === 'dual'
    // Everything the red exposure block says is true of both publishing
    // types — a host port with nothing of Caddy's in front of it.
    const published = publishesPort(curType)
    // What the raw publish targets INSIDE the container. A pure-tcp app has
    // one listener and the whole of it is published, so that is the control
    // plane's own port; a dual app names a second one.
    const containerPort = isDual ? app.data_plane_port : CONTROL_PLANE_PORT
    const dirty = ingressDraft.type !== curType
      || (publishesPort(ingressDraft.type) && ingressDraft.port.trim() !== String(app.public_port ?? ''))
      || (ingressDraft.type === 'dual' && ingressDraft.dataPort.trim() !== String(app.data_plane_port ?? ''))
      || (publishesPort(ingressDraft.type)
          && ingressDraft.sandboxPort.trim() !== String(app.sandbox_public_port ?? ''))
    return (
      <div
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 10500, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
        onClick={onClose}
      >
        <div
          style={{ width: 'min(600px, 92vw)', maxHeight: '85vh', background: 'var(--surface, #1a1a1a)', color: 'var(--text)', border: '1px solid var(--border, #333)', borderRadius: 8, boxShadow: '0 16px 48px rgba(0,0,0,.5)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
          onClick={e => e.stopPropagation()}
          role="dialog"
          aria-label={`Ingress for ${app.name}`}
        >
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border, #333)', background: 'var(--surface2, #232323)', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontWeight: 600, fontSize: '.95rem' }}>Ingress · {app.name}</span>
            <button className="btn btn-xs" style={{ marginLeft: 'auto' }} onClick={onClose}>Close</button>
          </div>
          <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14, fontSize: '.85rem', overflowY: 'auto' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <span style={{ color: 'var(--dim)' }}>Current</span>
              <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{curType}</span>
              {curType === 'http' && <span style={{ color: 'var(--dim)', fontSize: '.78rem' }}>HTTP through Caddy — SSO, TLS, identity headers, request logging all apply.</span>}
              {isDual && <span style={{ color: 'var(--dim)', fontSize: '.78rem' }}>Two planes at once — an HTTP control plane through Caddy, and a raw data plane published on the host.</span>}
            </div>

            {/* The point of the dual type is that the two planes have
                DIFFERENT security properties, and a single badge or enum
                can't say that. Showing them side by side is the only way a
                reader learns which half of their app is defended. */}
            {isDual && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div style={{ border: '1px solid rgba(34,197,94,.35)', background: 'rgba(34,197,94,.07)', borderRadius: 6, padding: 12 }}>
                  <div style={{ fontWeight: 700, fontSize: '.78rem', letterSpacing: '.3px', color: 'var(--green, #22c55e)', marginBottom: 6 }}>CONTROL PLANE · defended</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '.78rem', marginBottom: 6 }}>{CONTROL_PLANE_MAPPING} → Caddy</div>
                  <p style={{ margin: 0, color: 'var(--dim)', fontSize: '.75rem' }}>
                    Ordinary HTTP at this app's AppCrane URL. TLS, AppCrane SSO, <code style={{ fontFamily: 'monospace' }}>X-AppCrane-*</code> identity
                    headers, security headers and access logs all apply, exactly as on an <code style={{ fontFamily: 'monospace' }}>http</code> app.
                    This is also the plane the health check probes.
                  </p>
                </div>
                <div style={{ border: '1px solid rgba(239,68,68,.35)', background: 'rgba(239,68,68,.08)', borderRadius: 6, padding: 12 }}>
                  <div style={{ fontWeight: 700, fontSize: '.78rem', letterSpacing: '.3px', color: 'var(--red, #ef4444)', marginBottom: 6 }}>DATA PLANE · undefended</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '.78rem', marginBottom: 6 }}>
                    0.0.0.0:{app.public_port ?? '—'} → container:{app.data_plane_port ?? '—'}
                  </div>
                  <p style={{ margin: 0, color: 'var(--dim)', fontSize: '.75rem' }}>
                    A direct Docker publish. Caddy is not in this path, so none of the above applies to it — see below.
                    Clients reach it at the host address and this port; nothing about the AppCrane URL is involved.
                  </p>
                </div>
              </div>
            )}

            {published && (
              <div style={{ border: '1px solid rgba(239,68,68,.35)', background: 'rgba(239,68,68,.08)', borderRadius: 6, padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: 'monospace', fontSize: '1.5rem', fontWeight: 700, color: 'var(--red, #ef4444)' }}>
                    {app.public_port ? `:${app.public_port}` : 'no port allocated'}
                  </span>
                  {app.public_port && (
                    <span style={{ color: 'var(--dim)', fontSize: '.78rem', fontFamily: 'monospace' }}>
                      0.0.0.0:{app.public_port} → container:{containerPort ?? '—'}
                    </span>
                  )}
                </div>
                <p style={{ margin: 0 }}>
                  <strong>This port is a second door, and AppCrane does not guard it.</strong> Traffic to it never
                  touches Caddy, so there is <strong>no AppCrane sign-in</strong>, no <code style={{ fontFamily: 'monospace' }}>X-AppCrane-*</code> identity
                  headers, no per-request audit, no rate limiting, no security headers and no TLS from AppCrane.
                  Every access control AppCrane has assumes Caddy is the only way in. <strong>The app authenticates
                  every connection itself</strong> — if its own auth has a gap, anyone who can reach this host is inside it.
                  {isDual && <> This is true of the <strong>data plane only</strong>. The control plane above is
                  untouched and still fully behind Caddy — but the two are the same process in the same container,
                  so a flaw reachable through this port is reachable in the code that serves the defended plane too.</>}
                </p>
                <p style={{ margin: 0, color: 'var(--dim)' }}>
                  This host sits behind SDP, so the port is not on the internet — the population that can reach it
                  is everyone SDP admits, plus any compromised device inside that perimeter. For a forward / CONNECT
                  proxy that means an unaudited egress path out of the perimeter, used by whoever finds it.
                  {isTcp
                    ? <> The app's 407 Proxy-Authenticate path is the critical path here — not the ingress.</>
                    : <> Whatever this app's data-plane protocol uses to authenticate is the critical path here — not the ingress,
                      and not the sign-in on the control plane, which this port does not go through.</>}
                </p>
                <p style={{ margin: 0, color: 'var(--dim)' }}>
                  The app can still authenticate against AppCrane: <code style={{ fontFamily: 'monospace' }}>/api/me</code> with
                  the user's bearer token, or <code style={{ fontFamily: 'monospace' }}>/api/service</code> with its
                  own <code style={{ fontFamily: 'monospace' }}>APPCRANE_SERVICE_TOKEN</code> over the docker bridge.
                </p>
                <p style={{ margin: 0, color: 'var(--dim)' }}>
                  AppCrane <strong>publishes</strong> the port; reaching it from outside this host is governed by SDP
                  and the host's own filtering. Do not read that as two independent keys — see the Linux caveat below,
                  which is why a published port is not as contained as it looks.
                </p>
                <p style={{ margin: 0, color: 'var(--dim)' }}>
                  <strong>Linux caveat:</strong> a Docker-published port is a DNAT rule evaluated in{' '}
                  <code style={{ fontFamily: 'monospace' }}>FORWARD</code> and never traverses{' '}
                  <code style={{ fontFamily: 'monospace' }}>INPUT</code>, so a plain{' '}
                  <code style={{ fontFamily: 'monospace' }}>ufw deny</code> does <strong>not</strong> block it.
                  Filter in the <code style={{ fontFamily: 'monospace' }}>DOCKER-USER</code> chain, or in a cloud
                  security group upstream of this host.
                </p>
                <p style={{ margin: 0, color: 'var(--dim)' }}>
                  {isDual ? (
                    <>
                      The publish covers the <strong>whole listener on container port {app.data_plane_port ?? '—'}</strong>, not just the
                      protocol you had in mind for it. Anything that listener answers is reachable here. Port{' '}
                      <code style={{ fontFamily: 'monospace' }}>{CONTROL_PLANE_PORT}</code> is <strong>not</strong> published — that is
                      the whole reason a data plane port exists, and why AppCrane refuses to set it to{' '}
                      <code style={{ fontFamily: 'monospace' }}>{CONTROL_PLANE_PORT}</code>: doing so would put the app's ordinary
                      HTTP origin, health route and any admin or metrics route on the host with none of Caddy's controls in front.
                    </>
                  ) : (
                    <>
                      The publish covers the <strong>whole container port</strong>, not just the app's raw protocol —
                      every HTTP route it serves on port 3000, including <code style={{ fontFamily: 'monospace' }}>/api/health</code>{' '}
                      and any admin or metrics route it assumed was behind AppCrane SSO, answers here too.
                    </>
                  )}
                </p>
              </div>
            )}

            {/* The one state where "Current: http" is not the whole truth.
                Shown to readers, not only to the admin who flipped it: the
                person who has to act on it is whoever next looks at this app. */}
            {!published && !!app.pending_port_release && (
              <div style={{ border: '1px solid rgba(245,158,11,.4)', background: 'rgba(245,158,11,.08)', borderRadius: 6, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--amber, #f59e0b)' }}>
                  port {app.pending_port_release} is still open
                </div>
                <p style={{ margin: 0 }}>
                  Ingress is <code style={{ fontFamily: 'monospace' }}>http</code> again, so AppCrane publishes
                  nothing for this app — but the publish is a <code style={{ fontFamily: 'monospace' }}>docker run</code>{' '}
                  flag, and the container that is <strong>running right now</strong> was started with it. It keeps
                  binding <code style={{ fontFamily: 'monospace' }}>0.0.0.0:{app.pending_port_release}</code>, with no
                  AppCrane sign-in in front of it, until the container is <strong>recreated</strong>.
                </p>
                <p style={{ margin: 0, color: 'var(--dim)' }}>
                  <strong>Deploy this app, or press ↺ restart, to actually close the port.</strong> Until then
                  AppCrane keeps {app.pending_port_release} reserved to this app — no other app can be given a port
                  something is still bound to — and hands it back to the pool the moment the container returns
                  without it. The exposure is not revoked before that.
                </p>
              </div>
            )}

            {isPlatformAdmin ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, borderTop: '1px solid var(--border, #333)', paddingTop: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  Ingress type
                  <select
                    value={ingressDraft.type}
                    aria-label={`Ingress type for ${app.name}`}
                    onChange={e => setIngressDraft(d => ({ ...d, type: e.target.value as IngressType }))}
                    style={{ fontSize: '.8rem' }}
                  >
                    <option value="http">http — through Caddy (default)</option>
                    <option value="tcp">tcp — published on the host, unguarded</option>
                    <option value="dual">dual — Caddy for HTTP, plus an unguarded published port</option>
                  </select>
                </label>
                {publishesPort(ingressDraft.type) && (
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    Public host port
                    <input
                      className="editable" type="number" min={PUBLIC_PORT_MIN} max={PUBLIC_PORT_MAX}
                      aria-label={`Public host port for ${app.name}`}
                      value={ingressDraft.port}
                      placeholder="auto"
                      onChange={e => setIngressDraft(d => ({ ...d, port: e.target.value }))}
                      style={{ width: 110, fontFamily: 'monospace' }}
                    />
                    <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>
                      Leave blank to keep the current port, or to have one allocated from {AUTO_PORT_RANGE}.
                      Name one yourself and it may be anything in {PUBLIC_PORT_RANGE} — when a fleet of
                      clients is already configured for a port, that number is not AppCrane's to change. A port outside
                      the {AUTO_PORT_RANGE} block needs a firewall rule of its own.
                    </span>
                  </label>
                )}
                {/* The container-side half. Only 'dual' has two planes to
                    tell apart: a pure-tcp app publishes its one listener,
                    so a second number there would just be another way to
                    name the same port. */}
                {ingressDraft.type === 'dual' && (
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    Data plane port <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>(inside the container)</span>
                    <input
                      className="editable" type="number" min={PUBLIC_PORT_MIN} max={PUBLIC_PORT_MAX}
                      aria-label={`Data plane container port for ${app.name}`}
                      value={ingressDraft.dataPort}
                      placeholder="required"
                      onChange={e => setIngressDraft(d => ({ ...d, dataPort: e.target.value }))}
                      style={{ width: 110, fontFamily: 'monospace' }}
                    />
                    <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>
                      The port your app's raw listener binds INSIDE the container — required, and it cannot
                      be {CONTROL_PLANE_PORT}. Port {CONTROL_PLANE_PORT} is the HTTP control plane Caddy proxies to;
                      publishing it raw would hand out the app's ordinary HTTP origin with no TLS, no sign-in, no
                      identity headers and no audit. Two apps may use the same container-side port — only the host
                      port has to be unique.
                    </span>
                  </label>
                )}
                {/* v2.46.0: the SANDBOX container's own host port. Optional
                    and independent — leave it blank and sandbox publishes
                    nothing, exactly as it always did. It exists so a raw
                    data plane can be exercised before it goes live, which
                    was impossible when the publish was production-only. */}
                {publishesPort(ingressDraft.type) && (
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    Sandbox host port <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>(optional)</span>
                    <input
                      className="editable" type="number" min={PUBLIC_PORT_MIN} max={PUBLIC_PORT_MAX}
                      aria-label={`Sandbox public port for ${app.name}`}
                      value={ingressDraft.sandboxPort}
                      placeholder="none"
                      onChange={e => setIngressDraft(d => ({ ...d, sandboxPort: e.target.value }))}
                      style={{ width: 110, fontFamily: 'monospace' }}
                    />
                    <span style={{ color: 'var(--dim)', fontSize: '.75rem' }}>
                      Publishes the SANDBOX container on its own host port, so the raw plane can be tried
                      before it is promoted. Must differ from every port any app holds in either
                      environment. Leave blank and sandbox publishes nothing. This is a SECOND door with no
                      sign-in, no TLS from AppCrane and no audit — on the container running your least
                      reviewed code.
                    </span>
                  </label>
                )}
                {ingressDraft.type === 'tcp' && !isTcp && (
                  <p style={{ margin: 0, color: 'var(--red, #ef4444)', fontSize: '.8rem' }}>
                    Switching to tcp opens a host port for this app. It will be reachable with no AppCrane
                    authentication — the app must authenticate every connection itself. The port is a{' '}
                    <code style={{ fontFamily: 'monospace' }}>docker run</code> flag, so it appears when the
                    container is next recreated: a deploy, or the ↺ restart button.
                  </p>
                )}
                {ingressDraft.type === 'dual' && !isDual && (
                  <p style={{ margin: 0, color: 'var(--red, #ef4444)', fontSize: '.8rem' }}>
                    Switching to dual opens a host port for this app, in ADDITION to the HTTP it already serves
                    through Caddy. The published port is reachable with no AppCrane authentication — the app must
                    authenticate every connection on it itself. The HTTP control plane on container port{' '}
                    {CONTROL_PLANE_PORT} is unaffected: it keeps its TLS, sign-in, identity headers and logging, and
                    it stays the plane the health check probes, because a bare connection to the data port would look
                    healthy even with the control plane wedged. The port is a{' '}
                    <code style={{ fontFamily: 'monospace' }}>docker run</code> flag, so it appears when the
                    container is next recreated: a deploy, or the ↺ restart button.
                  </p>
                )}
                {ingressDraft.type === 'http' && published && (
                  <p style={{ margin: 0, color: 'var(--red, #ef4444)', fontSize: '.8rem' }}>
                    This does <strong>not</strong> close port {app.public_port}. It stops AppCrane publishing it —
                    the running container keeps binding it until the container is <strong>recreated</strong>
                    {' '}(deploy, or the ↺ restart button), because the publish is a{' '}
                    <code style={{ fontFamily: 'monospace' }}>docker run</code> flag. Until you do that the port
                    stays reachable and unauthenticated, so AppCrane keeps it <strong>reserved to this app</strong>:
                    no other app can be given a number something is still bound to, and it returns to the pool
                    automatically once the container comes back without it. <strong>Redeploy or restart this app
                    to actually close the port.</strong>
                  </p>
                )}
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                  <button
                    className="btn btn-xs"
                    disabled={!dirty || ingressBusy}
                    onClick={() => {
                      if (ingressDraft.type === 'tcp' && isDual
                        && !confirm(`Move "${app.name}" from dual to plain TCP?\n\nThis DROPS the data plane (container port ${app.data_plane_port}). Host port ${app.public_port ?? '(auto)'} will then reach container port ${CONTROL_PLANE_PORT} — the HTTP control plane — directly, with no TLS from AppCrane, no sign-in, no identity headers and no request audit. Clients stay pointed at the same port; what answers them changes.`)) return
                      if (ingressDraft.type === 'tcp' && !isTcp && !isDual
                        && !confirm(`Publish "${app.name}" on a raw TCP port?\n\nThe port is NOT behind AppCrane authentication. The app owns authn entirely.`)) return
                      if (ingressDraft.type === 'dual' && !isDual
                        && !confirm(`Publish a raw data plane for "${app.name}"?\n\nHost port ${ingressDraft.port.trim() || '(auto)'} will reach container port ${ingressDraft.dataPort.trim() || '(unset)'} directly. That port is NOT behind AppCrane authentication — the app owns authn on it entirely. The HTTP control plane on container port ${CONTROL_PLANE_PORT} stays behind Caddy, unchanged.`)) return
                      void save()
                    }}
                  >{ingressBusy ? 'Saving…' : 'Save'}</button>
                </div>
              </div>
            ) : (
              <p style={{ margin: 0, color: 'var(--dim)', fontSize: '.8rem', borderTop: '1px solid var(--border, #333)', paddingTop: 14 }}>
                Only a platform admin can change ingress. Opening a host port bypasses every control AppCrane
                has, so it is not a self-service setting — ask a platform admin.
              </p>
            )}
          </div>
        </div>
      </div>
  )
}
