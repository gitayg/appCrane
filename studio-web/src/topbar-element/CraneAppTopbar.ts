// <crane-app-topbar> — shared iframe-app top bar.
//
// Owns the chrome (brand, icon, name, version pill, env switcher, refresh,
// open-in-tab, back, evict, fold chevron). Per-runtime widgets — Learn /
// Request / Jobs / Presence / Builder Working badge — are slotted as
// children with slot="actions". Both the React admin and the vanilla
// portal share one source of truth for the chrome and styling while
// still owning their own action widgets.
//
// Attributes (kebab-case):
//   app-name        — visible app name
//   app-icon-url    — optional icon image URL (only http(s) allowed)
//   app-slug        — slug (passed through; this element doesn't read it)
//   prod-version    — version pill text for Production env
//   sand-version    — version pill text for Sandbox env
//   prod-url        — production iframe URL
//   sand-url        — sandbox iframe URL
//   env             — 'production' | 'sandbox' (which is current)
//   current-url     — what "open in new tab" links at (only http(s) or path)
//   show-evict      — boolean: render the 🗑 evict button
//   folded          — boolean: collapse to a thin strip with brand + chevron
//
// Events (CustomEvent, bubbles + composed):
//   crane-back, crane-refresh, crane-evict, crane-fold-toggle ({ folded })
//   crane-env-change ({ env: 'production' | 'sandbox' })
//
// CSS custom property set on :host — --crane-topbar-height (44px / 22px).
// Parents can use it to size the iframe area below.
//
// Security notes:
// - All attribute values that interpolate into the shadow HTML pass through
//   esc() (escapes & < > " '). innerHTML is set once per render against a
//   string built only from STYLES + escaped attribute values + a static
//   <slot>. The slot content (light DOM) is consumer-controlled markup
//   that the consumer is responsible for; we render no consumer-supplied
//   HTML strings.
// - URLs that land in href= / src= go through safeUrl() which permits only
//   http(s) origins and same-origin path-relative URLs. javascript: / data:
//   are dropped to '#'.

const STYLES = `
:host {
  display: block;
  --crane-topbar-height: 44px;
  contain: layout style;
}
:host([folded]) { --crane-topbar-height: 22px; }
.bar {
  height: var(--crane-topbar-height);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 14px;
  background: var(--surface, #1f2230);
  border-bottom: 1px solid var(--border, #2a2d3a);
  color: var(--text, #e4e4e7);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  font-size: .82rem;
  transition: height .15s ease;
  overflow: hidden;
  box-sizing: border-box;
}
.left, .right { display: flex; align-items: center; gap: 10px; min-width: 0; }
.left { flex: 1; min-width: 0; }
.brand { font-weight: 700; font-size: .9rem; flex-shrink: 0; }
.brand span { color: var(--accent, #3b82f6); }
.icon { width: 22px; height: 22px; border-radius: 4px; object-fit: cover; flex-shrink: 0; }
.name { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 320px; }
.version {
  font-family: monospace; font-size: .72rem; color: var(--dim, #a1a1aa);
  padding: 2px 6px; background: var(--surface2, #2a2d3a); border-radius: 4px; flex-shrink: 0;
}
.env { display: inline-flex; flex-shrink: 0; }
.env button {
  background: var(--surface2, #2a2d3a); color: var(--dim, #a1a1aa);
  border: 1px solid var(--border, #2a2d3a);
  padding: 3px 9px; font-size: .72rem; cursor: pointer; font-family: inherit;
}
.env button:first-child { border-radius: 4px 0 0 4px; border-right: none; }
.env button:last-child  { border-radius: 0 4px 4px 0; }
.env button.active-prod { background: rgba(34,197,94,.15);  color: #22c55e; border-color: rgba(34,197,94,.4); }
.env button.active-sand { background: rgba(249,115,22,.15); color: #f97316; border-color: rgba(249,115,22,.4); }
button.btn, a.btn {
  background: transparent; color: var(--dim, #a1a1aa);
  border: 1px solid var(--border, #2a2d3a); border-radius: 5px;
  padding: 4px 10px; cursor: pointer; font-size: .76rem; font-family: inherit;
  text-decoration: none; transition: border-color .12s, color .12s; white-space: nowrap;
}
button.btn:hover, a.btn:hover { border-color: var(--accent, #3b82f6); color: var(--text, #e4e4e7); }
button.btn.danger { color: #fca5a5; border-color: rgba(239,68,68,.4); }
button.btn.danger:hover { background: rgba(239,68,68,.12); color: #fff; border-color: #ef4444; }
button.fold {
  background: transparent; border: 1px solid var(--border, #2a2d3a); border-radius: 5px;
  color: var(--dim, #a1a1aa); cursor: pointer; padding: 2px 7px; font-size: .85rem; line-height: 1;
}
button.fold:hover { color: var(--text, #e4e4e7); border-color: var(--accent, #3b82f6); }
:host([folded]) .name,
:host([folded]) .icon,
:host([folded]) .version,
:host([folded]) .env,
:host([folded]) ::slotted([slot="actions"]),
:host([folded]) .right > .btn { display: none; }
:host([folded]) .bar { padding: 0 8px; }
`

function esc(s: string | null | undefined): string {
  if (s == null) return ''
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

// Allow only safe URL shapes for href / src interpolation.
// Permitted: http(s)://…, /path, ./path, ../path, #fragment.
// Rejected (mapped to '#'): javascript:, data:, vbscript:, blob:, file:, etc.
function safeUrl(u: string | null | undefined): string {
  if (!u) return ''
  const s = String(u).trim()
  if (!s) return ''
  if (/^https?:\/\//i.test(s)) return s
  if (/^[/.#]/.test(s)) return s
  return '#'
}

export class CraneAppTopbar extends HTMLElement {
  static get observedAttributes(): string[] {
    return [
      'app-name', 'app-icon-url', 'app-slug',
      'prod-version', 'sand-version',
      'prod-url', 'sand-url', 'env',
      'current-url', 'show-evict', 'folded',
    ]
  }

  private root: ShadowRoot
  private wired = false

  constructor() {
    super()
    this.root = this.attachShadow({ mode: 'open' })
  }

  connectedCallback() { this.render() }
  attributeChangedCallback() { if (this.isConnected) this.render() }

  private emit(name: string, detail?: Record<string, unknown>) {
    this.dispatchEvent(new CustomEvent(name, { bubbles: true, composed: true, detail }))
  }

  private toggleFold = () => {
    const next = !this.hasAttribute('folded')
    if (next) this.setAttribute('folded', '')
    else this.removeAttribute('folded')
    this.emit('crane-fold-toggle', { folded: next })
  }

  private wireOnce() {
    if (this.wired) return
    this.wired = true
    this.root.addEventListener('click', (e) => {
      const target = e.target as HTMLElement | null
      if (!target) return
      const action = target.closest('[data-action]')?.getAttribute('data-action')
      if (!action) return
      switch (action) {
        case 'back':    this.emit('crane-back'); break
        case 'refresh': this.emit('crane-refresh'); break
        case 'evict':   this.emit('crane-evict'); break
        case 'fold':    this.toggleFold(); break
        case 'env-prod': this.emit('crane-env-change', { env: 'production' }); break
        case 'env-sand': this.emit('crane-env-change', { env: 'sandbox' }); break
      }
    })
  }

  private template(): string {
    const folded = this.hasAttribute('folded')
    const name        = this.getAttribute('app-name')    || ''
    const iconUrl     = safeUrl(this.getAttribute('app-icon-url'))
    const env         = this.getAttribute('env') || 'production'
    const prodVersion = this.getAttribute('prod-version') || ''
    const sandVersion = this.getAttribute('sand-version') || ''
    const prodUrl     = this.getAttribute('prod-url') || ''
    const sandUrl     = this.getAttribute('sand-url') || ''
    const currentUrl  = safeUrl(this.getAttribute('current-url'))
    const showEvict   = this.hasAttribute('show-evict')
    const version     = env === 'sandbox' ? sandVersion : prodVersion
    const showSwitch  = !!(prodUrl && sandUrl)

    const foldChev = folded
      ? `<button class="fold" data-action="fold" title="Show topbar">▾</button>`
      : `<button class="fold" data-action="fold" title="Hide topbar">▴</button>`

    if (folded) {
      // Bar collapses to just the unfold chevron — no logo, no slot, no name.
      // Lets the iframe reclaim almost all the vertical space.
      return `<div class="bar folded">
        <div class="left"></div>
        <div class="right">${foldChev}</div>
      </div>`
    }

    const iconHtml = iconUrl ? `<img class="icon" src="${esc(iconUrl)}" alt="">` : ''
    const versionHtml = version
      ? `<span class="version">${esc(version.startsWith('v') ? version : 'v' + version)}</span>`
      : ''
    const envHtml = showSwitch ? `
      <div class="env">
        <button data-action="env-prod" class="${env === 'production' ? 'active-prod' : ''}">Production</button>
        <button data-action="env-sand" class="${env === 'sandbox'    ? 'active-sand' : ''}">Sandbox</button>
      </div>` : ''
    const evictHtml = showEvict
      ? `<button class="btn danger" data-action="evict" title="Tear down this app's shared container">🗑 Evict</button>`
      : ''
    const newTabHtml = currentUrl
      ? `<a class="btn" href="${esc(currentUrl)}" target="_blank" rel="noreferrer noopener">Open ↗</a>`
      : ''

    return `
      <div class="bar">
        <div class="left">
          <span class="brand">App<span>Crane</span></span>
          ${iconHtml}
          <span class="name">${esc(name)}</span>
          ${versionHtml}
          ${envHtml}
        </div>
        <div class="right">
          <slot name="actions"></slot>
          <button class="btn" data-action="refresh" title="Reload app">↺ Refresh</button>
          ${newTabHtml}
          ${evictHtml}
          <button class="btn" data-action="back">← Back</button>
          ${foldChev}
        </div>
      </div>
    `
  }

  private render() {
    // SAFETY: STYLES is a static string; every interpolation in template()
    // either passes through esc() (HTML-escapes & < > " ') or safeUrl()
    // (rejects javascript:/data: schemes). The only consumer-supplied
    // markup is via <slot>, which is light DOM the consumer owns —
    // we never serialize it through innerHTML.
    this.root.innerHTML = `<style>${STYLES}</style>${this.template()}` // nosemgrep: insecure-document-method — escaped/static interpolation only
    this.wireOnce()
  }
}

export function defineCraneAppTopbar() {
  if (!customElements.get('crane-app-topbar')) {
    customElements.define('crane-app-topbar', CraneAppTopbar)
  }
}
