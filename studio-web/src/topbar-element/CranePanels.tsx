import { createRoot, Root } from 'react-dom/client'
import { createElement } from 'react'
import { AskPanel }     from '../components/runtime-topbar/AskPanel'
import { RequestPanel } from '../components/runtime-topbar/RequestPanel'
import { BugPanel }     from '../components/runtime-topbar/BugPanel'

/**
 * Custom Element wrappers around the React Ask / Request / Bug panels.
 *
 * Same source as /applications uses; portal mounts them by writing
 * <crane-ask-panel>, <crane-request-panel>, <crane-bug-panel> instead
 * of its own hand-rolled vanilla-JS panel DOM. Single source of truth
 * for the chrome, the plan flow, the 🎯 element-picker, and the SSE
 * streaming.
 *
 * Light DOM (no shadow root) so host-page CSS — the portal's existing
 * .ask-panel / .ask-header / .ask-input-row styles, plus admin.css for
 * /applications — applies without duplication.
 *
 * Attributes:
 *   slug              app slug (required)
 *   app-name          display name (defaults to slug)
 *   open              presence = panel is open
 *   width             panel width in px (defaults to 380/420/460)
 *   iframe-selector   CSS selector for the embedded app iframe; the
 *                     element-picker uses this to attach hover/click
 *                     listeners to the iframe's content document.
 *
 * Events:
 *   crane-close       fires when the user clicks the × button
 */

type PanelKind = 'ask' | 'request' | 'bug'

abstract class CranePanelBase extends HTMLElement {
  private root: Root | null = null
  static get observedAttributes() {
    return ['slug', 'app-name', 'open', 'width', 'iframe-selector']
  }
  abstract kind: PanelKind

  connectedCallback() {
    if (!this.root) this.root = createRoot(this)
    this.scheduleRender()
  }
  disconnectedCallback() {
    if (this.root) {
      const r = this.root
      // Unmount on a microtask so React doesn't warn about "Attempted to
      // synchronously unmount a root while React was already rendering."
      queueMicrotask(() => r.unmount())
      this.root = null
    }
  }
  attributeChangedCallback() { this.scheduleRender() }

  private renderPending = false
  private scheduleRender() {
    if (this.renderPending) return
    this.renderPending = true
    queueMicrotask(() => { this.renderPending = false; this.render() })
  }

  private render() {
    if (!this.root) return
    const slug      = this.getAttribute('slug') || ''
    const appName   = this.getAttribute('app-name') || slug
    const open      = this.hasAttribute('open')
    const widthAttr = this.getAttribute('width')
    const width     = widthAttr ? Number(widthAttr) || undefined : undefined
    const ifSel     = this.getAttribute('iframe-selector') || ''
    // Mirror the `open` attribute as a class so host-page CSS that
    // targets the legacy `#bugPanel.open` / `#askPanel.open` /
    // `#planPanel.open` selectors keeps applying to the new element
    // without rewrites in portal.
    this.classList.toggle('open', open)
    // Re-resolve the iframe element on every render so navigations or
    // env-switches (which destroy + recreate the iframe DOM node) get
    // picked up by the next pick attempt.
    const iframeRef = { current: ifSel ? (document.querySelector(ifSel) as HTMLIFrameElement | null) : null }
    const onClose = () => this.dispatchEvent(new CustomEvent('crane-close', { bubbles: true }))

    const props: Record<string, unknown> = { slug, appName, open, onClose, iframeRef }
    if (width !== undefined) props.width = width

    let Comp: React.ComponentType<any>
    switch (this.kind) {
      case 'ask':     Comp = AskPanel; break
      case 'request': Comp = RequestPanel; break
      case 'bug':     Comp = BugPanel; break
    }
    this.root.render(createElement(Comp, props))
  }
}

class CraneAskPanel     extends CranePanelBase { kind: PanelKind = 'ask' }
class CraneRequestPanel extends CranePanelBase { kind: PanelKind = 'request' }
class CraneBugPanel     extends CranePanelBase { kind: PanelKind = 'bug' }

export function defineCranePanels() {
  if (!customElements.get('crane-ask-panel'))     customElements.define('crane-ask-panel',     CraneAskPanel)
  if (!customElements.get('crane-request-panel')) customElements.define('crane-request-panel', CraneRequestPanel)
  if (!customElements.get('crane-bug-panel'))     customElements.define('crane-bug-panel',     CraneBugPanel)
}

export { CraneAskPanel, CraneRequestPanel, CraneBugPanel }
