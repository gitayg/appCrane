var T=Object.defineProperty;var E=(t,e,r)=>e in t?T(t,e,{enumerable:!0,configurable:!0,writable:!0,value:r}):t[e]=r;var l=(t,e,r)=>E(t,typeof e!="symbol"?e+"":e,r);(function(t){"use strict";const e=`
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
:host([folded]) .brand { font-size: .72rem; }
`;function r(n){return n==null?"":String(n).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;")}function b(n){if(!n)return"";const a=String(n).trim();return a?/^https?:\/\//i.test(a)||/^[/.#]/.test(a)?a:"#":""}class p extends HTMLElement{constructor(){super();l(this,"root");l(this,"wired",!1);l(this,"toggleFold",()=>{const o=!this.hasAttribute("folded");o?this.setAttribute("folded",""):this.removeAttribute("folded"),this.emit("crane-fold-toggle",{folded:o})});this.root=this.attachShadow({mode:"open"})}static get observedAttributes(){return["app-name","app-icon-url","app-slug","prod-version","sand-version","prod-url","sand-url","env","current-url","show-evict","folded"]}connectedCallback(){this.render()}attributeChangedCallback(){this.isConnected&&this.render()}emit(o,s){this.dispatchEvent(new CustomEvent(o,{bubbles:!0,composed:!0,detail:s}))}wireOnce(){this.wired||(this.wired=!0,this.root.addEventListener("click",o=>{var i;const s=o.target;if(!s)return;const d=(i=s.closest("[data-action]"))==null?void 0:i.getAttribute("data-action");if(d)switch(d){case"back":this.emit("crane-back");break;case"refresh":this.emit("crane-refresh");break;case"evict":this.emit("crane-evict");break;case"fold":this.toggleFold();break;case"env-prod":this.emit("crane-env-change",{env:"production"});break;case"env-sand":this.emit("crane-env-change",{env:"sandbox"});break}}))}template(){const o=this.hasAttribute("folded"),s=this.getAttribute("app-name")||"",d=b(this.getAttribute("app-icon-url")),i=this.getAttribute("env")||"production",v=this.getAttribute("prod-version")||"",g=this.getAttribute("sand-version")||"",m=this.getAttribute("prod-url")||"",x=this.getAttribute("sand-url")||"",u=b(this.getAttribute("current-url")),w=this.hasAttribute("show-evict"),c=i==="sandbox"?g:v,k=!!(m&&x),f=o?'<button class="fold" data-action="fold" title="Show topbar">▾</button>':'<button class="fold" data-action="fold" title="Hide topbar">▴</button>';if(o)return`<div class="bar folded">
        <div class="left"><span class="brand">App<span>Crane</span></span></div>
        <div class="right">${f}</div>
      </div>`;const A=d?`<img class="icon" src="${r(d)}" alt="">`:"",y=c?`<span class="version">${r(c.startsWith("v")?c:"v"+c)}</span>`:"",$=k?`
      <div class="env">
        <button data-action="env-prod" class="${i==="production"?"active-prod":""}">Production</button>
        <button data-action="env-sand" class="${i==="sandbox"?"active-sand":""}">Sandbox</button>
      </div>`:"",C=w?`<button class="btn danger" data-action="evict" title="Tear down this app's shared container">🗑 Evict</button>`:"",S=u?`<a class="btn" href="${r(u)}" target="_blank" rel="noreferrer noopener">Open ↗</a>`:"";return`
      <div class="bar">
        <div class="left">
          <span class="brand">App<span>Crane</span></span>
          ${A}
          <span class="name">${r(s)}</span>
          ${y}
          ${$}
        </div>
        <div class="right">
          <slot name="actions"></slot>
          <button class="btn" data-action="refresh" title="Reload app">↺ Refresh</button>
          ${S}
          ${C}
          <button class="btn" data-action="back">← Back</button>
          ${f}
        </div>
      </div>
    `}render(){this.root.innerHTML=`<style>${e}</style>${this.template()}`,this.wireOnce()}}function h(){customElements.get("crane-app-topbar")||customElements.define("crane-app-topbar",p)}h(),t.CraneAppTopbar=p,t.defineCraneAppTopbar=h,Object.defineProperty(t,Symbol.toStringTag,{value:"Module"})})(this.CraneTopbar=this.CraneTopbar||{});
