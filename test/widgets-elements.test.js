import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import vm from 'vm';

// The widget script (server/assets/widgets.js) run in a VM against a small
// fake DOM and a fake fetch: element registration, how it gets and refreshes
// its token, what it sends, and that it renders what it is told as text.
// No browser and no jsdom (not a dependency): this proves the rendering
// logic, not layout or a real browser's custom-element lifecycle.

const SCRIPT = readFileSync(new URL('../server/assets/widgets.js', import.meta.url), 'utf8');

class FakeNode {
  constructor(tag) { this.tagName = tag; this.childNodes = []; this.attrs = {}; this.listeners = {}; this.parentNode = null; }
  appendChild(n) { n.parentNode = this; this.childNodes.push(n); return n; }
  replaceChildren(...nodes) { this.childNodes = []; nodes.forEach((n) => this.appendChild(n)); }
  get textContent() { return this._text ?? this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { this.childNodes = []; this._text = String(v); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  hasAttribute(k) { return k in this.attrs; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(t, fn) { (this.listeners[t] ||= []).push(fn); }
  dispatchEvent(ev) { (this.listeners[ev.type] || []).forEach((fn) => fn(ev)); return true; }
}
class FakeText extends FakeNode { constructor(t) { super('#text'); this._text = String(t); } }

function all(node, pred, out = []) {
  if (pred(node)) out.push(node);
  node.childNodes.forEach((c) => all(c, pred, out));
  return out;
}
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };

function boot(routes) {
  const calls = [];
  const registry = new Map();
  const events = [];
  class HTMLElement extends FakeNode {
    constructor() { super('custom'); }
    attachShadow() { this.shadowRoot = new FakeNode('#shadow'); return this.shadowRoot; }
    dispatchEvent(ev) { events.push(ev); return true; }
  }
  const fetch = async (url, init = {}) => {
    calls.push({ url, ...init, body: init.body === undefined ? undefined : JSON.parse(init.body) });
    const key = `${init.method || 'GET'} ${url}`;
    const handler = routes[key];
    if (!handler) return { ok: false, status: 404, text: async () => '{}' };
    const [status, body] = handler(calls[calls.length - 1], calls);
    return { ok: status < 400, status, text: async () => JSON.stringify(body) };
  };
  const ctx = {
    fetch,
    HTMLElement,
    CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
    customElements: { define: (n, c) => registry.set(n, c), get: (n) => registry.get(n) },
    document: { createElement: (t) => new FakeNode(t), createTextNode: (t) => new FakeText(t), querySelectorAll: () => [] },
    setTimeout, Date, Promise, JSON,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(SCRIPT, ctx);
  const mount = async (name, attrs = {}) => {
    const el = new (registry.get(name))();
    Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
    el.connectedCallback();
    await flush();
    return el;
  };
  return { calls, registry, events, mount };
}

const hour = () => new Date(Date.now() + 3600_000).toISOString();
const token = (n = 1) => () => [200, { token: `cwt_t${n}`, scopes: ['me', 'sessions', 'members', 'access', 'app-keys'], expires_at: hour() }];
const ME = {
  user: { id: 2, name: '<img src=x onerror=alert(1)> Ada Lovelace', email: 'ada@t.test', avatar_url: null },
  app: { slug: 'hub', name: 'Hub', env: 'production' },
  app_role: 'user', can_manage_members: false, access_requested: false, scopes: ['me', 'sessions', 'members', 'access', 'app-keys'],
  links: { sign_out: '/__appcrane/logout', account: 'https://crane.example.test/settings#account' },
};

test('registers all five elements and fetches the token same-origin with the widget header', async () => {
  const { registry, calls, mount } = boot({ 'POST /__appcrane/widgets/token': token(), 'GET /__appcrane/widgets/api/me': () => [200, ME] });
  assert.deepEqual([...registry.keys()].sort(),
    ['appcrane-app-keys', 'appcrane-app-members', 'appcrane-request-access', 'appcrane-sessions', 'appcrane-user-menu']);
  const el = await mount('appcrane-user-menu');
  const tok = calls.find((c) => c.url === '/__appcrane/widgets/token');
  assert.equal(tok.method, 'POST');
  assert.equal(tok.credentials, 'same-origin');
  assert.equal(tok.headers['X-AppCrane-Widget'], '1');
  const me = calls.find((c) => c.url === '/__appcrane/widgets/api/me');
  assert.equal(me.headers.Authorization, 'Bearer cwt_t1');
  assert.equal(me.credentials, 'omit', 'the widget API never rides on the cookie');

  const text = el.shadowRoot.textContent;
  assert.ok(text.includes('<img src=x onerror=alert(1)> Ada Lovelace'), 'the name is text');
  assert.equal(all(el.shadowRoot, (n) => n.tagName === 'img').length, 0, 'no element made from the name');
  assert.equal(all(el.shadowRoot, (n) => n.tagName === 'a' && n.attrs.href === '/__appcrane/logout').length, 1);
  const panel = all(el.shadowRoot, (n) => n.attrs.part === 'panel')[0];
  assert.ok(panel.hasAttribute('hidden'));
  all(el.shadowRoot, (n) => n.attrs.part === 'button')[0].dispatchEvent({ type: 'click' });
  assert.equal(panel.hasAttribute('hidden'), false, 'the button opens the menu');
});

test('one token for every widget; an expired or refused one is fetched again and the call retried', async () => {
  let n = 0;
  let meCalls = 0;
  const { calls, mount } = boot({
    'POST /__appcrane/widgets/token': () => [200, { token: `cwt_t${++n}`, expires_at: n === 1 ? new Date(Date.now() + 10_000).toISOString() : hour() }],
    'GET /__appcrane/widgets/api/me': (c) => (++meCalls === 1 && c.headers.Authorization === 'Bearer cwt_t2'
      ? [401, { error: { code: 'WIDGET_TOKEN_INVALID' } }] : [200, ME]),
    'GET /__appcrane/widgets/api/sessions': () => [200, { sessions: [] }],
  });
  await mount('appcrane-sessions');
  // The first token is inside the refresh margin, so the next call gets a new one.
  await mount('appcrane-user-menu');
  const tokens = calls.filter((c) => c.url.endsWith('/token')).length;
  assert.equal(tokens, 3, 'near expiry -> new token; 401 -> new token again');
  const mes = calls.filter((c) => c.url.endsWith('/api/me')).map((c) => c.headers.Authorization);
  assert.deepEqual(mes, ['Bearer cwt_t2', 'Bearer cwt_t3']);
});

test('signed out: the widget says so and offers sign-in', async () => {
  const { mount, events } = boot({ 'POST /__appcrane/widgets/token': () => [401, { error: { code: 'SIGNED_OUT', message: 'Not signed in' } }] });
  const el = await mount('appcrane-user-menu');
  assert.match(el.shadowRoot.textContent, /You are signed out\. Sign in/);
  assert.ok(events.some((e) => e.type === 'appcrane-signed-out'));
});

test('members: a member is told only owners manage; an owner gets role pickers that PUT', async () => {
  const member = boot({ 'POST /__appcrane/widgets/token': token(), 'GET /__appcrane/widgets/api/me': () => [200, ME] });
  const a = await member.mount('appcrane-app-members');
  assert.match(a.shadowRoot.textContent, /Only an owner of Hub/);
  assert.equal(member.calls.some((c) => c.url.endsWith('/api/members')), false);

  const owner = boot({
    'POST /__appcrane/widgets/token': token(),
    'GET /__appcrane/widgets/api/me': () => [200, { ...ME, can_manage_members: true }],
    'GET /__appcrane/widgets/api/members': () => [200, { roles: ['owner', 'admin', 'user', 'none'], members: [
      { id: 1, name: 'Olivia', email: 'o@t.test', app_role: 'owner', you: true },
      { id: 2, name: 'Ada', email: 'ada@t.test', app_role: 'user', you: false }] }],
    'PUT /__appcrane/widgets/api/members/2': () => [200, {}],
  });
  const b = await owner.mount('appcrane-app-members');
  const selects = all(b.shadowRoot, (n) => n.tagName === 'select' && n.attrs['aria-label']?.startsWith('Role of'));
  assert.deepEqual(selects.map((s) => s.value), ['owner', 'user']);
  selects[1].value = 'admin';
  selects[1].dispatchEvent({ type: 'change' });
  await flush();
  const put = owner.calls.find((c) => c.method === 'PUT');
  assert.equal(put.url, '/__appcrane/widgets/api/members/2');
  assert.deepEqual(put.body, { app_role: 'admin' });
});

test('members: turned off for the app, the widget says so and asks for nothing', async () => {
  const off = boot({ 'POST /__appcrane/widgets/token': token(), 'GET /__appcrane/widgets/api/me': () => [200, { ...ME, can_manage_members: true, scopes: ['me', 'sessions', 'access'] }] });
  const el = await off.mount('appcrane-app-members');
  assert.match(el.shadowRoot.textContent, /Member management is not turned on for Hub/);
  assert.equal(off.calls.some((c) => c.url.endsWith('/api/members')), false);
});

test('request access, signed out (a non-member cannot sign in here): links to the platform request page from the manifest', async () => {
  const { mount, calls } = boot({
    'POST /__appcrane/widgets/token': () => [401, { error: { code: 'SIGNED_OUT' } }],
    'GET /__appcrane/widgets/manifest.json': () => [200, { request_access: 'https://crane.example.test/login?denied=1&app=hub' }],
  });
  const el = await mount('appcrane-request-access');
  const links = all(el.shadowRoot, (n) => n.tagName === 'a');
  assert.deepEqual(links.map((a) => a.attrs.href), ['https://crane.example.test/login?denied=1&app=hub']);
  assert.match(el.shadowRoot.textContent, /Request access on AppCrane/);
  assert.equal(calls.find((c) => c.url.endsWith('/manifest.json')).credentials, 'omit');

  const bad = boot({
    'POST /__appcrane/widgets/token': () => [401, { error: { code: 'SIGNED_OUT' } }],
    'GET /__appcrane/widgets/manifest.json': () => [200, { request_access: 'javascript:alert(1)' }],
  });
  const el2 = await bad.mount('appcrane-request-access');
  assert.equal(all(el2.shadowRoot, (n) => n.tagName === 'a' && n.attrs.href.startsWith('javascript')).length, 0);
  assert.match(el2.shadowRoot.textContent, /You are signed out/);
});

test('request access: sends the note, then shows the request as sent', async () => {
  let requested = false;
  const { mount, calls } = boot({
    'POST /__appcrane/widgets/token': token(),
    'GET /__appcrane/widgets/api/me': () => [200, { ...ME, app_role: 'none', access_requested: requested }],
    'POST /__appcrane/widgets/api/access-request': () => { requested = true; return [201, { request_id: 7 }]; },
  });
  const el = await mount('appcrane-request-access');
  const note = all(el.shadowRoot, (n) => n.tagName === 'textarea')[0];
  note.value = 'need it';
  all(el.shadowRoot, (n) => n.tagName === 'form')[0].dispatchEvent({ type: 'submit', preventDefault() {} });
  await flush();
  assert.deepEqual(calls.find((c) => c.url.endsWith('/access-request')).body, { note: 'need it' });
  assert.match(el.shadowRoot.textContent, /Your access request was sent/);
});
