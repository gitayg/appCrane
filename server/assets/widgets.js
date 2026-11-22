/* AppCrane widgets: drop-in custom elements for an app on its own AppCrane host.
 *   <script src="/__appcrane/widgets.js" defer></script>
 *   <appcrane-user-menu></appcrane-user-menu> <appcrane-sessions></appcrane-sessions>
 *   <appcrane-app-members></appcrane-app-members> <appcrane-request-access></appcrane-request-access>
 *   <appcrane-app-keys></appcrane-app-keys>
 * No framework. Every widget renders in its own shadow root with DOM calls and
 * textContent only, and talks to /__appcrane/widgets/api/* on this host with a
 * short-lived widget token that is good for this app only. */
(function () {
  'use strict';
  if (window.AppCraneWidgets) return;
  var BASE = '/__appcrane/widgets';
  var REFRESH_MARGIN_MS = 60000;
  var tokenState = null;
  var tokenPending = null;
  var mePending = null;

  function fail(status, body) {
    var err = new Error((body && body.error && body.error.message) || ('Request failed (' + status + ')'));
    err.status = status;
    err.code = (body && body.error && body.error.code) || null;
    err.stepUpUrl = (body && body.error && body.error.step_up && body.error.step_up.url) || null;
    return err;
  }

  function readJson(res) {
    return res.text().then(function (t) { try { return t ? JSON.parse(t) : null; } catch (_) { return null; } });
  }

  function parseTime(s) {
    if (!s) return null;
    var iso = String(s).replace(' ', 'T');
    var d = new Date(/Z$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');
    return isNaN(d.getTime()) ? null : d;
  }

  function fmt(s) {
    var d = parseTime(s);
    return d ? d.toLocaleString() : '';
  }

  function getToken(force) {
    if (!force && tokenState && tokenState.exp - REFRESH_MARGIN_MS > Date.now()) return Promise.resolve(tokenState.token);
    if (tokenPending) return tokenPending;
    tokenPending = fetch(BASE + '/token', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-AppCrane-Widget': '1' },
      body: '{}',
    }).then(function (res) {
      return readJson(res).then(function (body) {
        if (!res.ok) throw fail(res.status, body);
        var exp = parseTime(body.expires_at);
        tokenState = { token: body.token, exp: exp ? exp.getTime() : Date.now() + 300000 };
        return tokenState.token;
      });
    }).then(function (t) { tokenPending = null; return t; }, function (e) { tokenPending = null; tokenState = null; throw e; });
    return tokenPending;
  }

  function api(method, path, body, retried) {
    return getToken(!!retried).then(function (token) {
      var headers = { Authorization: 'Bearer ' + token };
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      return fetch(BASE + '/api' + path, {
        method: method,
        credentials: 'omit',
        headers: headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    }).then(function (res) {
      return readJson(res).then(function (data) {
        if (res.status === 401 && !retried) return api(method, path, body, true);
        if (!res.ok) throw fail(res.status, data);
        return data;
      });
    });
  }

  function me(fresh) {
    if (fresh || !mePending) {
      mePending = api('GET', '/me').catch(function (e) { mePending = null; throw e; });
    }
    return mePending;
  }

  function h(tag, props) {
    var el = document.createElement(tag);
    var p = props || {};
    Object.keys(p).forEach(function (k) {
      var v = p[k];
      if (v == null || v === false) return;
      if (k === 'text') el.textContent = String(v);
      else if (k === 'value') el.value = v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      (Array.isArray(c) ? c : [c]).forEach(function (n) {
        if (n != null && n !== false) el.appendChild(typeof n === 'string' ? document.createTextNode(n) : n);
      });
    }
    return el;
  }

  var CSS = ':host{display:block;font:14px/1.4 system-ui,sans-serif;color:inherit}' +
    ':host([hidden]){display:none}.muted{opacity:.7}.err{color:#b91c1c}' +
    'button,select,input,textarea{font:inherit}button{cursor:pointer}' +
    'table{border-collapse:collapse;width:100%}td,th{padding:4px 6px;text-align:left;border-bottom:1px solid rgba(127,127,127,.25)}' +
    '.row{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:6px 0}.badge{font-size:12px;padding:0 6px;border-radius:8px;background:rgba(127,127,127,.2)}' +
    '.menu{position:relative;display:inline-block}.panel{position:absolute;right:0;z-index:1000;min-width:220px;padding:8px;background:Canvas;color:CanvasText;border:1px solid rgba(127,127,127,.4);border-radius:6px}' +
    '.panel a{display:block;padding:4px 0}.avatar{width:24px;height:24px;border-radius:50%;object-fit:cover;display:inline-flex;align-items:center;justify-content:center;background:rgba(127,127,127,.3);font-size:12px}' +
    'code{word-break:break-all}';
  var sheet = null;

  function styleRoot(root) {
    try {
      if (!sheet && typeof CSSStyleSheet === 'function') { sheet = new CSSStyleSheet(); sheet.replaceSync(CSS); }
      if (sheet && 'adoptedStyleSheets' in root) root.adoptedStyleSheets = [sheet];
    } catch (_) { /* unstyled is still usable */ }
  }

  class Base extends HTMLElement {
    connectedCallback() {
      if (!this._root) { this._root = this.attachShadow({ mode: 'open' }); styleRoot(this._root); }
      this.refresh();
    }
    show() {
      this._root.replaceChildren.apply(this._root, Array.prototype.slice.call(arguments));
    }
    emit(type, detail) {
      this.dispatchEvent(new CustomEvent(type, { detail: detail, bubbles: true, composed: true }));
    }
    problem(e) {
      if (e && (e.code === 'SIGNED_OUT' || e.status === 401)) {
        this.show(h('div', { class: 'muted', part: 'signed-out' }, 'You are signed out. ', h('a', { href: '/', text: 'Sign in' })));
        this.emit('appcrane-signed-out', {});
        return;
      }
      this.show(h('div', { class: 'err', part: 'error', text: (e && e.message) || 'Something went wrong' }));
      this.emit('appcrane-error', { code: e && e.code, message: e && e.message });
    }
    refresh() {
      var self = this;
      this.show(h('div', { class: 'muted', text: 'Loading\u2026' }));
      return Promise.resolve().then(function () { return self.load(); }).catch(function (e) { self.problem(e); });
    }
  }

  function define(name, load) {
    var El = class extends Base {};
    El.prototype.load = load;
    if (!customElements.get(name)) customElements.define(name, El);
    return El;
  }

  function initials(name) {
    return String(name || '?').split(/\s+/).filter(Boolean).slice(0, 2).map(function (w) { return w[0].toUpperCase(); }).join('');
  }

  define('appcrane-user-menu', function () {
    var self = this;
    return me().then(function (m) {
      var avatar = m.user.avatar_url && /^(https:|data:image\/)/.test(m.user.avatar_url)
        ? h('img', { class: 'avatar', src: m.user.avatar_url, alt: '' })
        : h('span', { class: 'avatar', 'aria-hidden': 'true', text: initials(m.user.name) });
      var sessionsHref = self.getAttribute('sessions-href') || m.links.account;
      var profileHref = self.getAttribute('profile-href') || m.links.account;
      var panel = h('div', { class: 'panel', part: 'panel', hidden: true },
        h('div', { text: m.user.name || m.user.email }),
        m.user.email ? h('div', { class: 'muted', text: m.user.email }) : null,
        h('div', { class: 'muted', text: m.app.name + ': ' + m.app_role }),
        profileHref ? h('a', { href: profileHref, text: 'Profile' }) : null,
        sessionsHref ? h('a', { href: sessionsHref, text: 'Your sessions' }) : null,
        h('a', { href: m.links.sign_out, part: 'sign-out', text: 'Sign out' }));
      var button = h('button', {
        type: 'button', part: 'button', 'aria-haspopup': 'true', 'aria-expanded': 'false',
        onclick: function () {
          var open = panel.hasAttribute('hidden');
          if (open) panel.removeAttribute('hidden'); else panel.setAttribute('hidden', '');
          button.setAttribute('aria-expanded', open ? 'true' : 'false');
        },
      }, avatar, ' ', h('span', { text: m.user.name || m.user.email }));
      self.show(h('div', { class: 'menu' }, button, panel));
    });
  });

  define('appcrane-sessions', function () {
    var self = this;
    return api('GET', '/sessions').then(function (r) {
      var rows = r.sessions.map(function (s) {
        var where = s.scope === 'app' && s.app
          ? s.app.name + (s.app.env === 'sandbox' ? ' (sandbox)' : '')
          : 'AppCrane';
        var action;
        if (s.revocable_here) {
          action = h('button', {
            type: 'button', part: 'revoke', text: s.current ? 'Sign out' : 'Revoke',
            onclick: function () {
              api('DELETE', '/sessions/' + encodeURIComponent(s.id)).then(function (res) {
                self.emit('appcrane-change', { widget: 'sessions', revoked: s.id });
                if (res.signed_out) { tokenState = null; mePending = null; self.problem({ code: 'SIGNED_OUT' }); return; }
                self.refresh();
              }).catch(function (e) { self.problem(e); });
            },
          });
        } else {
          action = h('span', { class: 'muted', text: 'Manage on AppCrane' });
        }
        return h('tr', { part: 'session' },
          h('td', null, where, s.current ? h('span', { class: 'badge', text: 'this browser' }) : null),
          h('td', { class: 'muted', text: 'signed in ' + fmt(s.created_at) }),
          h('td', { class: 'muted', text: s.last_seen_at ? 'last seen ' + fmt(s.last_seen_at) : '' }),
          h('td', null, action));
      });
      var others = r.other_sessions ? h('div', { class: 'muted', part: 'other-sessions', text: r.other_sessions + ' other session' + (r.other_sessions === 1 ? '' : 's') + ' (AppCrane and other apps): manage on AppCrane' }) : null;
      var list = rows.length ? h('table', null, h('tbody', null, rows)) : h('div', { class: 'muted', text: 'No active sessions here.' });
      if (others) self.show(list, others); else self.show(list);
    });
  });

  define('appcrane-app-members', function () {
    var self = this;
    return me().then(function (m) {
      if (m.scopes.indexOf('members') === -1) {
        self.show(h('div', { class: 'muted', part: 'off', text: 'Member management is not turned on for ' + m.app.name + '.' }));
        return null;
      }
      if (!m.can_manage_members) {
        self.show(h('div', { class: 'muted', part: 'not-allowed', text: 'Only an owner of ' + m.app.name + ' can see and manage its members.' }));
        return null;
      }
      return api('GET', '/members').then(function (r) {
        var note = h('div', { class: 'err', part: 'message' });
        var rows = r.members.map(function (u) {
          var select = h('select', {
            'aria-label': 'Role of ' + (u.name || u.email),
            onchange: function () {
              var role = select.value;
              api('PUT', '/members/' + u.id, { app_role: role }).then(function () {
                self.emit('appcrane-change', { widget: 'members', user_id: u.id, app_role: role });
                self.refresh();
              }).catch(function (e) { note.textContent = e.message; select.value = u.app_role; });
            },
          }, r.roles.map(function (role) {
            return h('option', { value: role, text: role === 'none' ? 'remove' : role });
          }));
          select.value = u.app_role;
          return h('tr', { part: 'member' },
            h('td', null, u.name || '', u.you ? h('span', { class: 'badge', text: 'you' }) : null),
            h('td', { class: 'muted', text: u.email || '' }),
            h('td', null, select));
        });
        var email = h('input', { type: 'email', placeholder: 'email of an AppCrane user', 'aria-label': 'Email to invite' });
        var role = h('select', { 'aria-label': 'Role to give' },
          ['user', 'admin', 'owner'].map(function (x) { return h('option', { value: x, text: x }); }));
        var invite = h('form', {
          class: 'row', part: 'invite',
          onsubmit: function (ev) {
            ev.preventDefault();
            api('POST', '/members', { email: email.value, app_role: role.value }).then(function () {
              self.emit('appcrane-change', { widget: 'members', invited: email.value });
              self.refresh();
            }).catch(function (e) { note.textContent = e.message; });
          },
        }, email, role, h('button', { type: 'submit', text: 'Add' }));
        self.show(h('table', null, h('tbody', null, rows)), invite, note);
      });
    });
  });

  // Someone with no role on a private app is never signed in on its host, so
  // signed out here offers the platform's own access-request page for this app.
  function requestElsewhere(self) {
    return fetch(BASE + '/manifest.json', { credentials: 'omit' }).then(function (res) {
      return readJson(res).then(function (mf) {
        if (!res.ok || !mf || !/^https:\/\//.test(mf.request_access || '')) throw { code: 'SIGNED_OUT' };
        self.show(h('div', { part: 'request-elsewhere' }, 'No access yet? ',
          h('a', { href: mf.request_access, text: 'Request access on AppCrane' }),
          ' (sign in there first if asked).'));
      });
    });
  }

  define('appcrane-request-access', function () {
    var self = this;
    return me().catch(function (e) {
      if (e && (e.code === 'SIGNED_OUT' || e.status === 401)) return requestElsewhere(self).then(function () { return null; });
      throw e;
    }).then(function (m) {
      if (!m) return;
      if (['owner', 'admin', 'user'].indexOf(m.app_role) !== -1) {
        self.show(h('div', { class: 'muted', part: 'has-access', text: 'You have access to ' + m.app.name + '.' }));
        return;
      }
      if (m.access_requested) {
        self.show(h('div', { part: 'requested', text: 'Your access request was sent. An owner of ' + m.app.name + ' will review it.' }));
        return;
      }
      var note = h('textarea', { rows: '3', maxlength: '1000', placeholder: 'Why do you need access? (optional)', 'aria-label': 'Note to the owners' });
      var msg = h('div', { class: 'err', part: 'message' });
      var form = h('form', {
        part: 'form',
        onsubmit: function (ev) {
          ev.preventDefault();
          api('POST', '/access-request', { note: note.value }).then(function (r) {
            self.emit('appcrane-change', { widget: 'request-access', request_id: r.request_id });
            me(true).then(function () { self.refresh(); });
          }).catch(function (e) {
            if (e.code === 'DUPLICATE_ACCESS_REQUEST') { me(true).then(function () { self.refresh(); }); return; }
            msg.textContent = e.message;
          });
        },
      }, h('div', { text: 'Ask the owners of ' + m.app.name + ' for access.' }), note,
        h('div', { class: 'row' }, h('button', { type: 'submit', text: 'Request access' })), msg);
      self.show(form);
    });
  });

  define('appcrane-app-keys', function () {
    var self = this;
    return api('GET', '/app-keys').then(function (r) {
      var msg = h('div', { class: 'err', part: 'message' });
      var rows = r.keys.map(function (k) {
        var live = !k.revoked_at && !(parseTime(k.expires_at) && parseTime(k.expires_at).getTime() < Date.now());
        return h('tr', { part: 'key' },
          h('td', { text: k.label || '(no label)' }),
          h('td', { class: 'muted', text: k.revoked_at ? 'revoked' : (live ? 'expires ' + fmt(k.expires_at) : 'expired') }),
          h('td', { class: 'muted', text: k.last_used_at ? 'used ' + fmt(k.last_used_at) : 'never used' }),
          h('td', null, live ? h('button', {
            type: 'button', text: 'Revoke',
            onclick: function () {
              api('DELETE', '/app-keys/' + k.id).then(function () { self.refresh(); }).catch(function (e) { msg.textContent = e.message; });
            },
          }) : null));
      });
      var label = h('input', { type: 'text', maxlength: '80', placeholder: 'label, e.g. laptop uploader', 'aria-label': 'Key label' });
      var days = h('input', { type: 'number', min: '1', max: String(r.max_days), value: '30', 'aria-label': 'Days until it expires' });
      var form = h('form', {
        class: 'row', part: 'create',
        onsubmit: function (ev) {
          ev.preventDefault();
          api('POST', '/app-keys', { label: label.value || null, expires_in_days: parseInt(days.value, 10) }).then(function (res) {
            self.refresh().then(function () {
              self._root.appendChild(h('div', { part: 'new-key' },
                h('div', { text: 'Copy this key now. It is not shown again and signs in to this app only.' }),
                h('code', { text: res.api_key })));
            });
          }).catch(function (e) {
            msg.textContent = e.message;
            if (e.code === 'STEP_UP_REQUIRED' && e.stepUpUrl) {
              msg.appendChild(document.createTextNode(' '));
              msg.appendChild(h('a', { href: e.stepUpUrl + '&return=' + encodeURIComponent(location.href), part: 'step-up', text: 'Confirm it is you' }));
            }
          });
        },
      }, label, days, h('button', { type: 'submit', text: 'Create key' }));
      self.show(rows.length ? h('table', null, h('tbody', null, rows)) : h('div', { class: 'muted', text: 'No app keys yet.' }), form, msg);
    });
  });

  window.AppCraneWidgets = {
    refresh: function () {
      tokenState = null; mePending = null;
      ['appcrane-user-menu', 'appcrane-sessions', 'appcrane-app-members', 'appcrane-request-access', 'appcrane-app-keys'].forEach(function (n) {
        Array.prototype.forEach.call(document.querySelectorAll(n), function (el) { if (el.refresh) el.refresh(); });
      });
    },
  };
})();
