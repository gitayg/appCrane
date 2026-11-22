(function () {
  'use strict';
  var API = '/api/it-setup';
  var csrf = null;
  var app = document.getElementById('app');

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') n.textContent = attrs[k];
      else if (k === 'onclick') n.addEventListener('click', attrs[k]);
      else if (k === 'checked') n.checked = !!attrs[k];
      else if (k === 'value') n.value = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }

  function call(method, path, body) {
    var headers = { 'Content-Type': 'application/json' };
    if (csrf) headers['X-IT-Setup-CSRF'] = csrf;
    return fetch(API + path, { method: method, headers: headers, credentials: 'same-origin', body: body ? JSON.stringify(body) : undefined })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, body: j }; }); });
  }

  function message(text, cls) {
    app.replaceChildren(el('h1', { text: 'AppCrane IT setup' }), el('p', { text: text, class: cls || '' }));
  }

  function field(label, input) { return el('label', {}, [label, input]); }
  function input(name, value, type) { return el('input', { type: type || 'text', name: name, value: value || '', autocomplete: 'off' }); }
  function checkbox(name, checked, label) { return el('label', { class: 'check' }, [el('input', { type: 'checkbox', name: name, checked: checked }), label]); }

  function readForm(form) {
    var out = {};
    Array.prototype.forEach.call(form.querySelectorAll('input, textarea, select'), function (i) {
      if (i.type === 'checkbox') out[i.name] = i.checked;
      else if (i.value !== '') out[i.name] = i.value;
    });
    return out;
  }

  function showError(where, r) {
    where.textContent = (r.body && r.body.error && (r.body.error.message || r.body.error_description || r.body.error)) || ('Request failed (' + r.status + ')');
    where.className = 'bad';
  }

  function changeBlock(c) {
    var out = el('p', { class: 'muted' });
    var box = el('div', { class: 'change' }, [
      el('div', { text: 'Pending change ' + c.id + ' (' + c.scope.toUpperCase() + '): not in effect until you confirm it.' }),
    ]);
    if (c.needs_test) {
      box.appendChild(el('button', { class: 'ghost', text: 'Test connection', onclick: function () {
        out.textContent = 'Testing...'; out.className = 'muted';
        call('POST', '/changes/' + c.id + '/test').then(function (r) {
          if (r.status !== 200) return showError(out, r);
          out.replaceChildren.apply(out, (r.body.steps || []).map(function (s) { return el('div', { class: s.ok ? 'ok' : 'bad', text: (s.ok ? 'PASS ' : 'FAIL ') + s.step + ': ' + s.detail }); }));
          out.className = '';
          if (r.body.ok) render();
        });
      } }));
    }
    box.appendChild(el('button', { text: 'Confirm', onclick: function () {
      call('POST', '/changes/' + c.id + '/confirm').then(function (r) {
        if (r.status !== 200) return showError(out, r);
        if (r.body.scim_token) {
          window.alert('New SCIM token (copy it now, it is not shown again):\n\n' + r.body.scim_token);
        }
        render();
      });
    } }));
    box.appendChild(el('button', { class: 'ghost', text: 'Discard', onclick: function () { call('POST', '/changes/' + c.id + '/discard').then(render); } }));
    if (c.needs_test && !c.test_ok) box.appendChild(el('p', { class: 'muted', text: 'Run the connection test and get a pass before confirming.' }));
    box.appendChild(out);
    return box;
  }

  function sectionForm(scope, title, fields, current, changes, extra) {
    var out = el('p', { class: 'muted' });
    var form = el('div', {}, fields);
    var sec = el('section', {}, [el('h2', { text: title })]);
    (extra || []).forEach(function (n) { sec.appendChild(n); });
    sec.appendChild(form);
    sec.appendChild(el('button', { text: 'Save as pending change', onclick: function () {
      call('POST', '/' + scope, readForm(form)).then(function (r) { if (r.status !== 201) return showError(out, r); render(); });
    } }));
    sec.appendChild(out);
    changes.filter(function (c) { return c.scope === scope && c.status === 'staged'; }).forEach(function (c) { sec.appendChild(changeBlock(c)); });
    return sec;
  }

  function info(rows) {
    return el('table', {}, rows.map(function (r) { return el('tr', {}, [el('th', { text: r[0] }), el('td', { class: 'mono', text: r[1] == null ? '' : String(r[1]) })]); }));
  }

  function oidcSection(cur, changes) {
    return sectionForm('oidc', 'OpenID Connect (OIDC)', [
      checkbox('enabled', cur.enabled, 'Turn OIDC sign-in on'),
      field('Discovery URL (https)', input('discovery_url', cur.discovery_url, 'url')),
      field('Client ID', input('client_id', cur.client_id)),
      field('Client secret (' + (cur.client_secret_set ? 'set; leave empty to keep it' : 'not set') + ')', input('client_secret', '', 'password')),
      field('Button label', input('provider_name', cur.provider_name)),
    ], cur, changes, [info([['Redirect URI', cur.redirect_uri]])]);
  }

  function samlSection(cur, changes) {
    var ta = el('textarea', { name: 'idp_cert', placeholder: 'Paste a new signing certificate, or leave empty to keep the current one' });
    return sectionForm('saml', 'SAML', [
      checkbox('enabled', cur.enabled, 'Turn SAML sign-in on'),
      field('IdP sign-in URL (https)', input('idp_sso_url', cur.idp_sso_url, 'url')),
      field('IdP signing certificate', ta),
      field('Button label', input('provider_name', cur.provider_name)),
    ], cur, changes, [info([
      ['ACS URL', cur.acs_url], ['Entity ID', cur.entity_id],
      ['Current certificate', cur.idp_cert ? (cur.idp_cert.fingerprint256 || 'unreadable') + (cur.idp_cert.valid_to ? ', valid to ' + cur.idp_cert.valid_to : '') : 'none'],
    ])]);
  }

  function scimSection(cur, changes) {
    var logBox = el('div');
    var sec = sectionForm('scim', 'SCIM provisioning', [
      checkbox('enabled', cur.enabled, 'Turn SCIM provisioning on'),
      checkbox('rotate_token', !cur.token_set, 'Issue a new SCIM token (the old one stops working when you confirm)'),
    ], cur, changes, [info([['SCIM base URL', cur.base_url], ['Token', cur.token_set ? 'set, created ' + (cur.token_created_at || 'unknown') : 'not set']])]);
    sec.appendChild(el('button', { class: 'ghost', text: 'Show recent SCIM requests', onclick: function () {
      call('GET', '/scim/requests').then(function (r) {
        if (r.status !== 200) return showError(logBox, r);
        logBox.replaceChildren(el('table', {}, [el('tr', {}, ['Time', 'Method', 'Path', 'Status', 'From'].map(function (h) { return el('th', { text: h }); }))]
          .concat(r.body.requests.map(function (q) { return el('tr', {}, [q.at, q.method, q.path, String(q.status), q.ip || ''].map(function (v) { return el('td', { class: 'mono', text: v }); })); }))));
      });
    } }));
    sec.appendChild(logBox);
    return sec;
  }

  function siemSection(cur, changes) {
    var sel = el('select', { name: 'preset' }, ['generic', 'splunk', 'datadog'].map(function (p) { return el('option', { value: p, text: p }); }));
    var urlIn = input('url', '', 'url');
    var tokenIn = input('token', '', 'password');
    var out = el('p', { class: 'muted' });
    var sec = el('section', {}, [el('h2', { text: 'SIEM destination (HTTPS)' }),
      el('p', { class: 'muted', text: 'Audit and security events from now on are sent here. Existing destinations are not shown.' }),
      field('Name', input('name', '')), field('Preset', sel), field('Endpoint URL (https)', urlIn), field('Token or API key', tokenIn), el('p', { class: 'muted', text: 'Other SIEM types (Sentinel, Sumo Logic, Elastic, S3) are set up by an AppCrane administrator.' })]);
    sec.appendChild(el('button', { text: 'Save as pending change', onclick: function () {
      var body = { name: sec.querySelector('input[name=name]').value, type: 'https', preset: sel.value, config: { url: urlIn.value }, secrets: {} };
      if (tokenIn.value) body.secrets[{ generic: 'auth_value', splunk: 'token', datadog: 'api_key' }[sel.value]] = tokenIn.value;
      call('POST', '/siem', body).then(function (r) { if (r.status !== 201) return showError(out, r); render(); });
    } }));
    sec.appendChild(out);
    (cur.sinks || []).forEach(function (s) { sec.appendChild(el('p', { class: 'ok', text: 'Added: ' + s.name + ' (' + s.preset + ')' })); });
    changes.filter(function (c) { return c.scope === 'siem' && c.status === 'staged'; }).forEach(function (c) { sec.appendChild(changeBlock(c)); });
    return sec;
  }

  function domainsSection(domains) {
    var out = el('p', { class: 'muted' });
    var add = input('domain', '');
    var sec = el('section', {}, [el('h2', { text: 'Domains' }),
      el('p', { class: 'muted', text: 'Prove your organization controls a domain by adding a DNS TXT record on it, then press Verify.' })]);
    domains.forEach(function (d) {
      var res = el('span', { class: 'muted' });
      sec.appendChild(el('div', { class: 'change' }, [
        el('div', {}, [el('strong', { text: d.domain }), ' ', el('span', { class: d.status === 'verified' ? 'ok' : 'bad', text: d.status })]),
        d.status !== 'verified' ? el('div', { class: 'mono', text: 'TXT ' + d.txt_name + '  "' + d.txt_value + '"' }) : null,
        d.last_result ? el('div', { class: 'muted', text: 'Last check: ' + d.last_result }) : null,
        el('button', { class: 'ghost', text: 'Verify now', onclick: function () {
          res.textContent = 'Checking DNS...';
          call('POST', '/domains/' + d.id + '/verify').then(function (r) { if (r.status !== 200) return showError(res, r); render(); });
        } }), res,
      ]));
    });
    sec.appendChild(field('Add a domain', add));
    sec.appendChild(el('button', { text: 'Add', onclick: function () {
      call('POST', '/domains', { domain: add.value }).then(function (r) { if (r.status >= 300) return showError(out, r); render(); });
    } }));
    sec.appendChild(out);
    return sec;
  }

  function render() {
    return call('GET', '/state').then(function (r) {
      if (r.status !== 200) return message((r.body.error && r.body.error.message) || 'This setup session has ended. Open the setup link again.', 'bad');
      var s = r.body;
      csrf = s.csrf;
      var nodes = [el('h1', { text: 'AppCrane IT setup' }),
        el('p', { class: 'muted', text: s.label + '. This link expires ' + s.expires_at + '. Changes take effect only when you confirm them.' }),
        el('div', { class: 'warn', text: 'This page cannot turn off password sign-in or the AppCrane administrators\' emergency access.' })];
      if (s.sections.oidc) nodes.push(oidcSection(s.sections.oidc, s.changes));
      if (s.sections.saml) nodes.push(samlSection(s.sections.saml, s.changes));
      if (s.sections.scim) nodes.push(scimSection(s.sections.scim, s.changes));
      if (s.domains) nodes.push(domainsSection(s.domains));
      if (s.sections.siem) nodes.push(siemSection(s.sections.siem, s.changes));
      var applied = s.changes.filter(function (c) { return c.status === 'applied'; });
      nodes.push(el('section', {}, [el('h2', { text: 'Finish' }),
        el('p', { class: 'muted', text: applied.length + ' change(s) applied. Finishing tells the AppCrane administrators and closes this link; pending changes are discarded.' }),
        el('button', { text: 'Finish setup', onclick: function () {
          if (!window.confirm('Finish setup? This link stops working.')) return;
          call('POST', '/complete').then(function (x) { if (x.status !== 200) return message('Could not finish: ' + ((x.body.error && x.body.error.message) || x.status), 'bad'); message('Setup is complete. Your AppCrane administrators were notified. You can close this page.', 'ok'); });
        } })]));
      app.replaceChildren.apply(app, nodes);
    });
  }

  var m = /[#&]t=([^&]+)/.exec(window.location.hash);
  if (m) {
    var token = decodeURIComponent(m[1]);
    window.history.replaceState(null, '', window.location.pathname);
    call('POST', '/session', { token: token }).then(function (r) {
      if (r.status !== 200) return message((r.body.error && r.body.error.message) || 'This setup link cannot be opened.', 'bad');
      csrf = r.body.csrf;
      render();
    });
  } else {
    render();
  }
})();
