// The Request / coder element-picker for an app on its own host (app isolation).
//
// The dashboard cannot see inside a frame on another host, so it loads this
// page, hidden, from the app's host (/__appcrane/picker). Being on the same
// host as the app, it can reach the app's frame through the dashboard's frame
// list, run the picker there, and post the picked element back. It answers only
// the platform host named in the page, and posts only to it.
(function () {
  var meta = document.querySelector('meta[name="appcrane-platform"]');
  var PLATFORM = meta && meta.content;
  if (!PLATFORM || window.parent === window) return;

  var stopPick = null;
  function send(msg) { window.parent.postMessage(msg, PLATFORM); }

  function appWindow(index) {
    try {
      var w = window.parent.frames[index];
      if (!w || w === window) return null;
      return w.document && w.document.body ? w : null;
    } catch (_) { return null; }
  }

  function selectorFor(el) {
    var root = el.ownerDocument.documentElement;
    var path = [];
    var cur = el;
    while (cur && cur.nodeType === 1 && cur !== root) {
      var sel = cur.nodeName.toLowerCase();
      if (cur.id) { path.unshift(sel + '#' + cur.id); break; }
      var nth = 1, sib = cur;
      while ((sib = sib.previousElementSibling)) if (sib.nodeName === cur.nodeName) nth++;
      if (nth > 1) sel += ':nth-of-type(' + nth + ')';
      path.unshift(sel);
      cur = cur.parentElement;
    }
    return path.join(' > ') || 'html';
  }

  function attach(win) {
    var doc = win.document;
    var hover = null;
    // A constructed sheet, not a <style> element: an app whose CSP refuses
    // inline styles would refuse the element, and the picker would show nothing.
    var sheet = null;
    try {
      sheet = new win.CSSStyleSheet();
      sheet.replaceSync(
        '.__ac_peek_hover{outline:2px solid #3b82f6!important;outline-offset:1px!important;background:#3b82f61a!important}' +
        ' *{cursor:crosshair!important}');
      doc.adoptedStyleSheets = doc.adoptedStyleSheets.concat([sheet]);
    } catch (_) { sheet = null; }

    function onOver(e) {
      if (hover) hover.classList.remove('__ac_peek_hover');
      hover = e.target;
      if (hover && hover.classList) hover.classList.add('__ac_peek_hover');
    }
    function onOut(e) { if (e.target && e.target.classList) e.target.classList.remove('__ac_peek_hover'); }
    // Same as the dashboard picker: the pick's press/release must not reach
    // the app, or a menu that opens on it opens under the Request box.
    function onPress(e) {
      if (e.type.indexOf('touch') !== 0) e.preventDefault();
      e.stopImmediatePropagation();
    }
    function onClick(e) {
      e.preventDefault();
      e.stopImmediatePropagation();
      var el = e.target;
      var r = el.getBoundingClientRect();
      var ctx = {
        selector: selectorFor(el),
        tag: el.nodeName.toLowerCase(),
        id: el.id || '',
        text: (el.innerText || '').trim().slice(0, 200),
        path: win.location.pathname,
        clickX: e.clientX, clickY: e.clientY,
        rect: { left: r.left, top: r.top, width: r.width, height: r.height },
      };
      cleanup();
      send({ type: 'appcrane-picked', ctx: ctx });
    }
    function onKey(e) {
      if (e.key !== 'Escape') return;
      e.preventDefault();
      cleanup();
      send({ type: 'appcrane-pick-cancel' });
    }
    var PRESS = ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'touchstart', 'touchend'];
    PRESS.forEach(function (t) { win.addEventListener(t, onPress, true); });
    doc.addEventListener('mouseover', onOver, true);
    doc.addEventListener('mouseout', onOut, true);
    win.addEventListener('click', onClick, true);
    doc.addEventListener('keydown', onKey, true);

    function cleanup() {
      try {
        if (hover) hover.classList.remove('__ac_peek_hover');
        if (sheet) doc.adoptedStyleSheets = doc.adoptedStyleSheets.filter(function (s) { return s !== sheet; });
        PRESS.forEach(function (t) { win.removeEventListener(t, onPress, true); });
        doc.removeEventListener('mouseover', onOver, true);
        doc.removeEventListener('mouseout', onOut, true);
        win.removeEventListener('click', onClick, true);
        doc.removeEventListener('keydown', onKey, true);
      } catch (_) {}
      stopPick = null;
    }
    return cleanup;
  }

  window.addEventListener('message', function (e) {
    if (e.origin !== PLATFORM || e.source !== window.parent) return;
    var m = e.data || {};
    if (m.type === 'appcrane-pick-stop') { if (stopPick) stopPick(); return; }
    if (m.type !== 'appcrane-pick-start') return;
    if (stopPick) stopPick();
    var w = appWindow(m.frame);
    if (!w) { send({ type: 'appcrane-pick-unavailable' }); return; }
    stopPick = attach(w);
  });
  send({ type: 'appcrane-picker-ready' });
})();
