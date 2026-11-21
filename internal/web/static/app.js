// Progressive enhancement: live clocks (UTC vs browser), UTC input previews,
// select-all, confirm prompts, in-place switches and live list refresh.
(function () {
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmt(d, utc) {
    if (utc) return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  function offset(d) {
    var m = -d.getTimezoneOffset(), s = m >= 0 ? '+' : '-';
    m = Math.abs(m);
    return 'UTC' + s + pad(Math.floor(m / 60)) + ':' + pad(m % 60);
  }
  var tz = '';
  try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}

  // header clocks
  var cu = document.querySelector('[data-clock=utc]'), cl = document.querySelector('[data-clock=local]'), ct = document.querySelector('[data-clock=tz]');
  function tick() {
    var d = new Date();
    if (cu) cu.textContent = fmt(d, true);
    if (cl) cl.textContent = fmt(d, false);
    if (ct) ct.textContent = (tz ? tz + ' ' : '') + offset(d);
  }
  if (cu) { tick(); setInterval(tick, 1000); }

  // hover any UTC timestamp to see it in browser time
  document.querySelectorAll('[data-utc]').forEach(function (el) {
    var v = el.getAttribute('data-utc');
    if (!v) return;
    var d = new Date(v);
    if (!isNaN(d)) el.title = 'browser time: ' + fmt(d, false) + ' (' + offset(d) + ')';
  });

  // catch-window inputs are UTC: preview them in browser time
  var prev = document.querySelector('[data-utc-preview]');
  var inputs = document.querySelectorAll('input[data-utc-input]');
  function preview() {
    if (!prev) return;
    var parts = [];
    inputs.forEach(function (i) {
      var lbl = i.name === 'catch_start' ? 'start' : 'end';
      if (!i.value) { parts.push(lbl + ': none'); return; }
      var d = new Date(i.value + ':00Z');
      if (isNaN(d)) { parts.push(lbl + ': invalid'); return; }
      var rel = Math.round((d - new Date()) / 60000), r;
      if (Math.abs(rel) < 120) r = (rel >= 0 ? 'in ' + rel + ' min' : Math.abs(rel) + ' min ago');
      else if (Math.abs(rel) < 2880) r = (rel >= 0 ? 'in ' + Math.round(rel / 60) + ' h' : Math.round(-rel / 60) + ' h ago');
      else r = (rel >= 0 ? 'in ' + Math.round(rel / 1440) + ' d' : Math.round(-rel / 1440) + ' d ago');
      parts.push(lbl + ' = ' + fmt(d, false) + ' your time (' + r + ')');
    });
    prev.textContent = 'In your browser time zone ' + (tz || offset(new Date())) + ': ' + parts.join(' · ');
  }
  inputs.forEach(function (i) { i.addEventListener('input', preview); });
  preview();

  document.querySelectorAll('input[data-select-all]').forEach(function (cb) {
    cb.addEventListener('change', function () {
      document.querySelectorAll('input[name="id"]').forEach(function (x) { x.checked = cb.checked; });
    });
  });
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (!window.confirm(f.getAttribute('data-confirm'))) e.preventDefault();
    });
  });
  document.querySelectorAll('form[data-busy]').forEach(function (f) {
    f.addEventListener('submit', function () {
      var b = f.querySelector('button');
      if (b) { b.textContent = f.getAttribute('data-busy'); }
      f.classList.add('busy');
    });
  });

  // switches flip in place without a page reload
  document.querySelectorAll('form[data-toggle]').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      e.preventDefault();
      var btn = f.querySelector('button.switch'), on = f.querySelector('input[name=on]');
      fetch(f.action, { method: 'POST', body: new FormData(f), credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var nowOn = on.value === '1';
          btn.classList.toggle('is-on', nowOn);
          btn.setAttribute('aria-pressed', nowOn ? 'true' : 'false');
          on.value = nowOn ? '0' : '1';
        })
        .catch(function () { f.submit(); });
    });
  });

  // live refresh of the domain list
  var table = document.querySelector('[data-live-domains]');
  if (table) {
    setInterval(function () {
      if (document.hidden) return;
      fetch('/domains.json', { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (list) {
        (list || []).forEach(function (x) {
          var row = table.querySelector('tr[data-id="' + x.id + '"]');
          if (!row) return;
          var set = function (f, v) { var el = row.querySelector('[data-f=' + f + ']'); if (el && el.textContent !== v) el.textContent = v; };
          var st = row.querySelector('[data-f=status] .st');
          if (st) { st.className = 'st st-' + x.status; st.textContent = x.status === 'pending_delete' ? 'pending delete' : x.status; }
          set('source', x.source); set('checked', x.checked); set('next', x.next); set('phase', x.phase);
          var c = row.querySelector('[data-f=catch]');
          if (c) c.textContent = x.catch === 'active' ? 'catching (' + x.attempts + ' orders)' : (x.catch === 'idle' ? '' : x.catch);
          row.classList.toggle('row-avail', x.status === 'available');
        });
      }).catch(function () {});
    }, 5000);
  }
})();
