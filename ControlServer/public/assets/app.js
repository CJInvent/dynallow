// DynAllow — all page behaviour. Attached via data-* attributes; there are
// no inline handlers anywhere (the CSP forbids them and would drop them silently).
(function () {
  'use strict';
  document.documentElement.classList.add('js');

  // Confirm before dangerous submits.
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-confirm]');
    if (b && !window.confirm(b.getAttribute('data-confirm'))) { e.preventDefault(); }
  });

  // Copy-to-clipboard buttons.
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]');
    if (!b) return;
    var el = document.getElementById(b.getAttribute('data-copy'));
    if (el && navigator.clipboard) {
      navigator.clipboard.writeText(el.textContent.trim()).then(function () { b.textContent = 'Copied'; });
    }
  });

  // Select-all checkbox for bulk actions.
  document.addEventListener('change', function (e) {
    if (e.target.matches('[data-check-all]')) {
      document.querySelectorAll('input[name="' + e.target.getAttribute('data-check-all') + '"]').forEach(function (c) { c.checked = e.target.checked; });
    }
  });

  // Provider field groups (DNS account form): show only the chosen provider's fields.
  function syncProvider(sel) {
    var form = sel.closest('form');
    form.querySelectorAll('[data-provider]').forEach(function (g) {
      var on = g.getAttribute('data-provider') === sel.value;
      g.classList.toggle('hidden', !on);
      g.querySelectorAll('input,select,textarea').forEach(function (i) { i.disabled = !on; });
    });
    var creates = sel.selectedOptions[0] && sel.selectedOptions[0].getAttribute('data-creates') === '1';
    form.querySelectorAll('[data-creates-only]').forEach(function (g) { g.classList.toggle('hidden', !creates); });
  }
  document.querySelectorAll('select[data-provider-select]').forEach(function (s) {
    syncProvider(s);
    s.addEventListener('change', function () { syncProvider(s); });
  });

  // DNS target rows (survey + agent page): name mode follows the account.
  function syncTarget(row) {
    var acc = row.querySelector('select[data-account]');
    if (!acc) return;
    var opt = acc.selectedOptions[0];
    var creates = opt && opt.getAttribute('data-creates') === '1';
    var domain = opt ? (opt.getAttribute('data-domain') || '') : '';
    var provider = opt ? opt.getAttribute('data-provider') : '';
    var mode = row.querySelector('select[data-name-mode]');
    if (mode) {
      mode.querySelector('option[value="random"]').disabled = !creates || !domain;
      if (mode.value === 'random' && (!creates || !domain)) mode.value = 'custom';
    }
    var isRandom = mode && mode.value === 'random';
    row.querySelectorAll('[data-when-random]').forEach(function (el) { el.classList.toggle('hidden', !isRandom); });
    row.querySelectorAll('[data-when-custom]').forEach(function (el) { el.classList.toggle('hidden', isRandom); });
    row.querySelectorAll('[data-domain-label]').forEach(function (el) { el.textContent = domain ? '.' + domain : ''; });
    row.querySelectorAll('[data-target-provider]').forEach(function (g) {
      var on = g.getAttribute('data-target-provider') === provider;
      g.classList.toggle('hidden', !on);
      g.querySelectorAll('input').forEach(function (i) { i.disabled = !on; });
    });
    row.querySelectorAll('[data-cf-only]').forEach(function (el) { el.classList.toggle('hidden', provider !== 'cloudflare'); });
  }
  function wireTarget(row) {
    row.addEventListener('change', function () { syncTarget(row); });
    var rm = row.querySelector('[data-remove-row]');
    if (rm) rm.addEventListener('click', function () { row.remove(); renumber(); });
    syncTarget(row);
  }
  function renumber() {
    document.querySelectorAll('[data-targets] .target-row').forEach(function (row, i) {
      row.querySelectorAll('[name]').forEach(function (el) {
        el.name = el.name.replace(/targets\[\d+\]/, 'targets[' + i + ']');
      });
    });
  }
  document.querySelectorAll('.target-row').forEach(wireTarget);
  document.querySelectorAll('[data-add-target]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var tpl = document.getElementById(btn.getAttribute('data-add-target'));
      var box = document.querySelector('[data-targets]');
      var frag = tpl.content.cloneNode(true);
      box.appendChild(frag);
      var row = box.lastElementChild;
      renumber();
      wireTarget(row);
    });
  });

  // Survey stepper. Without JS every step shows at once and the form still works.
  var survey = document.querySelector('[data-survey]');
  if (survey) {
    var steps = Array.prototype.slice.call(survey.querySelectorAll('.step'));
    var pills = Array.prototype.slice.call(document.querySelectorAll('.steps span'));
    var cur = parseInt(survey.getAttribute('data-start') || '0', 10);
    function show(i) {
      cur = Math.max(0, Math.min(steps.length - 1, i));
      steps.forEach(function (s, k) { s.classList.toggle('on', k === cur); });
      pills.forEach(function (p, k) { p.className = k === cur ? 'on' : (k < cur ? 'done' : ''); });
      if (cur === steps.length - 1) buildReview();
      window.scrollTo(0, 0);
    }
    function valid(step) {
      var ok = true;
      step.querySelectorAll('input,select,textarea').forEach(function (el) {
        if (!el.disabled && !el.closest('.hidden') && !el.checkValidity()) { if (ok) el.reportValidity(); ok = false; }
      });
      return ok;
    }
    survey.addEventListener('click', function (e) {
      if (e.target.matches('[data-next]')) { e.preventDefault(); if (valid(steps[cur])) show(cur + 1); }
      if (e.target.matches('[data-back]')) { e.preventDefault(); show(cur - 1); }
    });
    function val(name) {
      var el = survey.querySelector('[name="' + name + '"]:checked') || survey.querySelector('[name="' + name + '"]');
      if (!el) return '';
      if (el.tagName === 'SELECT') return el.selectedOptions[0] ? el.selectedOptions[0].text : '';
      return el.value;
    }
    function buildReview() {
      var out = survey.querySelector('[data-review]');
      if (!out) return;
      var rows = [['Customer', val('customer')], ['Site name', val('name')], ['Platform', val('platform')],
        ['Internet', val('isp') + ' / CGNAT: ' + val('cgnat')], ['Checks in', val('interval_sec')],
        ['Alert after', val('missed_threshold') + ' missed check-ins'], ['Trust mode', val('trust_mode')]];
      survey.querySelectorAll('[data-targets] .target-row').forEach(function (row) {
        var acc = row.querySelector('select[data-account]');
        var mode = row.querySelector('select[data-name-mode]');
        var host = mode && mode.value === 'random' ? '(random name).' + (acc.selectedOptions[0].getAttribute('data-domain') || '')
          : (row.querySelector('input[data-hostname]') || {}).value;
        rows.push(['DNS', acc.selectedOptions[0].text + ' → ' + host]);
      });
      out.innerHTML = '';
      rows.forEach(function (r) {
        var tr = document.createElement('tr');
        var th = document.createElement('th'); th.textContent = r[0];
        var td = document.createElement('td'); td.textContent = r[1] || '—';
        tr.appendChild(th); tr.appendChild(td); out.appendChild(tr);
      });
    }
    show(cur);
  }

  // Gentle auto-refresh for live pages; never while someone is typing or selecting.
  var ar = document.body.querySelector('[data-autorefresh]');
  if (ar) {
    setInterval(function () {
      var a = document.activeElement;
      var busy = a && (a.tagName === 'INPUT' || a.tagName === 'SELECT' || a.tagName === 'TEXTAREA');
      var anyChecked = document.querySelector('input[type=checkbox]:checked');
      if (!document.hidden && !busy && !anyChecked && !String(window.getSelection())) location.reload();
    }, parseInt(ar.getAttribute('data-autorefresh'), 10) * 1000);
  }
})();
