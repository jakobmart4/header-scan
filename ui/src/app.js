(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var STATUSES = ['fail', 'warn', 'info', 'pass', 'skipped'];
  var ICON = { fail: '✖ ', warn: '⚠ ', info: 'ℹ ', pass: '✔ ', skipped: '– ' };
  var CATS = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'seo', 'ai', 'ux', 'exposure'];
  var CAT_NAME = { headers: 'Headers', cookies: 'Cookies', tls: 'TLS', dns: 'DNS', mail: 'Mail', content: 'Content', seo: 'SEO', ai: 'AI visibility', ux: 'UX hygiene', exposure: 'Exposure' };
  var CAT_CODE = { headers: 'HDR', cookies: 'COK', tls: 'TLS', dns: 'DNS', mail: 'MAL', content: 'CNT', seo: 'SEO', ai: 'AI', ux: 'UX', exposure: 'EXP' };
  var result = null, verifiedHost = '', autoHost = '', txtHost = '', busy = false, toastTimer = 0;

  // Progressive enhancement gate: count-up via a registered custom property needs @property.
  if (window.CSS && typeof CSS.registerProperty === 'function') document.documentElement.classList.add('cp');

  // Scan data is untrusted: elements are built only with createElement + textContent.
  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); }
  function say(el, text, tone) { el.textContent = text; el.dataset.tone = tone || 'muted'; }
  function num(el, name, v, digits) { el.style.setProperty(name, String(Number(v.toFixed(digits || 0)))); }
  function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }

  function toast(text, tone) {
    var t = $('toast');
    t.textContent = text;
    t.dataset.tone = tone || 'ok';
    t.dataset.show = 'true';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.dataset.show = 'false'; }, 2500);
  }

  function setBusy(b) {
    busy = b;
    $('app').dataset.busy = String(b);
    $('scan-btn').disabled = b;
    $('verify-start').disabled = b;
    $('verify-check').disabled = b;
    $('deep-btn').disabled = b || !verifiedHost;
  }
  function setState(s) {
    $('results').dataset.state = s;
    $('results').setAttribute('aria-busy', String(s === 'loading'));
  }
  function setVerify(v) { $('deep').dataset.v = v; }

  async function api(path, opts) {
    var res, data;
    try { res = await fetch(path, opts); } catch (e) { throw new Error('Network error: could not reach the server.'); }
    try { data = await res.json(); } catch (e) { throw new Error('Unexpected server response (' + res.status + ').'); }
    if (!res.ok) throw new Error((data && data.error && data.error.message) || 'Request failed (' + res.status + ').');
    return data;
  }
  function post(path, body) {
    return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  }

  // Grade band: A+/A/B pass, C/D warn, E/F fail, N/A skip.
  function gradeBand(g) {
    if (g === 'N/A') return 'skip';
    var c = String(g).charAt(0);
    return c === 'A' || c === 'B' ? 'pass' : c === 'C' || c === 'D' ? 'warn' : 'fail';
  }
  function scoreBand(s) { return s === null ? 'skip' : s >= 80 ? 'pass' : s >= 55 ? 'warn' : 'fail'; }

  function fillGauge(g, s, label, band) {
    g.dataset.g = band;
    num(g, '--score', s === null ? 0 : clamp(s, 0, 100));
    g.setAttribute('aria-label', label + (s === null ? ': nothing measurable' : ', ' + s + ' of 100'));
    g.querySelector('.gauge-num').textContent = s === null ? 'n/a' : s;
  }

  function counts(findings) {
    var c = { pass: 0, warn: 0, fail: 0, info: 0, skipped: 0 };
    findings.forEach(function (f) { c[f.status]++; });
    return c;
  }

  function renderGauges(r) {
    [['security', 'Security'], ['quality', 'Quality']].forEach(function (p) {
      var s = r.score[p[0]], g = $('gauge-' + p[0]);
      fillGauge(g, s.score, p[1] + ' grade ' + s.grade, gradeBand(s.grade));
      g.querySelector('.gauge-grade').textContent = s.grade === 'N/A' ? '–' : s.grade;
    });
    var errs = r.errors && r.errors.length ? ' • ' + r.errors.length + ' module error(s): ' +
      r.errors.map(function (e) { return e.module + ' (' + e.message + ')'; }).join(', ') : '';
    $('meta').textContent = r.url + ' • ' + r.scannedAt + ' • ' + r.durationMs + ' ms • ' + (r.deep ? 'deep scan' : 'passive scan') + errs;
  }

  function renderDonut(findings) {
    var c = counts(findings), total = c.pass + c.warn + c.fail, d = $('donut');
    STATUSES.forEach(function (s) { $('lg-' + s).textContent = c[s]; });
    $('donut-total').textContent = total;
    d.dataset.empty = String(total === 0);
    num(d, '--a', total ? c.pass / total * 100 : 0, 1);
    num(d, '--b', total ? (c.pass + c.warn) / total * 100 : 0, 1);
    d.setAttribute('aria-label', c.pass + ' pass, ' + c.warn + ' warn, ' + c.fail + ' fail');
  }

  function renderHeat(findings) {
    var t = $('heat'), grid = {}, max = 0;
    clear(t);
    findings.forEach(function (f) {
      if (f.status !== 'fail' && f.status !== 'warn') return;
      var k = f.severity + ':' + f.category;
      grid[k] = (grid[k] || 0) + 1;
      if (grid[k] > max) max = grid[k];
    });
    t.appendChild(h('caption', 'sr', 'Number of fail and warn findings by severity and category'));
    var hr = h('tr');
    hr.appendChild(h('td'));
    CATS.forEach(function (c) {
      var th = h('th', '', CAT_CODE[c]);
      th.scope = 'col'; th.title = CAT_NAME[c]; th.setAttribute('aria-label', CAT_NAME[c]);
      hr.appendChild(th);
    });
    t.appendChild(h('thead')).appendChild(hr);
    var body = h('tbody');
    for (var sev = 5; sev >= 1; sev--) {
      var tr = h('tr'), rh = h('th', '', 'Sev ' + sev);
      rh.scope = 'row';
      tr.appendChild(rh);
      CATS.forEach(function (c) {
        var n = grid[sev + ':' + c] || 0, td = h('td', 'hc', n || '·');
        num(td, '--k', max ? n / max : 0, 2);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    }
    t.appendChild(body);
  }

  function renderCats(r) {
    var ul = $('cats'), i = 0;
    clear(ul);
    CATS.forEach(function (c) {
      var s = r.score.categories[c];
      if (!s) return;
      var band = scoreBand(s.score), li = h('li', 'crow');
      li.dataset.g = band;
      num(li, '--i', i++);
      var g = h('div', 'gauge gauge-sm');
      g.setAttribute('role', 'img');
      g.appendChild(h('div', 'gauge-ring'));
      g.appendChild(h('span', 'gauge-num'));
      fillGauge(g, s.score, CAT_NAME[c] + ' score', band);
      li.appendChild(g);
      li.appendChild(h('span', 'crow-name', CAT_NAME[c]));
      li.appendChild(h('span', 'crow-tag', s.fail + ' fail, ' + s.warn + ' warn, ' + s.pass + ' pass, ' + s.info + ' info, ' + s.skipped + ' skipped'));
      var bar = h('div', 'bar');
      bar.setAttribute('aria-hidden', 'true');
      ['pass', 'warn', 'fail'].forEach(function (st) {
        if (!s[st]) return;
        var seg = h('i', 'seg');
        seg.dataset.s = st;
        num(seg, '--n', s[st]);
        bar.appendChild(seg);
      });
      li.appendChild(bar);
      ul.appendChild(li);
    });
  }

  function renderFindings(r) {
    var box = $('findings'), ci = 0, fi = 0;
    clear(box);
    CATS.forEach(function (c) {
      var list = r.findings.filter(function (f) { return f.category === c; });
      if (!list.length) return;
      var d = h('details', 'cat'), sum = h('summary', 'cat-sum'), cnt = counts(list);
      d.dataset.c = c;
      d.open = cnt.fail + cnt.warn > 0;
      num(d, '--i', ci++);
      sum.appendChild(h('span', 'cat-name', CAT_NAME[c]));
      sum.appendChild(h('span', 'cat-count', '(' + list.length + ')'));
      STATUSES.forEach(function (s) {
        if (!cnt[s]) return;
        var chip = h('span', 'chip', ICON[s] + cnt[s]);
        chip.dataset.s = s;
        sum.appendChild(chip);
      });
      d.appendChild(sum);
      var ul = h('ul', 'list');
      list.forEach(function (f) {
        var li = h('li', 'fnd'), head = h('div', 'fnd-head'), pill = h('span', 'pill', ICON[f.status] + f.status);
        li.dataset.s = f.status; li.dataset.c = c;
        num(li, '--i', fi++);
        pill.dataset.s = f.status;
        head.appendChild(pill);
        head.appendChild(h('h3', 'fnd-title', f.title));
        head.appendChild(h('span', 'tag', 'severity ' + f.severity + '/5'));
        if (f.checklist) head.appendChild(h('span', 'tag', 'checklist #' + f.checklist));
        var sev = h('i', 'sev');
        sev.setAttribute('aria-hidden', 'true');
        num(sev, '--n', clamp(Number(f.severity) || 0, 0, 5));
        head.appendChild(sev);
        li.appendChild(head);
        if (f.evidence) li.appendChild(h('p', 'fnd-evidence muted', f.evidence));
        if (f.fix) li.appendChild(h('p', 'fnd-fix', 'Fix: ' + f.fix));
        if (typeof f.ref === 'string' && /^https?:\/\//i.test(f.ref)) {
          var a = h('a', 'fnd-ref', 'Reference');
          a.href = f.ref; a.rel = 'noopener noreferrer'; a.target = '_blank';
          li.appendChild(a);
        }
        ul.appendChild(li);
      });
      d.appendChild(ul);
      box.appendChild(d);
    });
  }

  // Filtering itself is CSS (:has, or [data-cat]/[data-st] fallback); this mirrors it for the counter.
  function syncFilters() {
    var cat = document.querySelector('input[name=cat]:checked').value;
    var st = document.querySelector('input[name=st]:checked').value;
    var res = $('results');
    res.dataset.cat = cat; res.dataset.st = st;
    var n = result ? result.findings.filter(function (f) {
      return (cat === 'all' || f.category === cat) &&
        (st === 'all' || (st === 'issues' ? f.status === 'fail' || f.status === 'warn' : f.status === st));
    }).length : 0;
    $('shown').textContent = n + (n === 1 ? ' finding shown' : ' findings shown');
    $('empty').hidden = n > 0;
  }

  function show(r) {
    result = r;
    renderGauges(r); renderDonut(r.findings); renderHeat(r.findings); renderCats(r); renderFindings(r); syncFilters();
    // Follow the latest scan unless the user typed their own host.
    if (!$('host').value || $('host').value === autoHost) {
      $('host').value = autoHost = r.host || '';
      $('host').dispatchEvent(new Event('input'));
    }
  }

  async function runScan(deep) {
    var url = $('url').value.trim();
    if (!url) { say($('status'), 'Enter a URL first.', 'err'); return; }
    setBusy(true);
    setState('loading');
    say($('status'), (deep ? 'Deep scan' : 'Scan') + ' running, this can take up to 45 seconds…');
    try {
      var r = deep ? await post('/api/scan', { url: url, deep: true }) : await api('/api/scan?url=' + encodeURIComponent(url));
      show(r);
      void $('results').offsetWidth; // reflow so the reveal animations restart on every scan
      setState('done');
      say($('status'), 'Scan finished.', 'ok');
    } catch (e) {
      $('error-msg').textContent = e.message;
      setState('error');
      say($('status'), 'Scan failed.', 'err');
    }
    setBusy(false);
  }

  $('scan-form').addEventListener('submit', function (ev) { ev.preventDefault(); if (!busy) runScan(false); });
  $('filters').addEventListener('change', syncFilters);

  $('verify-start').addEventListener('click', async function () {
    var host = $('host').value.trim();
    if (!host) { say($('verify-msg'), 'Enter the host you own.', 'err'); return; }
    setBusy(true); verifiedHost = '';
    setVerify('idle'); // never leave a previous host's record on screen
    try {
      var v = await post('/api/verify/start', { host: host });
      $('txt-name').textContent = v.txtName;
      $('txt-value').textContent = v.txtValue;
      $('txt-exp').textContent = 'Token expires ' + v.expiresAt + '.';
      txtHost = host;
      setVerify('pending');
      say($('verify-msg'), 'Waiting for the TXT record. Press Check after adding it.');
    } catch (e) { say($('verify-msg'), e.message, 'err'); }
    setBusy(false);
  });

  $('verify-check').addEventListener('click', async function () {
    var host = $('host').value.trim();
    setBusy(true);
    try {
      var v = await post('/api/verify/check', { host: host });
      if (v.verified) {
        verifiedHost = txtHost = host;
        setVerify('verified');
        say($('verify-msg'), 'Ownership verified for ' + v.host + '. Deep scan unlocked.', 'ok');
      } else { verifiedHost = ''; say($('verify-msg'), 'TXT record not found yet at ' + v.txtName + '. DNS can take a few minutes.', 'err'); }
    } catch (e) { verifiedHost = ''; say($('verify-msg'), e.message, 'err'); }
    setBusy(false);
  });

  // Editing the host invalidates the local unlock (the server re-checks on every deep scan anyway).
  $('host').addEventListener('input', function () {
    var host = $('host').value.trim();
    if (verifiedHost && host !== verifiedHost) { verifiedHost = ''; $('deep-btn').disabled = true; }
    if (txtHost !== host) setVerify('idle'); // the shown record/badge belongs to another host
  });

  $('deep-btn').addEventListener('click', function () {
    if (!verifiedHost || busy) return;
    if (!$('url').value.trim()) $('url').value = verifiedHost;
    runScan(true);
  });

  async function copy(text, done) {
    try { await navigator.clipboard.writeText(text); toast(done, 'ok'); }
    catch (e) { toast('Copy failed: select the text and copy it manually.', 'err'); }
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (b) {
    b.addEventListener('click', function () { copy($(b.getAttribute('data-copy')).textContent, 'Copied.'); });
  });
  $('copy-json').addEventListener('click', function () { if (result) copy(JSON.stringify(result, null, 2), 'JSON report copied.'); });
  $('dl-json').addEventListener('click', function () {
    if (!result) return;
    var blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'header-scan-' + String(result.host).replace(/[^a-z0-9.-]/gi, '_') + '.json';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });

  syncFilters();
})();
