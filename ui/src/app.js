(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var STATUSES = ['fail', 'warn', 'info', 'pass', 'skipped'];
  var ICON = { fail: '✖', warn: '⚠', info: 'ℹ', pass: '✔', skipped: '–' };
  var CATS = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'seo', 'ai', 'ux', 'exposure'];
  var CAT_NAME = { headers: 'Headers', cookies: 'Cookies', tls: 'TLS', dns: 'DNS', mail: 'Mail', content: 'Content', seo: 'SEO', ai: 'AI visibility', ux: 'UX hygiene', exposure: 'Exposure' };
  var CAT_CODE = { headers: 'HDR', cookies: 'COK', tls: 'TLS', dns: 'DNS', mail: 'MAL', content: 'CNT', seo: 'SEO', ai: 'AI', ux: 'UX', exposure: 'EXP' };
  var result = null, verifiedHost = '', autoHost = '', txtHost = '', busy = false, toastTimer = 0, busyFocus = null, sampleName = '';

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
  function txt(s) { return document.createTextNode(s); }
  // Status glyph for sighted users only; assistive tech reads the words that follow it.
  function glyph(s) {
    var g = h('span', '', ICON[s]);
    g.setAttribute('aria-hidden', 'true');
    return g;
  }
  function say(el, text, tone) { el.textContent = text; el.dataset.tone = tone || 'muted'; }
  function num(el, name, v, digits) { el.style.setProperty(name, String(Number(v.toFixed(digits || 0)))); }
  function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }

  // Errors stay long enough to be reached with a screen reader or magnifier (WCAG 2.2.1); the text is cleared
  // after the fade so a stale message is not left in the accessibility tree.
  function toast(text, tone) {
    var t = $('toast');
    t.textContent = text;
    t.dataset.tone = tone || 'ok';
    t.dataset.show = 'true';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      t.dataset.show = 'false';
      toastTimer = setTimeout(function () { t.textContent = ''; }, 400);
    }, tone === 'err' ? 8000 : 2500);
  }

  // Disabling the focused button drops focus to <body>: remember it and give it back when the request ends.
  function setBusy(b) {
    var a = document.activeElement;
    if (b) busyFocus = a && a.tagName === 'BUTTON' ? a : null;
    busy = b;
    $('app').dataset.busy = String(b);
    $('scan-btn').disabled = b;
    $('verify-start').disabled = b;
    $('verify-check').disabled = b;
    $('deep-btn').disabled = b || !verifiedHost;
    Array.prototype.forEach.call(document.querySelectorAll('[data-sample]'), function (x) { x.disabled = b; });
    if (!b && busyFocus && !busyFocus.disabled && (!a || a === document.body || a === busyFocus)) busyFocus.focus();
    if (!b) busyFocus = null;
  }
  // Enhancement-only code (charts extras, radar, view transitions) must never break the report: failures are swallowed.
  function enhance(fn, a) { try { fn(a); } catch (e) { /* the plain report stays */ } }

  // ---- View Transitions (progressive enhancement). Without the API, under reduced motion or in a hidden tab every change
  // applies at once. startViewTransition snapshots the OLD page at the next frame and only then calls the callback, so the
  // change itself must happen inside the callback. One transition at a time (vt.busy).
  var vt = { busy: false, cur: null, rm: window.matchMedia ? matchMedia('(prefers-reduced-motion: reduce)') : null };
  function vtOn() {
    return typeof document.startViewTransition === 'function' && !(vt.rm && vt.rm.matches) && !vt.busy && !document.hidden;
  }
  function viewTransition(cls, update) {
    var applied = false, root = document.documentElement;
    function apply() { if (applied) return; applied = true; update(); }
    if (!vtOn()) { apply(); return; }
    vt.busy = true;
    root.classList.add(cls);
    function end() { vt.busy = false; vt.cur = null; root.classList.remove(cls); }
    try {
      var t = vt.cur = document.startViewTransition(apply);
      t.ready.catch(function () {});
      t.finished.then(end, end);
      setTimeout(apply, 500); // never leave the page waiting if the callback is delayed
    } catch (e) { end(); apply(); }
  }

  // #results state (+ data-err). setState records the wanted state; the transition callback applies the LATEST wanted one,
  // so a reply that arrives before the first frame cannot leave the page stuck on "loading".
  var want = null, stateVT = false;
  function applyState(v) {
    var res = $('results');
    if (v.s === 'done' && res.dataset.state === 'done') res.dataset.state = 'loading'; // same state again: restart the reveal animations
    void res.offsetWidth; // reflow so the reveal animations restart on every scan
    res.dataset.state = v.s;
    res.dataset.err = v.err;
    res.setAttribute('aria-busy', String(v.s === 'loading'));
    if (v.s === 'done') enhance(tabsDone); // scroll + focus work of a finished deep scan (needs the report displayed)
  }
  function flushState() { var v = want; want = null; if (v) applyState(v); }
  function setState(s, err) {
    want = { s: s, err: err };
    if (stateVT) return;
    if (!vtOn()) { flushState(); return; }
    stateVT = true;
    viewTransition('flow-vt-state', function () { stateVT = false; flushState(); });
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

  // ISO timestamp -> local date and time; anything unparseable is shown as sent
  function when(iso) {
    try {
      var d = new Date(iso);
      return isNaN(d.getTime()) ? String(iso) : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    } catch (e) { return String(iso); }
  }

  function renderGauges(r) {
    [['security', 'Security'], ['quality', 'Quality']].forEach(function (p) {
      var s = r.score[p[0]], g = $('gauge-' + p[0]);
      fillGauge(g, s.score, p[1] + ' grade ' + s.grade, gradeBand(s.grade));
      g.querySelector('.gauge-grade').textContent = s.grade === 'N/A' ? '–' : s.grade;
    });
    // Why the letter is lower than the percentage suggests (see lib/score.js caps). Titles come from our own findings.
    var note = $('cap-note'), caps = [];
    [['security', 'Security'], ['quality', 'Quality']].forEach(function (p) {
      var s = r.score[p[0]];
      if (s.cappedBy && s.cappedBy.length) {
        var t = s.cappedBy.map(function (id) {
          var f = r.findings.filter(function (x) { return x.id === id; })[0];
          return f ? f.title : id;
        });
        caps.push(p[1] + ' grade capped at ' + s.grade + ' by: ' + t.join(', '));
      }
    });
    note.hidden = !caps.length;
    note.textContent = caps.join('. ');
    // The URL and module errors may be one long token (CSS breaks them anywhere); the fixed parts never wrap inside.
    var m = $('meta');
    clear(m);
    m.appendChild(txt(r.url));
    [when(r.scannedAt), r.durationMs + ' ms', r.deep ? 'deep scan' : 'passive scan'].forEach(function (t, i) {
      var s = h('span', 'nw', t);
      if (!i) s.title = String(r.scannedAt); // the ISO value stays available
      m.appendChild(txt(' • '));
      m.appendChild(s);
    });
    if (r.errors && r.errors.length) {
      m.appendChild(txt(' • ' + r.errors.length + ' module error(s): ' +
        r.errors.map(function (e) { return e.module + ' (' + e.message + ')'; }).join(', ')));
    }
  }

  function renderDonut(findings) {
    var c = counts(findings), total = c.pass + c.warn + c.fail, d = $('donut');
    STATUSES.forEach(function (s) { $('lg-' + s).textContent = c[s]; });
    $('donut-total').textContent = total;
    $('donut-cap').textContent = 'of ' + findings.length; // the donut counts pass+warn+fail only; the legend lists all five statuses
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
        if (!n) td.dataset.z = ''; // zero cell: muted numeral (skin-charts.css)
        num(td, '--k', max ? n / max : 0, 2);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    }
    t.appendChild(body);
    $('heat-min').textContent = '0'; // the legend ramp ends are real values
    $('heat-max').textContent = 'max ' + max;
  }

  // Fail + warn per severity (5 to 1) as a slim stacked bar plus a text key; role=img label carries every count.
  function renderStack(findings) {
    var box = $('sevstack'), by = {}, sev, total = 0, parts = [];
    for (sev = 1; sev <= 5; sev++) by[sev] = { fail: 0, warn: 0 };
    findings.forEach(function (f) {
      if ((f.status === 'fail' || f.status === 'warn') && by[f.severity]) { by[f.severity][f.status]++; total++; }
    });
    var bar = h('div', 'ss-bar'), key = h('ol', 'ss-key');
    for (sev = 5; sev >= 1; sev--) {
      var fl = by[sev].fail, wn = by[sev].warn, n = fl + wn;
      if (n) {
        var seg = h('i', 'ss-seg');
        seg.dataset.sev = String(sev);
        seg.style.setProperty('--n', String(n));
        seg.style.setProperty('--si', String(5 - sev));
        bar.appendChild(seg);
      }
      var li = h('li', 'ss-k'), l = h('span', 'ss-l'), sw = h('i', 'ss-sw');
      if (!n) li.dataset.z = '';
      sw.dataset.sev = String(sev);
      l.appendChild(sw);
      l.appendChild(txt('Sev ' + sev));
      li.appendChild(l);
      li.appendChild(h('b', 'ss-v', n));
      li.appendChild(h('span', 'ss-s', n ? (fl ? ICON.fail + fl : '') + (fl && wn ? ' ' : '') + (wn ? ICON.warn + wn : '') : 'none'));
      key.appendChild(li);
      parts.push('severity ' + sev + ': ' + n + (n ? ' (' + fl + ' fail, ' + wn + ' warn)' : ''));
    }
    clear(box);
    box.appendChild(bar);
    box.appendChild(key);
    box.setAttribute('aria-label', 'Fail and warn findings by severity, ' + total + ' in total. ' + parts.join('; '));
    box.hidden = false;
  }

  // Radar of the ten category scores (static markup in the template, drawn by skin-radar.css). Only where CSS can do
  // sin()/cos() in calc(); elsewhere the card stays hidden. The numbers are already announced by #cats, so it is aria-hidden.
  var RADAR_OK = !!(window.CSS && CSS.supports && CSS.supports('width', 'calc(sin(1rad) * 1px)'));
  // Value drawn for a not-measured axis: where its spoke crosses the straight chord between the nearest measured neighbours
  // (circular), so the outline bridges the gap without claiming a value. Linear blend when the chord misses the spoke
  // (neighbours 180deg or more apart).
  function radarValue(sc, i) {
    if (sc[i].s !== null) return sc[i].s;
    var n = sc.length, a = 1, b = 1;
    while (a < n && sc[(i - a + n) % n].s === null) a++;
    while (b < n && sc[(i + b) % n].s === null) b++;
    if (a >= n) return 0; // nothing measured at all
    var va = sc[(i - a + n) % n].s, vb = sc[(i + b) % n].s;
    var ta = a * Math.PI / 5, tb = b * Math.PI / 5; // 36deg per axis; the spoke of axis i is the y axis
    var ax = -va * Math.sin(ta), ay = va * Math.cos(ta), bx = vb * Math.sin(tb), by = vb * Math.cos(tb);
    if (a + b < 5 && bx - ax > 1e-9) return Math.max(0, ay + (by - ay) * (-ax / (bx - ax)));
    return (va * b + vb * a) / (a + b);
  }
  function renderRadar(r) {
    var card = $('radar-card'), radar = $('radar');
    if (!RADAR_OK || !card || !radar) return;
    var sc = CATS.map(function (c) {
      var s = r.score.categories[c];
      return s && typeof s.score === 'number' ? { s: clamp(s.score, 0, 100), g: scoreBand(s.score) } : { s: null, g: 'skip' };
    });
    var any = sc.filter(function (x) { return x.s !== null; }).length >= 3; // fewer measured axes would draw an invented shape
    card.hidden = !any;
    if (!any) return;
    card.dataset.g = gradeBand(r.score.security.grade);
    var pts = radar.querySelectorAll('.radar-pt'), lbs = radar.querySelectorAll('.radar-lb');
    sc.forEach(function (x, i) {
      var v = Math.round(radarValue(sc, i) * 10) / 10, na = x.s === null;
      radar.style.setProperty('--v' + (i + 1), String(v));
      pts[i].style.setProperty('--v', String(v));
      [pts[i], lbs[i]].forEach(function (e) {
        e.dataset.g = x.g;
        if (na) e.dataset.na = ''; else delete e.dataset.na;
      });
      lbs[i].querySelector('.radar-val').textContent = na ? 'n/a' : Math.round(x.s);
    });
  }

  function renderCats(r) {
    var ul = $('cats'), i = 0;
    clear(ul);
    CATS.forEach(function (c) {
      var s = r.score.categories[c];
      if (!s) return;
      var band = scoreBand(s.score), li = h('li', 'crow');
      li.dataset.g = band;
      li.dataset.c = c;
      num(li, '--i', i++);
      var g = h('div', 'gauge gauge-sm');
      g.setAttribute('role', 'img');
      g.appendChild(h('div', 'gauge-ring'));
      g.appendChild(h('span', 'gauge-num'));
      fillGauge(g, s.score, CAT_NAME[c] + ' score', band);
      li.appendChild(g);
      var name = h('span', 'crow-name', CAT_NAME[c]), nums = h('span', 'xc-n');
      nums.setAttribute('aria-hidden', 'true'); // larger status numerals shown on hover (skin-charts.css); crow-tag has the words
      ['fail', 'warn', 'pass'].forEach(function (k) {
        if (!s[k]) return;
        var b = h('b');
        b.dataset.s = k;
        b.appendChild(h('i', '', ICON[k]));
        b.appendChild(txt(s[k]));
        nums.appendChild(b);
      });
      if (nums.firstChild) name.appendChild(nums);
      li.appendChild(name);
      li.appendChild(h('span', 'crow-tag', ['fail', 'warn', 'pass', 'info', 'skipped'].filter(function (k) { return s[k]; }).map(function (k) { return s[k] + ' ' + k; }).join(', ') || 'no checks'));
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
    fxOpen = 0;
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
        var chip = h('span', 'chip');
        chip.dataset.s = s;
        chip.appendChild(glyph(s));
        chip.appendChild(txt(cnt[s]));
        chip.appendChild(h('span', 'sr', ' ' + s));
        sum.appendChild(chip);
      });
      d.appendChild(sum);
      var ul = h('ul', 'list');
      list.forEach(function (f) {
        var li = h('li', 'fnd'), head = h('div', 'fnd-head'), pill = h('span', 'pill');
        li.dataset.s = f.status; li.dataset.c = c; li.dataset.sev = String(f.severity);
        num(li, '--i', fi++);
        pill.dataset.s = f.status;
        pill.appendChild(glyph(f.status));
        pill.appendChild(txt(f.status));
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
        enhance(compactRow, li);
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
    $('empty-msg').textContent = st === 'issues' && cat === 'all' ? 'No fail or warn findings.' : 'No findings match these filters.';
    $('reset-filters').hidden = cat === 'all' && st === 'all';
    $('empty').hidden = n > 0;
    // A narrowed view (one category, or pass/info/skipped) would otherwise show collapsed headers only.
    if (cat !== 'all' || st === 'pass' || st === 'info' || st === 'skipped') {
      Array.prototype.forEach.call(document.querySelectorAll('#findings .cat'), function (d) { d.open = true; });
    }
    enhance(fxSync);
  }

  // The filter radios are visually hidden and, in the scrolling chip strips on narrow screens, sit at the strip
  // start: the browser never scrolls to the focused/checked chip on its own, so do it here.
  function reveal(ev) {
    var l = ev.target.labels && ev.target.labels[0], strip = l && l.parentNode;
    if (strip && strip.scrollWidth > strip.clientWidth) {
      l.scrollIntoView({ inline: 'nearest', block: 'nearest' });
    }
  }

  // Raw headers come from the scanned server (untrusted): textContent only. Set-Cookie values are already redacted server-side.
  function renderRaw(r) {
    var rows = Array.isArray(r.rawHeaders) ? r.rawHeaders : [], body = $('raw-body');
    clear(body);
    $('raw-card').hidden = !rows.length;
    $('raw-count').textContent = rows.length ? '(' + rows.length + ')' : '';
    rows.forEach(function (x) {
      var tr = h('tr');
      tr.appendChild(h('th', 'rn', x.name));
      tr.lastChild.setAttribute('scope', 'row');
      tr.appendChild(h('td', 'rv', x.value));
      body.appendChild(tr);
    });
  }

  function show(r, deep) {
    result = r;
    renderRaw(r);
    renderGauges(r); renderDonut(r.findings); renderHeat(r.findings); renderCats(r); renderFindings(r); syncFilters();
    enhance(renderStack, r.findings);
    enhance(renderRadar, r);
    enhance(stripSync);
    enhance(function () { tabsRender(r, deep); });
    // Follow the latest scan unless the user typed their own host.
    if (!r.sample && (!$('host').value || $('host').value === autoHost)) { // a sample's host is not a real one to verify
      $('host').value = autoHost = r.host || '';
      $('host').dispatchEvent(new Event('input'));
    }
  }

  // ---- Compact finding rows (skin-compact.css). Plain rows stay valid: all of this is enhancement keyed on li.fnd[data-fx],
  // so if it throws the report is still complete. Row = h3 > button (APG accordion); fail rows start open, the rest closed.
  var UNTIL_FOUND = 'onbeforematch' in document.documentElement; // hidden="until-found": find-in-page can open a collapsed row
  var phoneMQ = window.matchMedia ? matchMedia('(max-width: 640px)') : { matches: false };
  var fxSeq = 0, fxOpen = 0;
  function rowOpen(li) { return li.dataset.fx === 'open'; }
  function setRow(li, on, touched) {
    var b = li.querySelector('.fnd-toggle');
    if (!b) return;
    if (touched) li.dataset.touched = '1';
    li.dataset.fx = on ? 'open' : 'closed';
    b.setAttribute('aria-expanded', String(on));
    Array.prototype.forEach.call(li.querySelectorAll('[data-fxh]'), function (el) {
      if (on) el.removeAttribute('hidden'); else el.setAttribute('hidden', UNTIL_FOUND ? 'until-found' : '');
    });
  }
  // li is a finished row (head, optional evidence/fix/ref). Called from renderFindings for every row.
  function compactRow(li) {
    var head = li.querySelector('.fnd-head'), title = li.querySelector('.fnd-title');
    var ev = li.querySelector('.fnd-evidence'), fix = li.querySelector('.fnd-fix'), ref = li.querySelector('.fnd-ref');
    var fail = li.dataset.s === 'fail', ids = [], id = 'fx' + (++fxSeq);
    if (!head || !title) return;
    if (ev) { head.appendChild(ev); if (!fail) ev.dataset.fxh = '1'; } // evidence is the collapsed one-line preview on fail rows
    [fix, ref].forEach(function (el) { if (el) el.dataset.fxh = '1'; });
    [ev, fix, ref].forEach(function (el, i) { if (el) { el.id = id + 'abc'.charAt(i); ids.push(el.id); } });
    if (!ids.length) { li.dataset.fx = 'none'; return; }
    if (fail && ev) li.dataset.prev = '1';
    var b = h('button', 'fnd-toggle'), tt = h('span', 'fnd-tt', title.textContent);
    b.type = 'button';
    b.setAttribute('aria-controls', ids.join(' '));
    b.appendChild(tt);
    clear(title);
    title.appendChild(b);
    // phones: only the first three failed rows start open (a scan can have 15), the others show the one-line preview
    setRow(li, fail && (!phoneMQ.matches || ++fxOpen <= 3));
  }
  // rows the current filter shows: same rule as syncFilters (works for the :has path and the data-cat/data-st fallback alike)
  function fxRows() {
    var c = document.querySelector('input[name=cat]:checked').value, t = document.querySelector('input[name=st]:checked').value;
    return Array.prototype.filter.call($('findings').querySelectorAll('li.fnd[data-fx="open"], li.fnd[data-fx="closed"]'), function (li) {
      var s = li.dataset.s;
      return (c === 'all' || li.dataset.c === c) && (t === 'all' || (t === 'issues' ? s === 'fail' || s === 'warn' : s === t));
    });
  }
  function fxSync() {
    var all = $('expand-all'), r = fxRows();
    all.hidden = !r.length;
    all.textContent = r.length && r.every(rowOpen) ? 'Collapse all' : 'Expand all';
  }
  function initRows() {
    var box = $('findings'), all = $('expand-all'), live = $('fx-live');
    box.addEventListener('click', function (ev) {
      var b = ev.target.closest && ev.target.closest('.fnd-toggle');
      if (!b) return;
      var li = b.closest('li.fnd');
      setRow(li, !rowOpen(li), true);
      fxSync();
    });
    box.addEventListener('animationend', function (ev) { // the reveal plays once per user toggle, not on every later re-show
      if (ev.animationName !== 'x-open') return;
      var li = ev.target.closest && ev.target.closest('li.fnd');
      if (!li) return;
      var parts = li.querySelectorAll('.fnd-evidence, .fnd-fix, .fnd-ref');
      if (ev.target === parts[parts.length - 1]) delete li.dataset.touched;
    });
    box.addEventListener('beforematch', function (ev) { // find-in-page landed in a collapsed row
      var li = ev.target.closest && ev.target.closest('li.fnd');
      if (li && !rowOpen(li)) { setRow(li, true, true); fxSync(); }
    });
    all.addEventListener('click', function () {
      var r = fxRows(), on = !r.every(rowOpen);
      r.forEach(function (li) {
        if (on) { var d = li.closest('details.cat'); if (d) d.open = true; }
        setRow(li, on); // no 'touched': 100+ simultaneous reveal animations are noise
      });
      fxSync();
      live.textContent = r.length + (r.length === 1 ? ' finding ' : ' findings ') + (on ? 'expanded' : 'collapsed'); // the label flips while focus stays on the button
    });
    // printing shows everything: open every closed <details> in the report (category groups, raw headers); the print CSS shows the row parts
    var reopened = [];
    window.addEventListener('beforeprint', function () {
      reopened = reopened.concat(Array.prototype.filter.call(document.querySelectorAll('#report details:not([open])'), function (d) { d.open = true; return true; }));
    });
    window.addEventListener('afterprint', function () { reopened.forEach(function (d) { d.open = false; }); reopened = []; });
  }

  // ---- Report tabs Overview | Findings | Details (skin-tabs.css). #xt is real markup; #results[data-view] picks the visible group
  // by CSS and exists only after tabsRender, so without JS (or if it throws) the whole report stays visible.
  // #report is the tabpanel; while Details is selected the deep-scan section (outside #results) is a second panel of that tab.
  var VIEWS = ['overview', 'findings', 'details'];
  var TV = { first: true, lastUrl: null, after: null, fix: null };
  function tabEl(v) { return $('xt-tab-' + v); }
  function tabsMeasure() { // the tray height follows text zoom / wrapping (CSS reads it as a unitless number of px)
    var hgt = $('xt').offsetHeight;
    if (hgt) document.documentElement.style.setProperty('--xt-h', String(hgt));
  }
  // back to the top of the report (under the tray when it is sticky), only when the page is scrolled past it
  function tabsToStrip() {
    var strip = $('xt'), cs = getComputedStyle(strip), gap = parseFloat(cs.marginBottom) || 0;
    var tray = cs.position === 'fixed' ? 0 : strip.offsetHeight + gap;
    var y = window.pageYOffset + $('report').getBoundingClientRect().top - tray - 8;
    if (window.pageYOffset > y) window.scrollTo(0, Math.max(0, y));
  }
  function tabSelect(v, focus, scroll, noHash) {
    if (VIEWS.indexOf(v) < 0) return;
    var res = $('results'), deep = $('deep');
    res.dataset.view = v;
    VIEWS.forEach(function (k) {
      tabEl(k).setAttribute('aria-selected', String(k === v));
      tabEl(k).tabIndex = k === v ? 0 : -1;
    });
    $('report').setAttribute('aria-labelledby', 'xt-tab-' + v);
    if (v === 'details') { deep.setAttribute('role', 'tabpanel'); deep.setAttribute('aria-labelledby', 'xt-tab-details'); }
    else { deep.removeAttribute('role'); deep.setAttribute('aria-labelledby', 'deep-h'); }
    tabsMeasure();
    if (focus) tabEl(v).focus({ preventScroll: true });
    if (scroll) tabsToStrip();
    if (!noHash) { try { history.replaceState(null, '', '#' + (sampleName ? 'sample=' + sampleName + '&' : '') + 'view=' + v); } catch (e) { /* sandboxed */ } }
  }
  function hashView() {
    var m = /(?:^#|&)view=(overview|findings|details)(?:&|$)/.exec(location.hash);
    return m ? m[1] : null;
  }
  function setRadio(id) {
    var r = $(id);
    if (r && !r.checked) { r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); }
  }
  // open one finding in the Findings tab: widen the filters when they hide it, expand the row, focus its toggle
  function tabsGoto(li) {
    var c = document.querySelector('input[name=cat]:checked'), s = document.querySelector('input[name=st]:checked');
    if (c.value !== 'all' && c.value !== li.dataset.c) setRadio('cat-all');
    if (s.value !== 'all' && s.value !== 'issues' && s.value !== li.dataset.s) setRadio('st-issues');
    tabSelect('findings', false, false);
    var d = li.closest('details.cat'), b = li.querySelector('.fnd-toggle');
    if (d) d.open = true;
    if (b && b.getAttribute('aria-expanded') === 'false') b.click();
    li.scrollIntoView({ block: 'center' });
    (b || tabEl('findings')).focus({ preventScroll: true });
  }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  // Overview card: counts, the three most severe failed checks (warnings when nothing failed) and the deep-scan cue
  function tabsFix(c) {
    if (TV.fix && TV.fix.parentNode) TV.fix.parentNode.removeChild(TV.fix);
    var main = $('report-main'), fix = TV.fix = h('section', 'card xt-fix'), hd = h('h2', 'eyebrow', 'Fix first');
    fix.setAttribute('aria-labelledby', 'xt-fix-h');
    hd.id = 'xt-fix-h';
    fix.appendChild(hd);
    fix.appendChild(h('p', 'xt-sum', c.fail + ' failed, ' + plural(c.warn, 'warning', 'warnings')));
    var rows = Array.prototype.map.call($('findings').querySelectorAll('.fnd[data-s="' + (c.fail ? 'fail' : 'warn') + '"]'), function (li, i) {
      return { li: li, sev: Number(li.dataset.sev) || 0, i: i };
    });
    rows.sort(function (a, b) { return b.sev - a.sev || a.i - b.i; });
    if (rows.length) {
      var ol = h('ol', 'xt-top');
      rows.slice(0, 3).forEach(function (r) {
        var item = h('li'), b = h('button', 'xt-item'), t = r.li.querySelector('.fnd-title'), f = r.li.querySelector('.fnd-fix');
        b.type = 'button';
        b.appendChild(h('span', 'xt-sev', 'Sev ' + r.sev));
        b.appendChild(h('span', 'xt-ttl', t ? t.textContent : ''));
        if (f) b.appendChild(h('span', 'xt-fx', f.textContent.replace(/^Fix:\s*/, '')));
        b.addEventListener('click', function () { tabsGoto(r.li); });
        item.appendChild(b);
        ol.appendChild(item);
      });
      fix.appendChild(ol);
    }
    var cue = h('div', 'xt-cue'), go = h('button', 'btn', 'Verify ownership');
    cue.appendChild(h('p', 'muted', 'Exposed files (.git, .env) are only checked in a deep scan, for domains you own.'));
    go.type = 'button';
    go.addEventListener('click', function () { tabSelect('details', false, true); tabEl('details').focus({ preventScroll: true }); });
    cue.appendChild(go);
    fix.appendChild(cue);
    main.insertBefore(fix, main.firstChild);
  }
  // Overview category rows open their findings (a real button stretched over the row)
  function tabsLinkCats() {
    Array.prototype.forEach.call(document.querySelectorAll('#cats > .crow'), function (li) {
      var r = $('cat-' + li.dataset.c), tag = li.querySelector('.crow-tag');
      if (!r) return;
      var issues = tag && /fail|warn/.test(tag.textContent), b = h('button', 'crow-go');
      b.type = 'button';
      b.appendChild(h('span', 'sr', 'Show ' + CAT_NAME[li.dataset.c] + ' findings'));
      b.addEventListener('click', function () {
        setRadio(r.id);
        setRadio(issues ? 'st-issues' : 'st-all');
        tabSelect('findings', false, true);
        tabEl('findings').focus({ preventScroll: true }); // the button is hidden now: hand focus to the tab
      });
      li.appendChild(b);
    });
  }
  // Called from show() with the new report. Re-scanning the same URL keeps the tab; a new URL starts at the Overview;
  // a deep scan (started from Details) lands on Findings. The scroll and focus work waits for state "done" (tabsDone).
  function tabsRender(r, deep) {
    var res = $('results'), c = counts(r.findings), url = $('url').value.trim().toLowerCase();
    $('xt-count').textContent = String(c.fail + c.warn); // fail + warn over ALL findings: the filter radios do not change it
    $('xt-count-sr').textContent = ' issues (' + c.fail + ' failed, ' + plural(c.warn, 'warning', 'warnings') + ')';
    tabEl('findings').title = c.fail + ' failed, ' + plural(c.warn, 'warning', 'warnings');
    try { tabsFix(c); tabsLinkCats(); } catch (e) { /* the tabs work without them */ }
    document.documentElement.classList.add('xt');
    var same = TV.lastUrl !== null && url === TV.lastUrl;
    TV.lastUrl = url;
    var v = TV.first ? hashView() || 'overview' : deep ? 'findings' : same && res.dataset.view ? res.dataset.view : 'overview';
    TV.first = false;
    TV.after = deep ? { scroll: true, focus: true } : null;
    tabSelect(v, false, false);
  }
  function tabsDone() {
    var a = TV.after;
    TV.after = null;
    tabsMeasure();
    if (!a) return;
    if (a.scroll) tabsToStrip();
    // the deep scan button (outside the tab it landed on) is hidden now and focus fell to <body>: hand it to the tab
    var cur = document.activeElement;
    if (a.focus && (!cur || cur === document.body)) tabEl($('results').dataset.view).focus({ preventScroll: true });
  }
  function initTabs() {
    var res = $('results');
    $('report').setAttribute('role', 'tabpanel');
    VIEWS.forEach(function (v) { tabEl(v).addEventListener('click', function () { tabSelect(v, false, true); }); });
    $('xt').querySelector('.xt-list').addEventListener('keydown', function (ev) {
      if (ev.altKey || ev.ctrlKey || ev.metaKey || ev.shiftKey) return;
      var i = VIEWS.indexOf(res.dataset.view), k = ev.key, n;
      if (k === 'ArrowRight') n = (i + 1) % VIEWS.length;
      else if (k === 'ArrowLeft') n = (i + VIEWS.length - 1) % VIEWS.length;
      else if (k === 'Home') n = 0;
      else if (k === 'End') n = VIEWS.length - 1;
      else return;
      ev.preventDefault();
      tabSelect(VIEWS[n], true, true); // automatic activation: switching is a CSS toggle, nothing to load
    });
    if (window.ResizeObserver) new ResizeObserver(tabsMeasure).observe($('xt'));
    window.addEventListener('hashchange', function () {
      var v = hashView();
      if (v && res.dataset.view && v !== res.dataset.view) tabSelect(v, false, true, true);
    });
  }

  // ---- Phones (<= 640px): the donut, heat and radar cards (existing nodes, ids unchanged) move into one swipeable strip with
  // position dots; above 640px they go back to their place. If this throws the cards simply stay stacked.
  var stripSync = function () {};
  function initStrip() {
    if (!window.matchMedia) return;
    var cards = ['donut-card', 'heat-card', 'radar-card'].map($), mq = matchMedia('(max-width: 640px)');
    var strip = h('div'), dots = h('div', 'strip-dots');
    strip.id = 'strip';
    strip.setAttribute('role', 'region');
    strip.setAttribute('aria-label', 'Charts');
    strip.tabIndex = 0;
    dots.setAttribute('role', 'group');
    dots.setAttribute('aria-label', 'Choose chart');
    function visible() { return cards.filter(function (c) { return !c.hidden; }); } // the radar card stays hidden where it is not drawn
    // dot i is "on" when card i is the one nearest to the strip's start edge
    function mark() {
      var vis = visible(), kids = dots.children, best = 0, bd = Infinity;
      var edge = strip.getBoundingClientRect().left + (parseFloat(getComputedStyle(strip).paddingLeft) || 0);
      vis.forEach(function (c, i) {
        var d = Math.abs(c.getBoundingClientRect().left - edge);
        if (d < bd) { bd = d; best = i; }
      });
      for (var i = 0; i < kids.length; i++) kids[i].setAttribute('aria-current', String(i === best));
    }
    function go(i) { // scroll the strip itself (not the page) so card i sits at the start edge
      var c = visible()[i];
      if (!c) return;
      var pad = parseFloat(getComputedStyle(strip).paddingLeft) || 0;
      var left = c.getBoundingClientRect().left - strip.getBoundingClientRect().left + strip.scrollLeft - pad;
      var calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      strip.scrollTo({ left: left, behavior: calm ? 'auto' : 'smooth' });
      for (var k = 0; k < dots.children.length; k++) dots.children[k].setAttribute('aria-current', String(k === i));
    }
    function draw() {
      var n = visible().length;
      while (dots.children.length > n) dots.removeChild(dots.lastChild);
      while (dots.children.length < n) {
        var b = h('button', 'strip-dot');
        b.type = 'button';
        b.addEventListener('click', go.bind(null, dots.children.length));
        dots.appendChild(b);
      }
      for (var j = 0; j < n; j++) dots.children[j].setAttribute('aria-label', 'Show chart ' + (j + 1) + ' of ' + n);
      dots.hidden = n < 2;
      mark();
    }
    strip.addEventListener('scroll', mark, { passive: true }); // 3 rect reads: cheap enough without rAF throttling
    function wrap() {
      var host = cards[0].parentNode;
      if (strip.parentNode || !host) return;
      host.insertBefore(strip, cards[0]);
      cards.forEach(function (c) { strip.appendChild(c); });
      host.insertBefore(dots, strip.nextSibling);
      strip.scrollLeft = 0;
      draw();
    }
    function unwrap() {
      var host = strip.parentNode;
      if (!host) return;
      cards.forEach(function (c) { host.insertBefore(c, strip); });
      host.removeChild(strip);
      if (dots.parentNode) dots.parentNode.removeChild(dots);
    }
    function sync() { if (mq.matches) wrap(); else unwrap(); }
    if (mq.addEventListener) mq.addEventListener('change', sync); else if (mq.addListener) mq.addListener(sync);
    stripSync = function () { strip.scrollLeft = 0; draw(); }; // a new report starts at the first card; the radar card may have appeared
    sync();
  }

  async function runScan(deep) {
    var url = $('url').value.trim();
    if (!url) { say($('status'), 'Enter a URL first.', 'err'); return; }
    setBusy(true);
    delete $('results').dataset.refilter; // a fresh report gets the full staggered reveal again
    setState('loading', 'false');
    say($('status'), (deep ? 'Deep scan' : 'Scan') + ' running, this can take up to 45 seconds…');
    try {
      var r = deep ? await post('/api/scan', { url: url, deep: true }) : await api('/api/scan?url=' + encodeURIComponent(url));
      sampleName = '';
      $('sample-banner').hidden = true;
      show(r, deep);
      setState('done', 'false');
      say($('status'), 'Scan finished.', 'ok');
    } catch (e) {
      $('error-msg').textContent = e.message;
      // Keep the previous report (and its Copy/Download buttons); the error box sits above it.
      setState(result ? 'done' : 'error', String(!!result));
      say($('status'), 'Scan failed.', 'err');
    }
    setBusy(false);
  }

  // Sample reports: static JSON from /samples (made by scripts/sample-reports.mjs with the real scoring engine), shown through
  // the same show() as a scan. The banner stays until a real scan finishes.
  async function loadSample(name) {
    setBusy(true);
    delete $('results').dataset.refilter;
    setState('loading', 'false');
    say($('status'), 'Loading sample report…');
    try {
      var r = await api('/samples/' + name + '.json');
      sampleName = name;
      $('sample-banner').hidden = false;
      show(r, false);
      setState('done', 'false');
      say($('status'), 'Showing a sample report, not a real site.');
    } catch (e) {
      $('error-msg').textContent = e.message;
      setState(result ? 'done' : 'error', String(!!result));
      say($('status'), 'Sample report failed to load.', 'err');
    }
    setBusy(false);
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-sample]'), function (b) {
    b.addEventListener('click', function () { if (!busy) loadSample(b.dataset.sample); });
  });

  $('scan-form').addEventListener('submit', function (ev) { ev.preventDefault(); if (!busy) runScan(false); });
  $('filters').addEventListener('change', function (ev) {
    $('results').dataset.refilter = 'true'; // re-shown items reveal without the initial wait (findings.css)
    syncFilters();
    reveal(ev);
  });
  $('filters').addEventListener('focusin', reveal);
  $('reset-filters').addEventListener('click', function () {
    $('cat-all').checked = true;
    $('st-all').checked = true;
    $('st-all').dispatchEvent(new Event('change', { bubbles: true }));
    $('st-all').focus();
  });
  // Keep scroll-padding-top equal to the sticky filter bar so keyboard focus is never left underneath it.
  if (window.ResizeObserver) {
    new ResizeObserver(function () {
      document.documentElement.style.setProperty('--filters-h', $('filters').offsetHeight + 'px');
    }).observe($('filters'));
  }

  $('verify-start').addEventListener('click', async function () {
    var host = $('host').value.trim();
    if (!host) { say($('verify-msg'), 'Enter the host you own.', 'err'); return; }
    setBusy(true); verifiedHost = '';
    setVerify('idle'); // never leave a previous host's record on screen
    try {
      var v = await post('/api/verify/start', { host: host });
      $('txt-name').textContent = v.txtName;
      $('txt-value').textContent = v.txtValue;
      $('txt-exp').textContent = 'Token expires ' + new Date(v.expiresAt).toLocaleString() + '.';
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
        busyFocus = $('deep-btn'); // the Check button is hidden now: hand focus to the next step, not to <body>
        say($('verify-msg'), 'Ownership verified for ' + v.host + '. Deep scan unlocked.', 'ok');
      } else { verifiedHost = ''; say($('verify-msg'), 'TXT record not found yet at ' + v.txtName + '. DNS can take a few minutes.', 'err'); }
    } catch (e) { verifiedHost = ''; say($('verify-msg'), e.message, 'err'); }
    setBusy(false);
  });

  // Editing the host invalidates the local unlock (the server re-checks on every deep scan anyway).
  $('host').addEventListener('input', function () {
    var host = $('host').value.trim();
    if (verifiedHost && host !== verifiedHost) { verifiedHost = txtHost = ''; $('deep-btn').disabled = true; }
    if (txtHost !== host) { // the shown record/badge/message belongs to another host (or to a verification just lost)
      setVerify('idle');
      say($('verify-msg'), '');
    }
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

  // Without CSS :has() the donut arc highlight follows the legend rows through data-hl (hover only: the rows are not controls).
  function initLegendHover() {
    if (window.CSS && CSS.supports && CSS.supports('selector(:has(*))')) return;
    var d = $('donut');
    Array.prototype.forEach.call(document.querySelectorAll('.legend > .lg[data-s]:not(.plain)'), function (row) {
      row.addEventListener('mouseenter', function () { d.dataset.hl = row.dataset.s; });
      row.addEventListener('mouseleave', function () { delete d.dataset.hl; });
    });
  }

  // Filter changes run inside a view transition: the capture-phase handlers stop the native change, let the browser snapshot the
  // old page, then replay the press inside the callback (the :has() filtering stays the source of truth). Names live only
  // while html.flow-vt-filter is set (skin-flow.css). Only wired when startViewTransition exists.
  function initFilterFlow() {
    if (typeof document.startViewTransition !== 'function') return;
    var doc = document, root = doc.documentElement, replay = false, fgen = 0;
    root.classList.add('flow-vt-ok');
    function press(node, focusFirst) { // our own synthetic click must pass the capture handlers below
      replay = true;
      try { if (focusFirst) node.focus(); node.click(); } finally { replay = false; }
    }
    // while a transition runs the ::view-transition overlay swallows clicks (hit-testing lands on <html>): end it on the first
    // press and replay that press on whatever control is underneath
    doc.addEventListener('pointerdown', function (ev) {
      if (!vt.busy || !vt.cur || ev.target !== root) return;
      try {
        vt.cur.skipTransition();
        var hit = doc.elementFromPoint(ev.clientX, ev.clientY), l = hit && hit.closest ? hit.closest('#filters label, #reset-filters') : null;
        if (l) l.click();
      } catch (e) { /* the click is simply lost, as without the transition */ }
    }, true);
    // a click that goes through natively (a transition is running) must beat any earlier click still waiting for its transition
    doc.addEventListener('change', function (ev) {
      if (!replay && ev.target && ev.target.matches && ev.target.matches('#filters input.rb')) fgen++;
    }, true);
    // pointer / touch click on a chip label or the reset button
    doc.addEventListener('click', function (ev) {
      if (replay || ev.defaultPrevented || ev.button || !vtOn()) return;
      var t = ev.target;
      if (!t || !t.closest) return;
      var l = t.closest('#filters label');
      var radio = l && l.control && l.control.type === 'radio' ? l.control : null;
      var reset = !radio && t.closest('#reset-filters'), tk = fgen;
      if (radio) {
        if (radio.checked) return;
        ev.preventDefault(); // the label would flip the radio before the old state is captured
        viewTransition('flow-vt-filter', function () { if (tk === fgen) press(radio, true); });
      } else if (reset) {
        ev.preventDefault(); ev.stopImmediatePropagation();
        viewTransition('flow-vt-filter', function () { if (tk === fgen) press(reset, false); });
      }
    }, true);
    // arrow keys move + check a radio in the group natively; reproduce that (wrap-around) inside the transition
    doc.addEventListener('keydown', function (ev) {
      if (replay || ev.defaultPrevented || ev.altKey || ev.ctrlKey || ev.metaKey || ev.shiftKey || !vtOn()) return;
      var k = ev.key, d = k === 'ArrowRight' || k === 'ArrowDown' ? 1 : k === 'ArrowLeft' || k === 'ArrowUp' ? -1 : 0, r = ev.target;
      if (!d || !r || !r.matches || !r.matches('#filters input.rb')) return;
      var set = Array.prototype.slice.call(r.closest('fieldset').querySelectorAll('input.rb'));
      var n = set[(set.indexOf(r) + d + set.length) % set.length], tk = fgen;
      if (!n || n === r) return;
      ev.preventDefault();
      viewTransition('flow-vt-filter', function () { if (tk === fgen) press(n, true); });
    }, true);
  }
  enhance(initLegendHover);
  enhance(initFilterFlow);
  enhance(initRows);
  enhance(initTabs);
  enhance(initStrip);

  syncFilters();
  var sm = /(?:^#|&)sample=(perfect|mixed)(?:&|$)/.exec(location.hash);
  if (sm) loadSample(sm[1]);
})();
