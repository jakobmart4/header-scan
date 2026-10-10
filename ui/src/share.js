// Share links and compare (no server storage). The whole report travels in the URL fragment (#r=<token>), which the browser
// never sends to a server: token = base64url(deflate-raw(JSON)). Everything decoded here is untrusted: parse() rebuilds a fresh
// object with only the fields the UI renders, so ref links and raw headers from a link or file are never shown.
// Kept free of DOM code and at the top level (var HS) so test/share.test.js can load it in a vm context.
var HS = (function () {
  'use strict';
  // MAX_JSON bounds only the link path: decode() stops reading there (deflate bomb guard) and encode() refuses with 'too large'
  // above it, so no link is handed out that would not open. The per-field caps below bound parse() for files too and can add up
  // to more than MAX_JSON (300 findings at every cap, or escaped text); such a report still compares from a file but is too large
  // for a link, and the UI says exactly that. Real reports (<= 144 findings, mostly short evidence) stay far below it.
  var MAX_TOKEN = 32768, MAX_JSON = 262144, MAX_FINDINGS = 300;
  // The server takes up to 2048 input characters (lib/ssrf.js parseTarget) but reports the normalised href, where one UTF-16
  // unit can grow to 9 characters (a 3-byte UTF-8 character percent-encoded: U+4E2D -> %E4%B8%AD).
  var MAX_URL = 2048 * 9;
  // Active probes (lib/checks/probes.js: exp-probes-gate, exp-probe-*) run only in a deep scan.
  var DEEP_ONLY = /^exp-probe/;
  var STATUS = ['fail', 'warn', 'info', 'pass', 'skipped'];
  var CATS = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'seo', 'ai', 'ux', 'exposure'];
  var GRADES = ['A+', 'A', 'B', 'C', 'D', 'E', 'F', 'N/A'];
  // messages never echo the input
  function bad(m) { throw new Error(m); }
  function str(v, max, what) { if (typeof v !== 'string' || v.length > max) bad('bad ' + what); return v; }
  function int(v, lo, hi, what) { if (!Number.isInteger(v) || v < lo || v > hi) bad('bad ' + what); return v; }
  function pick(v, list, what) { if (list.indexOf(v) < 0) bad('bad ' + what); return v; }
  function obj(v, what) { if (!v || typeof v !== 'object' || Array.isArray(v)) bad('bad ' + what); return v; }
  function list(v, max, what) { if (!Array.isArray(v) || v.length > max) bad('bad ' + what); return v; }
  function group(v) {
    obj(v, 'score');
    var o = { score: v.score === null ? null : int(v.score, 0, 100, 'score'), grade: pick(v.grade, GRADES, 'grade') };
    if (v.cappedBy !== undefined) o.cappedBy = list(v.cappedBy, MAX_FINDINGS, 'score').map(function (x) { return str(x, 64, 'score'); });
    return o;
  }

  // untrusted report (scan JSON, downloaded file or decoded link) -> new object; throws Error('bad ...') on anything off-shape
  function parse(r) {
    obj(r, 'report');
    var s = obj(r.score, 'score'), cats = obj(s.categories, 'score');
    var out = {
      url: str(r.url, MAX_URL, 'url'), host: str(r.host, 253, 'host'), scannedAt: str(r.scannedAt, 40, 'time'),
      durationMs: int(r.durationMs, 0, 3600000, 'duration'), verified: false, deep: r.deep === true, rawHeaders: [],
      score: { security: group(s.security), quality: group(s.quality), categories: {} }, findings: [], errors: [], shared: true
    };
    CATS.forEach(function (c) {
      if (cats[c] === undefined) return;
      var x = obj(cats[c], 'score'), o = out.score.categories[c] = { score: x.score === null ? null : int(x.score, 0, 100, 'score') };
      STATUS.forEach(function (k) { o[k] = int(x[k], 0, 1000, 'score'); });
    });
    if (r.errors !== undefined) {
      out.errors = list(r.errors, 20, 'errors').map(function (e) {
        obj(e, 'errors');
        return { module: str(e.module, 40, 'errors'), message: str(e.message, 200, 'errors') };
      });
    }
    var seen = Object.create(null);
    out.findings = list(r.findings, MAX_FINDINGS, 'findings').map(function (f) {
      obj(f, 'finding');
      var id = str(f.id, 64, 'id');
      if (seen[id]) bad('duplicate id');
      seen[id] = 1;
      var o = {
        id: id, category: pick(f.category, CATS, 'category'), title: str(f.title, 200, 'title'), status: pick(f.status, STATUS, 'status'),
        severity: int(f.severity, 1, 5, 'severity'),
        evidence: f.evidence === undefined ? '' : str(f.evidence, 400, 'evidence'), fix: f.fix === undefined ? '' : str(f.fix, 400, 'fix')
      };
      if (f.checklist !== undefined) o.checklist = int(f.checklist, 1, 999, 'checklist');
      return o;
    });
    return out;
  }

  function b64u(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  // report -> token. Throws when the report would not decode again (off-shape or over the size limit).
  async function encode(r) {
    var c = Object.assign({}, r);
    delete c.rawHeaders; delete c.shared; delete c.sample;
    c.findings = (r.findings || []).map(function (f) { var g = Object.assign({}, f); delete g.ref; return g; });
    var json = JSON.stringify(c), bytes = new TextEncoder().encode(json);
    if (bytes.length > MAX_JSON) bad('too large');
    parse(JSON.parse(json));
    var z = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
    var tok = b64u(new Uint8Array(await new Response(z).arrayBuffer()));
    if (tok.length > MAX_TOKEN) bad('too large');
    return tok;
  }
  // token -> parse()d report. The decompressed size is counted while reading, so a deflate bomb stops at MAX_JSON.
  async function decode(tok) {
    if (typeof tok !== 'string' || !tok || tok.length > MAX_TOKEN || tok.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(tok)) bad('bad link');
    var bin = atob(tok.replace(/-/g, '+').replace(/_/g, '/')), u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    var rd = new Blob([u]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader(), parts = [], n = 0;
    for (;;) {
      var x = await rd.read();
      if (x.done) break;
      n += x.value.length;
      if (n > MAX_JSON) { rd.cancel().catch(function () {}); bad('too large'); }
      parts.push(x.value);
    }
    var all = new Uint8Array(n), o = 0;
    parts.forEach(function (p) { all.set(p, o); o += p.length; });
    return parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all)));
  }
  // pasted text or location.hash -> token: the r= part of a fragment, '' when a fragment has none, else the text itself
  // (a bare token). Split, not a regex: linear on any input.
  function token(text) {
    var s = String(text).trim(), i = s.indexOf('#');
    if (i < 0) return s;
    var parts = s.slice(i + 1).split('&');
    for (var k = 0; k < parts.length; k++) if (parts[k].slice(0, 2) === 'r=') return parts[k].slice(2);
    return '';
  }

  function problem(s) { return s === 'fail' || s === 'warn'; }
  // old = earlier report, cur = current one; findings matched by id. fixed: fail/warn -> pass/info; added: a new fail/warn;
  // changed: fail <-> warn; same: status unchanged; other: any other move (skipped is never "fixed"); gone: only in old.
  // depth: deep-only findings left out because one report is a deep scan and the other is not (they are not new or gone).
  // delta: score change per group, null when a score is n/a or (Security) the depths differ.
  function compare(old, cur) {
    var m = Object.create(null), out = { fixed: [], added: [], changed: [], same: 0, other: 0, gone: 0, depth: 0 };
    function keep(f) { if (old.deep !== cur.deep && DEEP_ONLY.test(f.id)) { out.depth++; return false; } return true; }
    old.findings.filter(keep).forEach(function (f) { m[f.id] = f; });
    cur.findings.filter(keep).forEach(function (f) {
      var o = m[f.id];
      delete m[f.id];
      if (!o) { if (problem(f.status)) out.added.push({ f: f, from: '' }); else out.other++; return; }
      if (o.status === f.status) { out.same++; return; }
      var row = { f: f, from: o.status };
      if (problem(o.status) && (f.status === 'pass' || f.status === 'info')) out.fixed.push(row);
      else if (!problem(o.status) && problem(f.status)) out.added.push(row);
      else if (problem(o.status) && problem(f.status)) out.changed.push(row);
      else out.other++;
    });
    out.gone = Object.keys(m).length;
    // Score deltas (null = not comparable). Probe findings score in Security only, so its delta is withheld across depths.
    out.delta = {};
    ['security', 'quality'].forEach(function (k) {
      var a = old.score[k].score, b = cur.score[k].score;
      out.delta[k] = a === null || b === null || (k === 'security' && old.deep !== cur.deep) ? null : b - a;
    });
    return out;
  }

  return { parse: parse, encode: encode, decode: decode, token: token, compare: compare };
})();
