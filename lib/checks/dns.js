import { isIP } from 'node:net';
import { finding } from '../score.js';

export const IDS = ['dns-caa', 'dns-dnssec', 'dns-ns-count', 'dns-ipv6', 'mail-mx', 'mail-spf-present', 'mail-spf-single',
  'mail-spf-all', 'mail-spf-lookups', 'mail-dmarc-present', 'mail-dmarc-policy', 'mail-dmarc-rua', 'mail-mta-sts',
  'mail-tls-rpt', 'mail-dkim'];

const T = { // id -> [title, severity]
  'dns-caa': ['CAA records restrict certificate issuance', 2], 'dns-dnssec': ['DNSSEC enabled', 2],
  'dns-ns-count': ['At least two nameservers', 2], 'dns-ipv6': ['IPv6 (AAAA) record', 1],
  'mail-mx': ['MX records', 1], 'mail-spf-present': ['SPF record present', 4],
  'mail-spf-single': ['Single SPF record', 4], 'mail-spf-all': ['SPF ends with a strict all', 4],
  'mail-spf-lookups': ['SPF DNS lookups within limit', 3], 'mail-dmarc-present': ['DMARC record present', 4],
  'mail-dmarc-policy': ['DMARC policy enforced', 4], 'mail-dmarc-rua': ['DMARC aggregate reports (rua)', 1],
  'mail-mta-sts': ['MTA-STS policy', 1], 'mail-tls-rpt': ['TLS-RPT reporting', 1], 'mail-dkim': ['DKIM selector found', 1],
};
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 'mail'];

// Resolver wrapper: {v} on success, {err} on any DNS error.
const q = async (fn) => { try { return { v: await fn() }; } catch (e) { return { err: e.code || 'ERR' }; } };
// Names to try, longest first: the host, then each parent down to two labels (the org domain). Capped for many-label hosts.
function climbNames(host) {
  const l = host.split('.');
  const all = l.map((_, i) => l.slice(i).join('.')).filter((d, i) => i === 0 || d.includes('.'));
  return all.length > 6 ? [all[0], ...all.slice(-4)] : all;
}
// First name whose answer passes `ok` (RFC 8659 tree climb for CAA; org-domain fallback for mail records), else the host's own answer.
async function climb(names, fn, ok = (v) => v.length) {
  const rs = await Promise.all(names.map(async (d) => ({ d, r: await q(() => fn(d)) })));
  return rs.find((x) => x.r.v && ok(x.r.v)) || rs[0];
}
const isDmarc = (s) => /^v=DMARC1/i.test(s.trim());
const isSpf = (s) => /^v=spf1(\s|$)/i.test(s.trim());
const tags = (rec) => Object.fromEntries(rec.split(';').map((p) => p.trim()).filter(Boolean).map((p) => {
  const i = p.indexOf('=');
  return [p.slice(0, i).trim().toLowerCase(), p.slice(i + 1).trim()];
}));

// Approximate RFC 7208 lookup count: include/redirect are followed, a/mx/ptr/exists count as 1 each.
async function spfLookups(txt, rec, seen, depth = 0) {
  if (depth > 10) return 11;
  let n = 0;
  for (const t of rec.trim().split(/\s+/).slice(1)) {
    const m = /^[+\-~?]?(include|redirect|exists|a|mx|ptr)(?:[:=/](.*))?$/i.exec(t);
    if (!m) continue;
    n++;
    const kind = m[1].toLowerCase();
    if ((kind === 'include' || kind === 'redirect') && m[2] && !seen.has(m[2].toLowerCase())) {
      seen.add(m[2].toLowerCase());
      const r = await q(() => txt(m[2]));
      const sub = (r.v || []).find(isSpf);
      if (sub) n += await spfLookups(txt, sub, seen, depth + 1);
    }
    if (n > 10) return n;
  }
  return n;
}

export async function run(ctx) {
  const out = [];
  const host = ctx.target.host;
  const R = ctx.resolve;
  const add = (id, status, evidence = '', fix = '') =>
    out.push(finding(id, id.startsWith('mail') ? 'mail' : 'dns', T[id][0], status, T[id][1], { evidence, fix: status === 'pass' ? '' : fix }));
  const skip = (id, err) => add(id, 'skipped', `error: ${err}`);

  // IP literals have no DNS records to check.
  if (isIP(host.replace(/^\[|\]$/g, ''))) {
    for (const id of IDS) add(id, 'skipped', 'IP address: no DNS/mail checks');
    return out;
  }
  // CAA, SPF, MX and DMARC are looked up at the host, then its parents (a www host inherits the domain's records).
  const names = climbNames(host);
  const [caaAt, ns, aaaa, mxAt, spfAt, dmarcAt, mta, rpt] = await Promise.all([
    climb(names, (d) => R.caa(d)), q(() => R.ns()), q(() => R.aaaa()), climb(names, (d) => R.mx(d)),
    climb(names, (d) => R.txt(d), (v) => v.some(isSpf)),
    climb(names.map((d) => `_dmarc.${d}`), (d) => R.txt(d), (v) => v.some(isDmarc)),
    q(() => R.txt(`_mta-sts.${host}`)), q(() => R.txt(`_smtp._tls.${host}`)),
  ]);
  const caa = caaAt.r, mx = mxAt.r, spfTxt = spfAt.r;
  const at = (d) => (d === host ? '' : ` (at ${d})`);
  const dnssec = typeof R.dnssec === 'function' ? await q(() => R.dnssec()) : null;

  if (caa.err) skip('dns-caa', caa.err);
  else add('dns-caa', caa.v.length ? 'pass' : 'warn', caa.v.length ? `${caa.v.length} CAA record(s): ${[...new Set(caa.v.map((c) => c.tag))].join(', ')}${at(caaAt.d)}` : 'no CAA records',
    'Add CAA records naming the CAs allowed to issue certificates.');

  if (!dnssec || dnssec.err || dnssec.v?.status === 'unknown') add('dns-dnssec', 'skipped', dnssec?.err ? `error: ${dnssec.err}` : 'DNSSEC status unknown (best effort)');
  else add('dns-dnssec', dnssec.v.status === 'signed' ? 'pass' : 'warn', `zone is ${dnssec.v.status}`, 'Enable DNSSEC signing at the registrar and DNS host.');

  if (ns.err) skip('dns-ns-count', ns.err);
  else if (!ns.v.length) add('dns-ns-count', 'skipped', 'no NS records at this name (subdomain?)');
  else add('dns-ns-count', ns.v.length < 2 ? 'warn' : 'pass', `${ns.v.length} nameserver(s)`, 'Use at least two nameservers.');

  if (aaaa.err) skip('dns-ipv6', aaaa.err);
  else add('dns-ipv6', aaaa.v.length ? 'pass' : 'info', aaaa.v.length ? 'AAAA present' : 'no AAAA record', 'Consider adding IPv6 support.');

  // Null MX ("0 .") means "no mail", so it counts as no MX
  const mxs = (mx.v || []).filter((m) => m.exchange && m.exchange !== '.');
  const hasMx = mxs.length > 0;
  if (mx.err) skip('mail-mx', mx.err);
  else add('mail-mx', hasMx ? 'pass' : 'info', hasMx ? `${mxs.length} MX record(s)${at(mxAt.d)}` : "no MX (no mail expected? add null MX '0 .')");

  // SPF
  const spfs = (spfTxt.v || []).filter(isSpf);
  if (spfTxt.err) for (const id of ['mail-spf-present', 'mail-spf-single', 'mail-spf-all', 'mail-spf-lookups']) skip(id, spfTxt.err);
  else {
    if (!spfs.length) add('mail-spf-present', hasMx ? 'fail' : 'warn', 'no SPF record', 'Publish a v=spf1 TXT record ending in -all.');
    else add('mail-spf-present', 'pass', `SPF record found${at(spfAt.d)}`);
    if (!spfs.length) for (const id of ['mail-spf-single', 'mail-spf-all', 'mail-spf-lookups']) add(id, 'skipped', 'no SPF record');
    else {
      add('mail-spf-single', spfs.length > 1 ? 'fail' : 'pass', `${spfs.length} SPF record(s)`, 'Merge SPF records into exactly one.');
      // follow redirect= when the record itself has no all mechanism
      let rec = spfs[0];
      for (let i = 0; i < 5 && !/\sall$|\s[+\-~?]all(\s|$)/i.test(rec); i++) {
        const red = /\sredirect=(\S+)/i.exec(rec);
        const r = red && (await q(() => R.txt(red[1]))).v;
        const next = r?.find(isSpf);
        if (!next) break;
        rec = next;
      }
      const all = /(?:^|\s)([+\-~?]?)all(?:\s|$)/i.exec(rec)?.[1];
      if (all === undefined) add('mail-spf-all', 'fail', 'no all mechanism', 'End the SPF record with -all.');
      else if (all === '-') add('mail-spf-all', 'pass', '-all');
      else if (all === '~') add('mail-spf-all', 'warn', '~all (softfail)', 'Switch ~all to -all once senders are covered.');
      else add('mail-spf-all', 'fail', `${all || '+'}all allows anyone`, 'Use -all instead.');
      const n = await spfLookups((name) => R.txt(name), spfs[0], new Set([spfAt.d]));
      add('mail-spf-lookups', n > 10 ? 'fail' : n >= 8 ? 'warn' : 'pass', `~${n} DNS-lookup mechanism(s), limit 10 (approximate)`, 'Reduce include/a/mx mechanisms to stay within 10 lookups.');
    }
  }

  // DMARC
  const dmarc = (dmarcAt.r.v || []).find(isDmarc);
  if (!dmarc && dmarcAt.r.err) for (const id of ['mail-dmarc-present', 'mail-dmarc-policy', 'mail-dmarc-rua']) skip(id, dmarcAt.r.err);
  else if (!dmarc) {
    add('mail-dmarc-present', hasMx ? 'fail' : 'warn', 'no DMARC record', 'Publish a v=DMARC1 TXT record at _dmarc.<domain>.');
    for (const id of ['mail-dmarc-policy', 'mail-dmarc-rua']) add(id, 'skipped', 'no DMARC record');
  } else {
    add('mail-dmarc-present', 'pass', `found at ${dmarcAt.d}`);
    const t = tags(dmarc);
    const p = (t.p || '').toLowerCase(), sp = (t.sp || p).toLowerCase();
    const pct = t.pct === undefined ? 100 : Number(t.pct);
    const rank = { none: 0, quarantine: 1, reject: 2 };
    if (!(p in rank)) add('mail-dmarc-policy', 'fail', 'missing or invalid p= tag', 'Set p=quarantine or p=reject.');
    else if (p === 'none') add('mail-dmarc-policy', 'fail', 'p=none (monitoring only)', 'Move to p=quarantine or p=reject.');
    else if (pct < 100 || (sp in rank && rank[sp] < rank[p])) add('mail-dmarc-policy', 'warn', `p=${p}, pct=${pct}, sp=${sp}`, 'Apply the policy to 100% of mail and subdomains.');
    else add('mail-dmarc-policy', 'pass', `p=${p}`);
    add('mail-dmarc-rua', t.rua ? 'pass' : 'warn', t.rua ? 'rua present' : 'no rua= tag', 'Add rua=mailto:... to receive aggregate reports.');
  }

  add('mail-mta-sts', mta.err || !(mta.v || []).some((s) => /^v=STSv1/i.test(s.trim())) ? 'info' : 'pass',
    (mta.v || []).some((s) => /^v=STSv1/i.test(s.trim())) ? 'MTA-STS TXT present' : 'no MTA-STS TXT record', 'Consider publishing an MTA-STS policy.');
  add('mail-tls-rpt', rpt.err || !(rpt.v || []).some((s) => /^v=TLSRPTv1/i.test(s.trim())) ? 'info' : 'pass',
    (rpt.v || []).some((s) => /^v=TLSRPTv1/i.test(s.trim())) ? 'TLS-RPT TXT present' : 'no TLS-RPT TXT record', 'Consider publishing a TLS-RPT record.');

  // DKIM: best effort over common selectors only
  const dk = await Promise.all(DKIM_SELECTORS.map(async (s) => ({ s, r: await q(() => R.txt(`${s}._domainkey.${host}`)) })));
  const found = dk.filter((d) => (d.r.v || []).some((x) => /v=DKIM1|p=/i.test(x))).map((d) => d.s);
  add('mail-dkim', found.length ? 'pass' : 'info', found.length ? `selector(s): ${found.join(', ')}` : 'selector unknown, cannot conclude', 'Publish DKIM keys and sign outgoing mail.');

  return IDS.map((id) => out.find((f) => f.id === id));
}
