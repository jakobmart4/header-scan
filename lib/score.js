// Grading per SPEC.md section 3. Pure and deterministic.
export const CATEGORIES = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'seo', 'ai', 'ux', 'exposure'];
const SECURITY = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'exposure'];
const QUALITY = ['seo', 'ai', 'ux'];
const STATUSES = ['pass', 'warn', 'fail', 'info', 'skipped'];
const EARNED = { pass: 1, warn: 0.5, fail: 0 };
const ORDER = ['F', 'E', 'D', 'C', 'B', 'A', 'A+'];

export function finding(id, category, title, status, severity, { evidence = '', fix = '', ref, checklist } = {}) {
  if (!CATEGORIES.includes(category)) throw new Error(`finding ${id}: bad category ${category}`);
  if (!STATUSES.includes(status)) throw new Error(`finding ${id}: bad status ${status}`);
  if (![1, 2, 3, 4, 5].includes(severity)) throw new Error(`finding ${id}: bad severity ${severity}`);
  const ev = String(evidence);
  const f = { id, category, title, status, severity, evidence: ev.length > 300 ? ev.slice(0, 297) + '...' : ev, fix };
  if (ref !== undefined) f.ref = ref;
  if (checklist !== undefined) f.checklist = checklist;
  return f;
}

// Weighted percentage over counted (pass/warn/fail) findings; null when nothing is countable.
function pct(findings) {
  let earned = 0, total = 0;
  for (const f of findings) {
    if (!(f.status in EARNED)) continue;
    total += f.severity;
    earned += f.severity * EARNED[f.status];
  }
  return total === 0 ? null : Math.round((100 * earned) / total);
}

// `findings` is one group's findings (security or quality); the group is inferred from categories.
export function gradeFor(score, findings) {
  if (score === null || score === undefined) return 'N/A';
  let i = score >= 97 ? 6 : score >= 90 ? 5 : score >= 80 ? 4 : score >= 70 ? 3 : score >= 55 ? 2 : score >= 40 ? 1 : 0;
  const fails = findings.filter((f) => f.status === 'fail');
  const warns = findings.filter((f) => f.status === 'warn');
  if (i === 6 && (fails.length || warns.some((f) => f.severity >= 3))) i = 5;
  const isSecurity = findings.some((f) => SECURITY.includes(f.category));
  if (isSecurity) {
    if (fails.some((f) => f.severity === 5)) i = Math.min(i, 2);
    else if (fails.some((f) => f.severity === 4)) i = Math.min(i, 3);
  }
  if (fails.length > 3) i = Math.min(i, 2);
  return ORDER[i];
}

export function score(findings) {
  const group = (cats) => {
    const fs = findings.filter((f) => cats.includes(f.category));
    const s = pct(fs);
    return { score: s, grade: gradeFor(s, fs) };
  };
  const categories = {};
  for (const c of CATEGORIES) {
    const fs = findings.filter((f) => f.category === c);
    const n = (st) => fs.filter((f) => f.status === st).length;
    categories[c] = { score: pct(fs), pass: n('pass'), warn: n('warn'), fail: n('fail'), info: n('info'), skipped: n('skipped') };
  }
  return { security: group(SECURITY), quality: group(QUALITY), categories };
}

// Tiny self-check: node lib/score.js
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const assert = (await import('node:assert/strict')).default;
  const F = (st, sev, cat = 'headers') => finding('x', cat, 't', st, sev);
  assert.equal(score([]).security.grade, 'N/A');
  assert.equal(score([F('info', 5), F('skipped', 5)]).security.score, null);
  assert.equal(score([F('pass', 4), F('warn', 4)]).security.score, 75);
  assert.equal(score([F('pass', 2), F('pass', 3)]).security.grade, 'A+');
  assert.equal(score([F('pass', 5), F('pass', 5), F('pass', 5), F('pass', 5), F('warn', 3)]).security.grade, 'A');
  const sev5 = [...Array(30).fill(0).map(() => F('pass', 1)), F('fail', 5)];
  assert.equal(score(sev5).security.grade, 'D');
  assert.equal(score([...Array(30).fill(0).map(() => F('pass', 1)), F('fail', 4)]).security.grade, 'C');
  const q = [...Array(60).fill(0).map(() => F('pass', 3, 'seo')), F('fail', 5, 'seo')];
  assert.equal(score(q).quality.grade, 'A');
  assert.throws(() => finding('x', 'nope', 't', 'pass', 1));
  assert.equal(finding('x', 'seo', 't', 'pass', 1, { evidence: 'a'.repeat(400) }).evidence.length, 300);
  console.log('score.js self-check ok');
}
