import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { score, gradeFor, finding } from '../lib/score.js';

const F = (status, sev, cat = 'headers') => finding('x', cat, 't', status, sev);
const many = (n, status, sev, cat) => Array.from({ length: n }, () => F(status, sev, cat));

describe('finding()', () => {
  test('truncates evidence to 300 chars and validates enums', () => {
    assert.equal(finding('a', 'seo', 't', 'pass', 1, { evidence: 'x'.repeat(500) }).evidence.length, 300);
    assert.throws(() => finding('a', 'nope', 't', 'pass', 1));
    assert.throws(() => finding('a', 'seo', 't', 'nope', 1));
    assert.throws(() => finding('a', 'seo', 't', 'pass', 6));
  });
  test('optional fields only when given', () => {
    const f = finding('a', 'seo', 't', 'pass', 1, { checklist: 5, ref: 'https://x.test' });
    assert.equal(f.checklist, 5);
    assert.equal(f.ref, 'https://x.test');
    assert.equal('checklist' in finding('a', 'seo', 't', 'pass', 1), false);
  });
});

describe('score()', () => {
  test('no findings / only info+skipped -> null and N/A', () => {
    assert.deepEqual(score([]).security, { score: null, grade: 'N/A' });
    const s = score([F('info', 5), F('skipped', 5)]);
    assert.equal(s.security.score, null);
    assert.equal(s.security.grade, 'N/A');
  });
  test('info and skipped are excluded from numerator and denominator', () => {
    assert.equal(score([F('pass', 4), F('info', 5), F('skipped', 5)]).security.score, 100);
  });
  test('weights by severity, warn counts half', () => {
    assert.equal(score([F('pass', 4), F('warn', 4)]).security.score, 75);
    assert.equal(score([F('pass', 1), F('fail', 3)]).security.score, 25);
  });
  test('groups: security vs quality; per-category counts', () => {
    const s = score([F('pass', 2, 'headers'), F('fail', 2, 'seo'), F('warn', 1, 'mail'), F('info', 1, 'ai')]);
    assert.equal(s.quality.score, 0);
    assert.equal(s.categories.seo.fail, 1);
    assert.equal(s.categories.ai.info, 1);
    assert.equal(s.categories.headers.score, 100);
    assert.equal(s.categories.mail.warn, 1);
    assert.equal(s.categories.tls.score, null);
  });
  test('deterministic', () => {
    const fs = [F('pass', 3), F('warn', 2), F('fail', 1, 'seo')];
    assert.deepEqual(score(fs), score([...fs]));
  });
});

describe('grades and caps', () => {
  test('table', () => {
    const grade = (n) => score([...many(n, 'pass', 1), ...many(100 - n, 'warn', 1)]).security; // warn = 0.5 -> score = n + (100-n)/2
    assert.equal(gradeFor(95, [F('pass', 1)]), 'A');
    assert.equal(gradeFor(85, [F('pass', 1)]), 'B');
    assert.equal(gradeFor(75, [F('pass', 1)]), 'C');
    assert.equal(gradeFor(60, [F('pass', 1)]), 'D');
    assert.equal(gradeFor(45, [F('pass', 1)]), 'E');
    assert.equal(gradeFor(10, [F('pass', 1)]), 'F');
    assert.equal(gradeFor(null, []), 'N/A');
    assert.ok(grade(90).score >= 90);
  });
  test('A+ needs zero fails and zero warn with severity >= 3', () => {
    assert.equal(score([F('pass', 2), F('pass', 3)]).security.grade, 'A+');
    assert.equal(score([...many(4, 'pass', 5), F('warn', 3)]).security.grade, 'A');
    assert.equal(score([...many(40, 'pass', 5), F('warn', 1)]).security.grade, 'A+');
    assert.equal(score([...many(60, 'pass', 5), F('fail', 1)]).security.grade, 'A');
  });
  test('security caps: sev-5 fail -> D, sev-4 fail -> C, >3 fails -> D', () => {
    assert.equal(score([...many(30, 'pass', 1), F('fail', 5)]).security.grade, 'D');
    assert.equal(score([...many(30, 'pass', 1), F('fail', 4)]).security.grade, 'C');
    assert.equal(score([...many(200, 'pass', 3), ...many(4, 'fail', 1)]).security.grade, 'D');
    assert.equal(score([...many(200, 'pass', 3), ...many(3, 'fail', 1)]).security.grade, 'A');
  });
  test('quality group caps by count only, not severity', () => {
    assert.equal(score([...many(60, 'pass', 3, 'seo'), F('fail', 5, 'seo')]).quality.grade, 'A');
    assert.equal(score([...many(200, 'pass', 3, 'seo'), ...many(4, 'fail', 1, 'seo')]).quality.grade, 'D');
  });
});
