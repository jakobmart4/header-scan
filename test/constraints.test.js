// Guards settled decisions: no npm dependencies, Render free plan, and HEADERSCAN_ALLOW_PRIVATE (turns off the SSRF rules) never in deploy config.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (f) => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

test('package.json has no dependencies of any kind', () => {
  const pkg = JSON.parse(read('package.json'));
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) assert.ok(!(k in pkg), k);
});

test('render.yaml stays on the free plan and never sets ALLOW_PRIVATE', () => {
  const y = read('render.yaml');
  assert.match(y, /^\s*plan: free\s*$/m);
  assert.doesNotMatch(y, /ALLOW_PRIVATE/);
});

test('Dockerfile runs as the node user and never sets ALLOW_PRIVATE', () => {
  const d = read('Dockerfile');
  assert.match(d, /^USER node\s*$/m);
  assert.doesNotMatch(d, /ALLOW_PRIVATE/);
});
