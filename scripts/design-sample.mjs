// Writes design/sample.json: a real scan result of the "bad" fixture site, used by the design previews.
import { writeFileSync } from 'node:fs';
import { start, stubResolve } from '../test/fixture-server.js';
import { scan } from '../lib/scan.js';

const fx = await start({ mode: 'bad' });
try {
  const r = await scan({ url: fx.url, allowPrivate: true, resolve: stubResolve() });
  r.host = 'demo.example'; r.url = 'https://demo.example/';
  writeFileSync(new URL('../design/sample.json', import.meta.url), JSON.stringify(r, null, 1));
  console.log('findings', r.findings.length, 'score', JSON.stringify(r.score && { s: r.score.security, q: r.score.quality }).slice(0, 120));
} finally { await fx.close(); }
