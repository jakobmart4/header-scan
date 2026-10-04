// Scans the fixture sites ('good', 'bad', ...) offline and prints their scores and every non-pass finding.
// Usage: node scripts/score-fixtures.mjs [mode ...]   (default: good bad)
process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
const { scan } = await import('../lib/scan.js');
const { start, stubResolve } = await import('../test/fixture-server.js');

for (const mode of process.argv.slice(2).length ? process.argv.slice(2) : ['good', 'bad']) {
  const srv = await start({ mode });
  try {
    const r = await scan({ url: srv.url + '/', resolve: stubResolve(), allowPrivate: true });
    console.log(`\n== ${mode}: security ${JSON.stringify(r.score.security)} quality ${JSON.stringify(r.score.quality)}`);
    console.log('categories', JSON.stringify(r.score.categories));
    for (const f of r.findings) if (f.status !== 'pass' && f.status !== 'skipped') console.log(`  ${f.status.padEnd(5)} ${f.id}: ${String(f.evidence || '').slice(0, 80)}`);
  } finally { await srv.close(); }
}
