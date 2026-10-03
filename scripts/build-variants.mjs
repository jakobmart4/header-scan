// 'current' = the real UI incl. ui/src/skin.css; 'editorial' = the old baseline without the skin.
// Builds design/preview/<variant>.html from the real UI + ui/variants/<variant>.css, with fetch stubbed to design/sample.json,
// plus design/preview/index.html (side-by-side board). Preview only: not deployed (dist/ and public/ are untouched).
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rd = (...p) => readFileSync(join(root, ...p), 'utf8').replace(/\r\n?/g, '\n');
const BASE = ['tokens.css', 'base.css', 'layout.css', 'gauge.css', 'charts.css', 'findings.css', 'panels.css'];
const sample = JSON.stringify(JSON.parse(rd('design', 'sample.json')));
const vdir = join(root, 'ui', 'variants');
const variants = ['current', 'editorial', ...readdirSync(vdir).filter((f) => f.endsWith('.css')).map((f) => f.slice(0, -4)).sort(), ...(readdirSync(vdir).some((f) => f.startsWith('x-')) ? ['x-all'] : [])];
const layers = readdirSync(vdir).filter((f) => f.startsWith('x-') && f.endsWith('.css')).map((f) => f.slice(0, -4));
mkdirSync(join(root, 'design', 'preview'), { recursive: true });

const stub = `<script>(function(){var S=${sample};var f=window.fetch;window.fetch=function(u,o){return String(u).indexOf('/api/scan')===0?Promise.resolve(new Response(JSON.stringify(S),{status:200,headers:{'content-type':'application/json'}})):f.apply(this,arguments)};
addEventListener('DOMContentLoaded',function(){setTimeout(function(){var i=document.getElementById('url');i.value='demo.example';document.getElementById('scan-form').dispatchEvent(new Event('submit',{cancelable:true}))},50)})})();</script>`;

for (const v of variants) {
  const layerOf = v === 'x-all' ? layers : v.startsWith('x-') ? [v] : [];
  const lay = (ext) => layerOf.filter((n) => existsSync(join(vdir, n + ext))).map((n) => rd('ui', 'variants', n + ext));
  const skin = v === 'editorial' ? [] : v.startsWith('x-') || v === 'current' ? [rd('ui', 'src', 'skin.css')] : [rd('ui', 'variants', v + '.css')];
  const css = BASE.map((f) => rd('ui', 'src', f)).concat(skin, lay('.css')).join('\n');
  const extraJs = lay('.js').map((j) => '<script>\n' + j + '\n</script>').join('\n');
  const html = rd('ui', 'src', 'index.template.html')
    .split('<!--@STYLE-->').join('<style>\n' + css + '\n</style>')
    .split('<!--@SCRIPT-->').join('<script>\n' + rd('ui', 'src', 'app.js') + '\n</script>' + extraJs + stub);
  writeFileSync(join(root, 'design', 'preview', v + '.html'), html);
}

const frames = variants.map((v) => `<figure><figcaption>${v}</figcaption><iframe src="${v}.html" title="${v}" loading="lazy"></iframe></figure>`).join('\n');
writeFileSync(join(root, 'design', 'preview', 'index.html'), `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>header-scan design variants</title>
<style>body{margin:0;font:14px system-ui;background:#222;color:#eee}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,640px),1fr));gap:12px;padding:12px}figure{margin:0}figcaption{padding:4px 2px;font-weight:600}iframe{width:100%;height:85vh;border:0;background:#fff}</style>
<main>${frames}</main>`);
console.log('variants:', variants.join(', '));
