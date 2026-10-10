// Builds public/index.html from ui/src (see ui/DESIGN.md): one inline <style>, one inline <script>.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = (f) => join(root, 'ui', 'src', f);
const CSS = ['tokens.css', 'base.css', 'layout.css', 'gauge.css', 'charts.css', 'findings.css', 'panels.css', 'skin.css', 'skin-charts.css', 'skin-flow.css', 'skin-motion.css', 'skin-radar.css', 'skin-compact.css', 'skin-mobile.css', 'skin-tabs.css'];
const lf = (s) => s.replace(/\r\n?/g, '\n').replace(/\n+$/, '');
const fail = (m) => { console.error('build-ui: ' + m); process.exit(1); };

function read(f, name, closer) {
  if (!existsSync(src(f))) fail('missing ' + f);
  const t = lf(readFileSync(src(f), 'utf8'));
  if (closer.test(t)) fail(name + ' contains a closing tag that would end the inline block');
  return t;
}

const template = lf(readFileSync(src('index.template.html'), 'utf8'));
for (const p of ['<!--@STYLE-->', '<!--@SCRIPT-->']) {
  if (template.split(p).length !== 2) fail('placeholder ' + p + ' must appear exactly once in the template');
}

const css = [];
for (const f of CSS) {
  if (!existsSync(src(f))) { console.warn('build-ui: WARNING ' + f + ' not found, skipped'); continue; }
  css.push(read(f, f, /<\/style/i));
}
if (!css.length) fail('no CSS files found');
// share.js defines the global HS that app.js uses: it goes first, in the same inline script (one CSP hash)
const js = ['share.js', 'app.js'].map((f) => read(f, f, /<\/script/i)).join('\n');

// split/join, not String.replace: CSS/JS may contain "$&" style sequences.
const out = template
  .split('<!--@STYLE-->').join('<style>\n' + css.join('\n') + '\n</style>')
  .split('<!--@SCRIPT-->').join('<script>\n' + js + '\n</script>') + '\n';

for (const [re, what] of [[/style="/, 'inline style attribute'], [/ on[a-z]+=/, 'inline event handler'], [/innerHTML/, 'innerHTML']]) {
  if (re.test(out)) fail('output contains forbidden ' + what + ' (' + re + ')');
}

writeFileSync(join(root, 'public', 'index.html'), out);
const b = (s) => Buffer.byteLength(s);
console.log(`build-ui: public/index.html ${b(out)} bytes (css ${b(css.join('\n'))}, js ${b(js)}, template ${b(template)})`);
