# Direction: terminal-neon (header-scan UI)

Dark-first "security terminal": mono accents, neon status colours, one radar sweep, sparing glow. Light theme is a plain, quiet twin (no glow). Single file, CSP hash-only, CSS draws everything; JS only sets `--vars`, classes, `textContent`.

## Palette tokens (contrast computed with WCAG formula, see script in session; all text/UI >= AA)
| token | dark | light |
|---|---|---|
| --bg / --surface / --surface-2 | #070b0a / #0d1412 / #142019 | #eef4f1 / #fff / #e3ece7 |
| --text | #d7efe4 (15.4 on surface) | #0c1f18 (17.2) |
| --muted | #8fb0a2 (7.9) | #3f5449 (8.2) |
| --accent (neon green/cyan) | #3df5a7 (13.2) | #006b45 (6.6) |
| --on-accent | #04140d (13.3 on accent) | #fff (6.6) |
| --pass | #3ddc97 (10.6) | #0a6b3f (6.6) |
| --warn | #ffc247 (11.6) | #7a5200 (6.9) |
| --fail | #ff6b6b (6.7) | #b3261e (6.5) |
| --info | #6cc4ff (9.8) | #0b5a99 (7.2) |
| --skip | #8fa39a (7.0) | #4a5d53 (7.0) |
| --line (input/control border, >=3:1) | #5f7a6d (4.0) | #6b8074 (4.2) |
Ratios are vs --surface. Pills: status text on 14% status/surface tint, worst case fail 5.6 dark / 5.2 light. Heat cells: --text on <=45% tint, worst 4.8 (dark warn) / 7.7 light. Rule: status colours never carry meaning alone; always icon glyph + word + number. Decorative hairlines use color-mix(--line 40%, transparent).
Theme: `prefers-color-scheme`, light overrides under `:root:not([data-theme=dark])`, `color-scheme: dark light`.

## Type, space, radius, shadow
- Fonts: body `system-ui, "Segoe UI", sans-serif`; accents/numbers/labels `ui-monospace, "Cascadia Code", Consolas, monospace`, `font-variant-numeric: tabular-nums`.
- Scale (rem): 0.75 label caps / 0.875 meta / 1 body / 1.25 h2 / 1.75 h1 / 3.25 grade glyph. Line-height 1.5 body, 1.1 display.
- Space 4px grid: 4 8 12 16 24 32 48. Radius: 2 (pills, cells), 4 (controls), 8 (cards). No pill-rounding except status pills.
- Shadow: light = `0 1px 0 var(--line)` only. Dark = 1px hairline + `0 0 16px color-mix(in srgb, var(--accent) 22%, transparent)` on the two ring cards and focused input only. Scanlines: 2px `repeating-linear-gradient` at 4% on the ring cards, static.
- Focus: `:focus-visible` 3px --accent outline, 2px offset (>=3:1 on both surfaces); radio inputs visually hidden but their labels get the ring via `:has(:focus-visible)`. Targets >= 40px.

## Motion principles
- Only transform, opacity and registered props (`--p` integer, `--sweep` angle). Ease-out `cubic-bezier(.16,1,.3,1)`; UI 150ms, reveals 350ms, ring/donut 1100ms, sweep 1400ms once.
- On scan-complete (JS adds `.in` to `#results` one frame after render): ring `--p` 0 to score with count-up; one radar sweep over each ring; category bars scaleX 0 to v (stagger 40ms x `min(--i,12)`); donut `--sweep` 0 to 360deg; heat cells fade/scale .92 to 1 (stagger by cell index); finding rows fade+translateY(8px) (stagger, cap 12, rest instant).
- Initial (hidden) states are declared ONLY inside `@media (prefers-reduced-motion: no-preference)`; base CSS = final state. Reduce: also `animation:none; transition:none` catch-all. Result: no-@property/no-motion browsers see the final static UI.
- Loading: `aria-busy` on results shell; indeterminate 2px bar (translateX of a 30%-wide pseudo-element), skeleton ring/bars/donut of identical size (opacity pulse .5-1, no shimmer bg-position), so swap has zero layout shift.

## How each piece is drawn
- Grade ring: `@property --p {syntax:'<integer>'; inherits:true; initial-value:0}`. `.ring{background:conic-gradient(var(--c) calc(var(--p)*1%), var(--track) 0); mask:radial-gradient(farthest-side, transparent calc(100% - 10px), #000 0); transition:--p 1.1s}`; JS sets `--p` (clamped Number 0..100). Count-up: `.ring{counter-reset:n var(--p)}` + `.num::after{content:counter(n)}`. The real text ("87") stays in DOM; `html.anim` (added by JS only if `CSS.registerProperty` exists) hides it (font-size 0) so unsupported browsers show the real number. `role=img` + aria-label "Security grade B, 87 of 100". Grade letter centre in mono 3.25rem, colour by grade class (A+/A/B pass, C/D warn, E/F fail, N/A skip; null score = track only). Radar sweep: `::after` conic-gradient(transparent 300deg, accent 360deg) rotate 0 to 360deg once, opacity 0.5 to 0.
- Category bars: `<li>` name + `%` text + `.bar` track; fill `transform:scaleX(var(--v))` (`--v` = score/100), origin left. Terminal segmenting via `mask: repeating-linear-gradient(90deg,#000 0 calc(10% - 2px),transparent 0 10%)`. Fill colour by band (>=80 pass, >=55 warn, else fail) via `data-band`. Below: mono `2 fail / 1 warn / 9 pass` text. n/a = empty track + "n/a".
- Donut (pass/warn/fail split; info/skipped excluded like scoring): JS sets integer `--np --nw --nf`. `conic-gradient(pass 0 calc(var(--np)/var(--t)*1turn), warn 0 ..., fail 0 ...)` with 2px surface gaps via extra hard stops; reveal by `mask: conic-gradient(#000 var(--sweep), transparent 0)` with `@property --sweep <angle>`, hole via radial mask. Centre = total, legend below as `<dl>` with glyphs. Zero total = track.
- Severity heat-grid: real `<table>`, rows severity 5..1, columns fail/warn/pass, cell text = count (mono). Tint `background: color-mix(in srgb, var(--st) calc(var(--n)/var(--max)*45%), transparent)`; `--n`,`--max` integers set by JS; 0 shows "·". Legend states the scale; not clickable.
- Findings accordion: `<details class="cat" open>`; `summary` = category, mono counts, chevron `rotate` transition. Body animates where supported: `details::details-content{block-size:0;overflow:clip;transition:block-size .25s, content-visibility .25s allow-discrete}` + `details[open]::details-content{block-size:auto}` with `interpolate-size:allow-keywords`, all in `@supports (interpolate-size:allow-keywords)`; else instant toggle. Each finding: status pill (glyph+word), title `h3`, severity dots (`radial-gradient` repeat, n of 5 lit) + "severity n/5" text, evidence, `Fix:`, link.
- Category tabs + status filters: two `fieldset`s of visually-hidden radios + `label`s. `#results:has(#c-tls:checked) .cat:not([data-c=tls]){display:none}` and `#results:has(#f-fail:checked) .fnd:not([data-s=fail]){display:none}` (generated by build-ui from the CATS/STATUSES lists). `@supports not selector(:has(*))`: JS `change` handler sets `data-c`/`data-f` on `#results` and the same rules key off `[data-f=...]`. Tab strip: horizontal scroll-snap on 375px. Empty-state line toggled by JS (`hidden`) after a change.

## Layout
- 375px: one column, 16px gutters, no horizontal page scroll. Order: form, status, two rings side by side (each ~150px, ring 128px), donut card, heat-grid card (table fits at 343px), bars 1 col, tabs (scroll strip), status filter (wraps), findings, deep-scan panel. TXT name/value `word-break:anywhere`.
- 1200px: `max-width:72rem`, 12-col grid. Row A: ring, ring, donut, heat-grid (3+3+3+3). Row B: bars in 2 columns. Row C: tabs left rail (sticky) + findings (max ~50rem). Deep-scan panel as full-width card below.
- Layout-shift control: ring/donut fixed via `aspect-ratio`, number `min-width:3ch`, skeletons match final boxes.

## Risks
1. `counter()` on an animated registered property: Firefox < 128 has no @property; handled by the `html.anim` gate (real text kept). Generated counter text is not selectable; ring carries aria-label and the inner number is `aria-hidden`.
2. `:has()` (FF < 121), `::details-content`/`interpolate-size` (Chromium-first): each behind `@supports` with static fallback; needs a real test in Firefox and Safari, only Chromium is easy to test here.
3. Neon glow/scanlines can lower perceived contrast or look gimmicky: limited to two cards, dark only; verify with forced-colors (add `@media (forced-colors:active)` borders, drop masks).
4. Combined tab+status filter can leave "empty" categories; pure CSS cannot show the empty message, so JS toggles it (accepted glue).
5. CSP: inline blocks are hashed, so build-ui output must be byte-deterministic and update hashes in server.js loadIndex / build-pages (they compute at load, so only stable output matters). No `style=` attributes anywhere; scan numbers reach CSS only through `style.setProperty` after `Number()` + clamp.
6. Segmented mask + conic masks need `-webkit-mask` prefixes for older Safari.
