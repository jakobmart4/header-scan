# Direction: editorial-light

Printed-report feel: warm paper, near-black ink, hairline rules, big serif numerals, ONE accent (ink blue) used only for interactive things (focus, primary button, active tab/filter, links). Status colours are reserved for pass/warn/fail/info and are never used as accent. Dark theme = same layout, "night paper" (warm charcoal, not blue-black).

## Tokens (all on `:root`; dark under `@media (prefers-color-scheme: dark)`; no `data-theme` toggle needed)
Contrast ratios computed with the WCAG formula (scratch script), text/UI on `--surface`.

| token | light | dark | notes (light / dark ratio) |
|---|---|---|---|
| `--paper` (page) | `#f7f4ee` | `#141311` | ink on paper 15.7 / 15.9 |
| `--surface` (cards) | `#fffdf9` | `#1d1c19` | ink 16.9 / 14.6 |
| `--ink` | `#1c1b18` | `#f0ede6` | body text |
| `--muted` | `#5c584f` | `#aaa69b` | 6.97 / 7.01 (also 5.4 / 6.0 on `--track`) |
| `--rule` (hairlines) | `#d8d2c4` | `#3a372f` | decorative only, 1.4 / 1.6 |
| `--edge` (input/button border) | `#857f72` | `#8a8578` | 3.9 / 4.6 (WCAG 1.4.11 needs 3.0) |
| `--track` (empty bar/ring) | `#e6e1d5` | `#2b2924` | decorative |
| `--accent` / `--accent-ink` | `#1c3fa8` / `#fff` | `#8fabf5` / `#0e1633` | text 8.9 / 7.6; button label 9.0 / 7.9 |
| `--pass` on `--pass-bg` | `#1a6b3c` on `#e2f1e7` | `#6ccf98` on `#15301f` | on surface 6.4 / 8.9; pill 5.6 / 7.5 |
| `--warn` on `--warn-bg` | `#8a5300` on `#f8ebd0` | `#efbf5c` on `#382c10` | on surface 6.2 / 10.0; pill 5.4 / 8.0 |
| `--fail` on `--fail-bg` | `#b1281e` on `#f9e1de` | `#ff8c82` on `#3c1b18` | on surface 6.5 / 7.6; pill 5.3 / 6.9 |
| `--info` on `--info-bg` | `#3b5482` on `#e5eaf4` | `#9db6e6` on `#1a2739` | on surface 7.4 / 8.3; pill 6.3 / 7.4 |
Every status colour is >= 4.8:1 against `--track`, so ring/bar/donut fills pass 3:1 non-text on both the track and the surface. Skipped = `--muted`. NOT run through `validate_palette.js`: pass/warn/fail are a reserved status trio, not a categorical palette, so identity never relies on hue alone (see donut/heat-grid: counts + labels + icons `✔ ⚠ ✖ ℹ –` always in text).

Type (system stacks only): display/numerals `ui-serif, "Iowan Old Style", Georgia, serif`; body `system-ui, "Segoe UI", sans-serif`; mono `ui-monospace, Consolas`. Scale (rem): 0.75 / 0.875 / 1 / 1.25 / 1.75 / 2.5 / grade numeral `clamp(4rem, 12vw, 6rem)`. Line-height 1.5 body, 1.1 display; measure <= 68ch. Small-caps eyebrow labels (0.75rem, `letter-spacing:.08em`, uppercase, `--muted`).
Spacing (4px base): 4 8 12 16 24 32 48 72. Radius: 2px cards/inputs (print-like), 4px chips, 999px pills. Shadow: cards get `0 1px 0 var(--rule)` only; the score card alone adds `0 18px 40px -28px rgb(28 27 24 / .35)` (light) / none (dark, border instead).

## Motion principles
- Only `transform`, `opacity` and registered custom properties (`--p`, `--n`, `--a`, `--b`) animate. Never width/height/top.
- Base CSS is the FINAL state; keyframes/transitions only define the `from` side (`animation-fill-mode: backwards`). So reduced motion (`@media (prefers-reduced-motion: reduce){*,*::before,*::after{animation:none!important;transition:none!important}}`) and no-@property browsers automatically show the finished picture.
- Easing: enter `cubic-bezier(.2,.7,.2,1)`; state changes `cubic-bezier(.4,0,.2,1)`. Durations: hover/focus 120ms, filter/tab/accordion 220ms, reveal 300ms, ring/donut/count-up 900ms.
- Scan-complete choreography (JS only sets `--score`, `--i`, `--p` via `style.setProperty` and adds `.in` to `#results` on next frame): 0ms score card fades up 8px; 100ms ring sweep + count-up (same 900ms so digits and arc agree); 250ms category bars grow, stagger `calc(var(--i)*40ms)` (max 400ms); 300ms donut sweep; 400ms heat cells fade to their intensity, stagger by column `25ms`; 500ms+ findings rows fade/translate 8px, stagger capped at 300ms (`min(var(--i),10)*30ms`). Total < 1.6s; nothing loops after completion.
- Loading: an indeterminate 3px accent bar under the form (a `::after` sliding with `translateX`, 1.4s linear infinite) + `aria-busy=true` on `#results`, whose skeleton blocks (same fixed sizes as final: ring 8rem, 10 bar rows, donut 8rem, heat 5x10) shimmer via `translateX` of a gradient (1.6s). Skeletons swap for content in place, so no layout shift. Reduced motion: bar becomes a static striped rail, skeleton static.

## How each piece is drawn (pure CSS; scan values arrive as CSSOM custom props, text via textContent)
- Grade ring (Security, Quality): `@property --p {syntax:'<number>'; inherits:false; initial-value:0}` and `--n {syntax:'<integer>'...}`. `.ring{background:conic-gradient(var(--c) calc(var(--p)*1%), var(--track) 0); mask:radial-gradient(circle, #0000 58%, #000 59%); --p:var(--score); --n:var(--score); counter-reset:n var(--n)}`; `.ring::after{content:counter(n)}` shows the count-up number over the serif grade letter. `transition`/`@keyframes` from `--p:0;--n:0`. Colour `--c` by grade class (A/B pass, C/D warn, E/F fail, N/A muted). The real score and grade stay as text in the DOM (`<b>B</b><span>87 / 100</span>`, `role=img` label); the counter overlay is used only when JS sees `CSS.registerProperty` and sets `html.cp`, so nothing double-reads and old browsers just show the plain number.
- Category bars: `<ul>` of rows; `.bar` track (`overflow:hidden`) + child `transform:scaleX(calc(var(--p)/100))` `transform-origin:left`, square ends so scaling does not distort; label, `87%` text, and "2 fail, 1 warn..." tag stay as text. `n/a` rows get an empty track with a diagonal hatch (not just grey).
- Pass/warn/fail donut (counts over all findings): `--a` = pass %, `--b` = pass+warn %; `conic-gradient(var(--pass) 0 calc(var(--a)*1%), var(--surface) 0 calc(var(--a)*1% + .6%), var(--warn) 0 calc(var(--b)*1%), ...)` (hard stops + 0.6% surface gaps), same radial mask as ring, `--a`/`--b` registered so it sweeps. Beside it a legend `<dl>`: swatch + icon + label + count (info/skipped listed as plain counts, not slices). Centre text = total counted.
- Severity heat-grid: 5 rows (severity 5..1) x 10 category columns (3-letter headers with full name in `aria-label`/`title`), each cell an `<li>` = count of fail+warn findings at that severity. Intensity = `--k` (0..1, JS: count/max) on a `::before` in `--fail` with `opacity:calc(.12 + var(--k)*.78)`, capped so the number (sitting in a `--surface` chip) is always 16:1 readable; empty cell = `--track`, no chip. Cell is a `<label>` for the category radio, so clicking a column filters findings to it.
- Findings accordion: one `<details class="cat">` per category (open when it holds fail/warn) + inner `<details>` per finding (pill, title, severity `●●●○○` as text `severity 3/5`). Chevron rotates (`transform`). Height animates with `::details-content{transition:block-size 220ms, content-visibility 220ms allow-discrete}` + `interpolate-size:allow-keywords` inside `@supports`; elsewhere it toggles instantly. Evidence in `<p>`, fix in `<p class=fix>`, ref link only if `^https?://`.
- Category tabs + status filters: radio groups (`name=cat`, `name=st`) hidden with the visually-hidden pattern (still focusable, arrow-key navigable); labels styled as chips with `input:checked + label` / `:focus-visible + label`. `#results:has(#st-fail:checked) .f:not(.s-fail){display:none}` (and same for cat). Fallback: `@supports not selector(:has(*))` uses `data-cat`/`data-st` on `#results`, set by one `change` listener. A finding row `grid-template-rows:1fr->0fr` collapse is optional polish, not required.
- Ownership flow, copy/JSON buttons, deep scan panel: same DOM/logic as now, restyled as a "Deep scan" ruled section; TXT name/value in mono on `--track` with Copy buttons; verify state = pill `✔ Verified` / text message in the `aria-live` region.

## Layout
- 375px: one column, 16px gutters, no horizontal page scroll. Order: masthead, form (input full width, button below), score card (ring 8rem centred over meta, stacked Security then Quality), donut + legend, category bars (1 col), heat-grid (10 cols at ~30px, 12px labels, 4px gap = fits 343px), category chips (wrap), status chips (wrap), findings, deep scan. Touch targets >= 44px.
- 1200px: `max-width:72rem`, 12-col grid with 24px gap. Left sticky rail (cols 1-4): both rings side by side, donut, heat-grid. Right (cols 5-12): bars in 2 columns, tabs/filters, findings accordion, deep scan below. Masthead uses a big serif h1 with a hairline rule beneath; generous 48-72px vertical rhythm.

## Risks
- `@property`-driven count-up/sweep needs Chrome 85+/Safari 16.4+/Firefox 128+; without it the ring, donut and numbers still render at the final value (no animation) — must be verified by forcing the fallback path.
- `:has()` filtering and `::details-content`/`interpolate-size` are newer; the `data-*` fallback and instant toggle must be tested, not assumed.
- Contrast numbers above are computed for tokens only; heat-cell chips, hatch pattern, and hover/checked chip states are not yet measured.
- Radios + labels must keep visible focus rings (3px `--accent`, 2px offset) and screen-reader names; filtering hides rows with `display:none` so hidden findings drop out of the accessibility tree (intended).
- Filtering/tab changes shrink the list, so the results region needs a `min-height` and the status line an `aria-live` count ("12 findings shown") to avoid confusing jumps.
- Inline `<script>` size/hash: the build must recompute SHA-256 for both blocks (server.js and build-pages already do); any CSSOM `style.setProperty` is CSP-safe, but no `setAttribute('style')`.
