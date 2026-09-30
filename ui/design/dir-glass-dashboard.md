# Direction: glass-dashboard

Soft gradient page, translucent "glass" cards, depth via transform + shadow, bento grid of CSS-drawn charts. System font stack only, no images, no external requests. Output stays ONE `public/index.html` (built from `ui/src/`).

## Palette tokens (light | dark)
All contrast ratios computed (WCAG, sRGB) against the composited card (card rgba over the page gradient's worse stop).
| token | light | dark | notes |
|---|---|---|---|
| `--bg-a` / `--bg-b` | #e4edf9 / #e3f4ef | #0c1422 / #0e1f24 | 160deg page gradient |
| `--card` | rgba(255,255,255,.72) -> #f7fafd | rgba(28,40,58,.62) -> #162031 | glass; solid fallback #fff / #1c283a |
| `--text` | #14202e (15.7:1) | #e9eef5 (14.0:1) | |
| `--muted` | #4a5a6e (6.7:1) | #a7b4c5 (7.8:1) | |
| `--accent` / `--on-accent` | #1552b3 / #fff (7.3:1 pair, 6.9 on card) | #7fb0ff / #0a1524 (8.3:1 pair, 7.4 on card) | |
| status TEXT pass/warn/fail | #0a6390 6.3 / #8a5300 6.0 / #b3261e 6.2 | #8cc4f0 8.8 / #f2c05a 9.7 / #ff8f86 7.4 | on 14% tinted pill: min 4.95 light, 5.76 dark |
| info / skip text | #2b5a94 6.7 / #566270 5.9 | #8fb6ea 7.8 / #a7b4c5 7.8 | |
| status MARK (fills) pass/warn/fail | #0b6f9e (5.3:1) / #d19000 (2.6:1)  / #b3261e | #3a94d0 / #c28400 / #d63f3f | ring, donut, heat cells |
Marks were run through the dataviz validator (`--pairs all`). Light: all PASS (worst CVD dE 19.7, normal 24.1; warn 2.6:1 is the "relief" case, always labelled). Dark: PASS, CVD WARN 7.8 (legal only with secondary encoding: 2px gaps, icons, labels, always present). Pass is deliberately BLUE not green: green/amber/red failed CVD (deutan dE 1.4). Status is never color-only (icon + word + count).
Text tokens and mark tokens are separate (text never wears the series color).

## Type, spacing, radius, shadow
- Font `system-ui,-apple-system,"Segoe UI",sans-serif`; mono `ui-monospace,Consolas`. Scale (rem): 0.75 / 0.875 / 1 / 1.125 / 1.5 / 2.25 (grade) / 3.5 (ring number, `clamp(2.5rem,9vw,3.5rem)`). Weights 400/600/800; numbers `font-variant-numeric:tabular-nums`.
- Spacing 4-pt scale: `--s1..--s6` = 0.25/0.5/0.75/1/1.5/2 rem. Radius `--r-s:8px`, `--r-m:16px`, `--r-l:24px`, pill 999px.
- Shadow: `--sh-1:0 1px 2px rgb(0 0 0/.06),0 8px 24px rgb(20 40 80/.10)`; hover `--sh-2` deeper. Dark uses higher alpha + 1px inner top highlight. Card border 1px `color-mix(in srgb,var(--text) 12%,transparent)`.
- `backdrop-filter:blur(14px) saturate(1.2)` inside `@supports`; otherwise solid card.

## Motion
- Tokens: `--dur-1:150ms` (hover/press), `--dur-2:320ms` (accordion, filters), `--dur-3:900ms` (ring/bars/donut fill). Easings: `--ease-out:cubic-bezier(.2,.8,.2,1)`, `--ease-io:cubic-bezier(.65,0,.35,1)`.
- Only transform, opacity, registered custom props (`@property --p{syntax:'<integer>'}`, `--fill{syntax:'<percentage>'}`). No layout properties animated (bars use `scaleX`, accordion uses `grid-template-rows` 0fr->1fr in a `@supports`, else instant).
- On scan complete (JS only sets `data-state="done"` on `#results` and per-item `--v`, `--i` via CSSOM): 1) cards rise in (translateY 12px, opacity, stagger `calc(var(--i)*60ms)`); 2) ring sweeps 0->score with count-up over 900ms; 3) bars grow, stagger 40ms; 4) donut segments sweep; 5) heat cells pop (scale .6->1, stagger 12ms, capped at 400ms total). Hover: card `translateY(-2px)`, `--sh-2`.
- `prefers-reduced-motion:reduce`: all `animation:none;transition:none`, elements at final state (final values are the base rules, the animation only defines `from`).

## How each piece is drawn (pure CSS; JS = `--v`/`--i`, textContent, classes)
- Grade ring: `div.ring{--p:0; background:conic-gradient(var(--mark) calc(var(--p)*1%),var(--track) 0); mask:radial-gradient(farthest-side,#0000 calc(100% - 12px),#000 0)}`; JS sets `--p` (integer 0-100); `@keyframes count{from{--p:0}}` animates the registered property; centre text is `counter(p)` via `counter-reset:p var(--p)` + `::after{content:counter(p)}` over a real `<span>` with the grade letter and a visually-hidden "score 87 of 100". Fallback without `@property`: static conic at final value, number as plain text.
- Category bars: `<li>` with a real number + `span.fill{transform:scaleX(calc(var(--v)/100));transform-origin:left}`, animated from `scaleX(0)`; the `--v` value comes from CSSOM. Track = `--track`.
- Donut pass/warn/fail: one conic-gradient with 3 hard stops from `--p1`, `--p2` (registered `<percentage>`), 2px gap via `--surface` stops, hole via mask; centre shows total counted findings; legend list below with icon + word + count (`✔ Pass 61`).
- Severity heat-grid: CSS grid `repeat(auto-fill,minmax(14px,1fr))`, one `<li>` per finding sorted by category; hue = status mark token, intensity = severity via `color-mix(in srgb,var(--mark) calc(var(--sev)*16% + 20%),transparent)`; `title` + `aria-label` per cell; grid is `role="img"` with a text summary, detail lives in the accordion.
- Findings accordion: `<details name="cat">`-style per category (open by default for fail/warn); chevron rotates via `transform`; body reveals with `::details-content` transition where supported. Summary shows count badges.
- Category tabs + status filter: radio inputs (visually hidden, still focusable, `:focus-visible` ring on the label) and `#results:has(#f-fail:checked) [data-s]:not([data-s=fail]){display:none}`. Without `:has`, `@supports not selector(:has(*))` shows all findings and JS toggles `hidden`.
- Loading: `#results[aria-busy=true]` shows skeleton cards (same dimensions, so no layout shift), shimmer = `translateX` of a gradient pseudo-element; scan button gets an indeterminate bar (`scaleX` loop). Status text stays in an `aria-live` region.

## Layout
- 375px: single column, 16px gutters, order: form, ring (grade Security + Quality side by side, 2x ring 120px), donut, bars (1 col), heat-grid (cells 14px), filters as horizontally wrapping chips (min 44px tall), accordion, deep-scan card. No horizontal scroll; `code` wraps (`overflow-wrap:anywhere`).
- 1200px: `max-width:72rem`, 12-col bento grid: ring Security (3) + ring Quality (3) + donut (3) + meta/actions (3); row 2: bars (7) + heat-grid (5); findings full width in 2 columns of categories; deep-scan card full width. Breakpoints 640px and 960px via `@media (min-width)`.
- Reserved sizes for every chart (aspect-ratio / fixed heights) so results appearing does not shift the form.

## Risks
- `@property` / `:has` / `::details-content` gaps (older Firefox/Safari): covered by `@supports`, static final render.
- Glass over busy gradient can drop text contrast: text sits only on the composited card (measured above); solid fallback if `backdrop-filter` is missing.
- Blue-for-pass departs from the green convention; icon + word mitigate. Alternative: green with texture fill (more CSS).
- Warn mark on light is 2.6:1 (relief case): always paired with a warn label/count, never alone.
- Heat-grid with hundreds of cells (138 findings max) is cheap, but stagger must be capped; blur on many cards costs GPU on low-end phones (limit blur to the 4 top-level cards).
- CSP: stylesheet is hashed inline only; no `style=""`, all dynamic values via `style.setProperty`.
