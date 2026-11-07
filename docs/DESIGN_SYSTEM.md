# NULLPLINTH design system

Premium industrial minimalism for a security workbench: black surfaces, off-white type, a small
set of signal colours that mean something, and dense technical data. Every value below lives in
`src/styles/tokens.css`; components must read variables and never hardcode hex values.

## Typography

| Role | Token | Notes |
|------|-------|-------|
| Interface | `--font-ui` - Urbanist (variable, bundled) | `src/assets/fonts/Urbanist-Variable.ttf`, SIL Open Font License 1.1, no remote font service |
| Technical | `--font-mono` - Cascadia Mono / Consolas | IPs, ports, hashes, timestamps, packet bytes, raw records |
| Sizes | `--fs-xs` 11, `--fs-sm` 12, `--fs-md` 13, `--fs-lg` 15, `--fs-xl` 18, `--fs-2xl` 24, `--fs-3xl` 32, `--fs-metric` 34 | UI text is intentionally small and dense |
| Weights | `--fw-regular` 400, `--fw-medium` 500, `--fw-semibold` 600, `--fw-bold` 700 | Metrics use semibold, labels medium |
| Labels | `--tracking-label` 0.08em uppercase | Section labels, table headers |

## Colour

### Surfaces and lines
`--bg` #000000 · `--surface-1` #141414 · `--surface-2` #1C1C1C · `--surface-3` #242424 ·
`--line` #303030 · `--line-soft` #212121

### Text
`--fg` #EAEAEA · `--fg-secondary` #929292 · `--fg-muted` #6D6D6D · `--fg-dim` #4F4F4F

### Signal colours
| Meaning | Token | Value |
|---------|-------|-------|
| Critical, danger, failed | `--coral` | #FF6F6F |
| Healthy, protected, operational | `--lime` | #A9EB64 |
| Warning, suspicious, attention | `--orange` | #FF934F |
| Medium severity | `--amber` | #E7C55C |
| Network activity | `--teal` | #39CDB0 |
| Analytical accent, TLS | `--cyan` | #65C8ED |
| Informational, selected, TCP | `--blue` | #6495ED |
| Secondary analytical, UDP | `--violet` | #B68CFF |
| Neutral, unknown, unsupported | `--gray` | #8A8A8A |

### Semantic mappings
- Severity: `--sev-critical` coral, `--sev-high` orange, `--sev-medium` amber, `--sev-low` blue, `--sev-info` grey. Each has a `-wash` variant for chip and row backgrounds.
- Status: `--ok` lime, `--danger` coral, `--warn` orange, `--info` blue, `--accent` cyan.
- Protocols: `--proto-tcp` blue, `--proto-udp` violet, `--proto-dns` teal, `--proto-http` lime, `--proto-tls` cyan, `--proto-icmp` orange, `--proto-other` grey.

**Colour is never the only signal.** Every severity, protocol and status also carries a text
label and, where useful, an icon or shape difference.

## Spacing and layout

- Spacing scale: `--s-1` 2px, `--s-2` 4, `--s-3` 6, `--s-4` 8, `--s-5` 12, `--s-6` 16, `--s-7` 20, `--s-8` 24, `--s-9` 32, `--s-10` 40, `--s-11` 56.
- Navigation rail: `--rail-w` 60px (slim) · `--rail-w-expanded` 208px.
- Top bar: `--topbar-h` 56px.
- Rows: `--row-h` 30px, compact 26px. Controls: `--control-h` 28px, large 34px.
- Radii stay small: `--r-xs` 3, `--r-sm` 5, `--r-md` 8, `--r-lg` 12. Shadows are almost invisible.

## Motion

`--t-fast` 110ms, `--t-base` 170ms, `--t-slow` 260ms, easing `--ease`. Motion explains state
change only. All durations collapse to 0 under `prefers-reduced-motion`.

## Layers

`--z-rail` 20, `--z-topbar` 30, `--z-dropdown` 40, `--z-overlay` 50, `--z-modal` 60, `--z-toast` 70.

## Components

Shared primitives live in `src/components/ui` and are the only place a control's look is defined:

| Component | Purpose |
|-----------|---------|
| `Button`, `IconButton` | primary / ghost / danger actions with consistent heights and focus rings |
| `Field` (`Select`, `TextInput`) | labelled controls with validation states |
| `Panel` | surface-1 container with a precise 1px border |
| `MetricCard` | label, large value, supporting line - used as a metric strip, not a card grid |
| `Table` | sticky header, hover/selected rows, mono technical cells, internal scrolling |
| `Badge` | severity, protocol, status, frame-kind and encrypted chips |
| `Feedback` | empty, loading, error and notice states |
| `Drawer`, `ConfirmDialog` | inspectors and destructive confirmations |
| `FilterBuilder` | guided typed filters shared by events and packets |
| `VolumeChart` | time-series with formatted axes and hover detail |
| `TopologyGraph` | relationship graph from real events and alerts |
| `HexView`, `LayerTree` | packet bytes and decoded protocol hierarchy |

## Rules

1. No hardcoded colours, font sizes, radii or spacing outside `tokens.css`.
2. No duplicate one-off styles: extend a primitive instead.
3. Data density before decoration; no decorative gradients, glow or particle effects.
4. Charts visualise real backend data only; empty states are honest and explain what to import.
5. Beginner mode adds labels and explanations; Analyst mode adds density and raw detail. Both
   read the same query and the same rows.
