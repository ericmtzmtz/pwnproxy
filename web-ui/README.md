# Web UI — Scaffold Plan

## Stack
- **Framework**: Astro 5
- **CSS**: Tailwind CSS v4 (via `@tailwindcss/vite`)
- **Typography**: Inter (neutral sans — professional security tool)
- **Icons**: Lucide (consistent, comprehensive set)

## Folder Structure

```
src/
├── lib/                  # Utilities (formatting, helpers, constants)
├── ui/                   # Shared components (Button, Card, Modal, Badge, Input)
├── style.css             # Design system tokens + Tailwind theme
├── pages/                # Route modules
│   ├── proxy/            # Live proxy traffic view
│   │   └── components/   # Proxy-specific components
│   ├── scanners/         # Scanner results per type
│   │   └── components/
│   ├── repeater/         # Request replay
│   │   └── components/
│   ├── intruder/         # Fuzzer
│   │   └── components/
│   ├── reports/          # SARIF/PDF export
│   │   └── components/
│   ├── scope/            # Target scope management
│   │   └── components/
│   └── settings/         # Proxy config, plugin mgmt
│       └── components/
├── api/                  # API layer (one folder per domain)
│   ├── scanners/
│   │   ├── calls.ts      # What it does — fetch functions
│   │   └── types.ts      # Interfaces/types
│   ├── proxy/
│   │   ├── calls.ts
│   │   └── types.ts
│   ├── scope/
│   │   ├── calls.ts
│   │   └── types.ts
│   ├── reports/
│   │   ├── calls.ts
│   │   └── types.ts
│   └── plugins/
│       ├── calls.ts
│       └── types.ts
└── core/                 # Global configs (API base URL, auth, constants)
```

## Design System (defined in `style.css`)

### Theme: Dark-first (security proxy tool)

```css
/* Neutral greys with cool blue tint (tech/security personality) */
--color-neutral-50:  hsl(220, 15%, 95%);
--color-neutral-100: hsl(220, 12%, 88%);
--color-neutral-200: hsl(220, 10%, 78%);
--color-neutral-300: hsl(220, 8%, 65%);
--color-neutral-400: hsl(220, 6%, 52%);
--color-neutral-500: hsl(220, 5%, 40%);
--color-neutral-600: hsl(220, 5%, 30%);
--color-neutral-700: hsl(220, 6%, 22%);
--color-neutral-800: hsl(220, 8%, 15%);
--color-neutral-900: hsl(220, 10%, 10%);
--color-neutral-950: hsl(220, 12%, 6%);

/* Primary: cyber-blue */
--color-primary-50:  hsl(210, 90%, 95%);
--color-primary-100: hsl(210, 85%, 85%);
--color-primary-200: hsl(210, 80%, 72%);
--color-primary-300: hsl(210, 75%, 60%);
--color-primary-400: hsl(210, 70%, 50%);
--color-primary-500: hsl(210, 72%, 42%);
--color-primary-600: hsl(210, 75%, 35%);
--color-primary-700: hsl(210, 78%, 28%);
--color-primary-800: hsl(210, 80%, 20%);
--color-primary-900: hsl(210, 85%, 14%);
--color-primary-950: hsl(210, 90%, 8%);

/* Semantic */
--color-danger-500:  hsl(0, 75%, 50%);
--color-warning-500: hsl(40, 85%, 50%);
--color-success-500: hsl(145, 60%, 45%);
--color-info-500:    hsl(210, 70%, 50%);

/* Type scale */
--text-xs:   12px;
--text-sm:   14px;
--text-base: 16px;
--text-lg:   18px;
--text-xl:   20px;
--text-2xl:  24px;
--text-3xl:  30px;
--text-4xl:  36px;
--text-5xl:  48px;
--text-6xl:  60px;
--font-normal: 400;
--font-semibold: 600;
--font-bold: 700;

/* Spacing (4px base × factors) */
--space-1: 4px;
--space-2: 8px;
--space-3: 12px;
--space-4: 16px;
--space-6: 24px;
--space-8: 32px;
--space-12: 48px;
--space-16: 64px;
--space-24: 96px;
--space-32: 128px;

/* Border radius */
--radius-sm: 2px;
--radius-md: 4px;
--radius-lg: 6px;
--radius-xl: 8px;

/* Shadows (elevation) */
--shadow-xs: 0 1px 2px 0 rgba(0,0,0,0.4);
--shadow-sm: 0 1px 3px 0 rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.3);
--shadow-md: 0 4px 6px -1px rgba(0,0,0,0.4), 0 2px 4px rgba(0,0,0,0.3);
--shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.4), 0 4px 6px rgba(0,0,0,0.3);
--shadow-xl: 0 20px 25px -5px rgba(0,0,0,0.4), 0 10px 10px rgba(0,0,0,0.3);
```

### Design principles
1. **Dark-first** — security tool lives in terminals; dark theme is expected
2. **Monochromatic with blue accent** — one primary hue keeps UI clean
3. **Severity as color** — findings use semantic colors (red=critical, yellow=medium, green=info)
4. **Data density** — proxy traffic and findings need compact layouts; use spacing system consciously
5. **Status communicated with color + icon + text** — never color alone

## Implementation Order (v2)
1. Scaffold Astro + Tailwind project
2. Define `style.css` with design tokens
3. Build `ui/` component library (Button, Card, Badge, Table, Modal, Input)
4. Build `api/` layer — one domain at a time, starting with scanners
5. Build `pages/` — scanners first (most impactful), then proxy traffic, settings, scope, repeater, intruder, reports
