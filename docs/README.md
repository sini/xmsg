# xmsg docs

The `xmsg` documentation and marketing site: [Astro](https://astro.build) +
[Starlight](https://starlight.astro.build), published to <https://xmsg.dev>
by `.github/workflows/docs-pages.yml`.

## Running locally

```bash
pnpm install
pnpm run dev          # local dev server
pnpm run check        # status prebuild + typecheck
pnpm run status:test  # unit tests for status manifest & lint
pnpm run build        # status prebuild, typecheck, static build into dist/, validate every internal link
```

## Gates

Five checks run on every `pnpm run build`:

- **Feature status manifest** — `scripts/status-check.mjs` resolves each entry in `src/data/features.ts` against `main`, the live `xmsg` pin in `github.com/sini/nix-config` `main`'s `flake.lock` (using `docs/fleet-pin.txt` only as an offline cross-check), and `v*` release tags once into `.status.json`, validates `<Status id="..." />` references, and rejects free-text status markers (`(planned)`, `planned, not yet released`, `<Aside title="...planned...">`) on converted pages.
- **Broken internal links** — `starlight-links-validator` fails the build on any dead internal link.
- **Type errors** — `astro check` runs before `astro build`.
- **Code imports** — `remark-code-import` pulls source snippets directly from `<rootDir>/...` so stale file paths or line ranges fail the build.
- **Palette validation** — `src/palettes.mjs` validates all token and attribution invariants on import.

## Adding or updating a feature status

1. Add or update the feature entry in `src/data/features.ts` with its `id`, `title`, `owner`, and `evidence` (`{ path, anchor }[]`).
2. Render `<Status id="..." />` in the MDX page instead of writing free-text `(planned)` or `Planned, not yet released` markers.
3. Run `pnpm run status:test && pnpm run build` before pushing.
