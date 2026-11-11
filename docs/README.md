# xmsg docs

The `xmsg` documentation and marketing site: [Astro](https://astro.build) +
[Starlight](https://starlight.astro.build), published to <https://xmsg.dev>
by `.github/workflows/docs-pages.yml`.

## Running locally

```bash
pnpm install
pnpm run dev      # local dev server
pnpm run check    # typecheck only
pnpm run build    # typecheck, static build into dist/, validate every internal link
```

## Gates

Three checks run on every `pnpm run build`:

- **Broken internal links** — `starlight-links-validator` fails the build on any dead internal link.
- **Type errors** — `astro check` runs before `astro build`.
- **Code imports** — `remark-code-import` pulls source snippets directly from `<rootDir>/...` so stale file paths or line ranges fail the build.
- **Palette validation** — `src/palettes.mjs` validates all token and attribution invariants on import.
