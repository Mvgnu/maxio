# MaxIO console

The Svelte/TypeScript console is served by MaxIO at `/ui/`. The Rust management
API lives under `/api/`; the frontend uses its typed client in `src/lib/api.ts`.
Read the [domain spec](../specs/domains/web_console_ui.md) before editing.

## Local development

Use the pinned Bun version from `../.bun-version`. From this directory:

```bash
bun install --frozen-lockfile
bun run check
bun run test
bun run build
```

From the repository root, build and run `maxio` as described in the
[README](../README.md). Debug executables read `ui/dist/` from the checkout;
release executables embed that build. Rebuild the console after editing it.

Vite has a `/ui/` base and no development API proxy. A standalone Vite preview
does not provide a working management server; use the actual MaxIO listener for
login and object operations.

## Review

Follow [the design rules](DESIGN_SYSTEM.md). Independently drive login, bucket
creation, upload and download at 390×844 and 1440×900. Verify the downloaded bytes,
that primary controls are inside the viewport, and that loading the console makes
no third-party requests. Bun tests alone do not establish this user journey.
