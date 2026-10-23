# MaxIO console design rules

The existing theme is derived from Coolify. Its implemented token source is
[`src/app.css`](src/app.css); shared Svelte controls live in
[`src/lib/components/ui/`](src/lib/components/ui/). Keep those sources authoritative
instead of copying a second catalogue of CSS into this document. The previous
full reference remains in Git history at `c9ffef2`.

## Purpose

An operator should create a bucket, upload a file and retrieve it without learning
cluster internals. The normal object task comes first; detailed system diagnostics
remain a separate view. Name unavailable or degraded states explicitly.

## Visual rules

- Preserve the existing light and dark tokens and local MaxIO mark. Do not
  invent a separate palette per screen.
- Use local/system fonts. No remotely loaded fonts, scripts, tracking or CDNs.
- Use the existing Button, Input, Table, Card and toast components.
- Keep foreground, muted text, borders and destructive actions legible in both
  themes. Focus and selected states must remain visible.
- Use plain labels for actions and explicit loading, empty and failure states.
  A stale success must not cover a new error.

## Responsive behavior

- Start with the compact sidebar on phone widths. Give content a shrinking
  flex boundary so long names cannot push the entire page offscreen.
- Creation forms wrap on narrow screens; their submit/cancel controls remain
  reachable without horizontal scrolling.
- Keep object names and download/actions visible on phones. Secondary date and
  size columns may adapt; a file size is also shown beside its name on phones.
- Truncate long identifiers visually with their full value available in context.
  Never change the identifier sent to the API.
- Preserve a useful desktop table, keyboard focus and accessible names for
  icon actions. Do not use a screenshot as evidence that a control works.

## Quality bar

The [domain spec](../specs/domains/web_console_ui.md) compares the object-management
task with MinIO Console. A fresh critic uses the served artifact at 390×844 and
1440×900, performs the real upload/download, inspects requests and screenshots,
and reports the largest remaining gap. Record evidence in the dated Gauntlet
review; do not self-award a pass here.
