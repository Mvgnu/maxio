---
{
  "name": "web_console_ui",
  "description": "Make local object management usable without external network dependencies",
  "paths": {
    "owned": [
      "ui/"
    ],
    "tests": [],
    "exclude": [
      "ui/package.json",
      "ui/bun.lock",
      "ui/vite.config.ts",
      "ui/tsconfig*.json",
      "ui/svelte.config.js"
    ]
  },
  "exports": [
    "embedded /ui/ console",
    "typed API client",
    "object/version/settings/system views"
  ],
  "consumes": [
    "console_api JSON and session contracts"
  ],
  "verification": {
    "check": "cd ui && bun run check",
    "test": "cd ui && bun run test && bun run check",
    "build": "cd ui && bun run build",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "MinIO Console object browser",
    "url": "https://github.com/minio/console",
    "property": "An operator can create a bucket, upload a file and retrieve it at desktop and phone widths without third-party requests or hidden controls."
  },
  "artifact": "Serve the embedded console, drive the task at 390x844 and 1440x900, inspect browser requests and screenshots."
}
---

# Make local object management usable without external network dependencies

## Required behavior

- Use Bun and the current Svelte design system; no new frontend framework.
- Use local assets/system fonts; the console must not require Google Fonts or another external service.
- Show standalone tasks first; distributed diagnostics must not be prerequisites for object management.
- Preserve explicit loading/error/empty states; do not hide failures behind stale success.

## Known limits / next decision

- Existing system diagnostics are dense and need independent usability review; green unit tests are not evidence of usability.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
