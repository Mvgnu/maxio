---
{
  "name": "quality_harness",
  "description": "Make verification reproducible and fail when no relevant check actually ran",
  "paths": {
    "owned": [
      "scripts/domain_check.sh",
      "scripts/smoke_standalone.py",
      "scripts/seed.sh",
      "scripts/run_checks.py"
    ],
    "tests": [
      "tests/integration.rs",
      "tests/integration/helpers.rs",
      "tests/mc_test.sh",
      "tests/aws_cli_test.sh"
    ],
    "exclude": []
  },
  "exports": [
    "domain check runner",
    "whole-repository gate",
    "real-process smoke scenarios"
  ],
  "consumes": [
    "all domain verification commands",
    "PM-owned architecture gate and specs"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "python3 -m unittest discover -s tests/architecture -v && bash -n scripts/domain_check.sh tests/mc_test.sh tests/aws_cli_test.sh",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "pytest exit-code contract for no tests collected",
    "url": "https://docs.pytest.org/en/stable/reference/exit-codes.html",
    "property": "A misspelled domain, vanished test selection, missing spec or out-of-bound change fails visibly instead of yielding a green no-op."
  },
  "artifact": "Run architecture negative cases, invalid domain selection, full suite and real-process journey scripts from the documented commands."
}
---

# Make verification reproducible and fail when no relevant check actually ran

## Required behavior

- Run the full Rust suite once per integration, not once per domain plus hundreds of filtered invocations.
- Domain selection must name existing tests and must fail if it selects zero.
- CI builds assets with locked dependencies and runs ownership/dependency/spec checks.
- Process scenarios own and clean only their temporary directories and child processes.
- A green harness must never overwrite an independent Gauntlet verdict.
- The complete gate includes standalone, peer, sync, direct-workspace, local-agent
  and managed B–E process journeys, using binaries from the selected Cargo target.
  Managed three-device runs are isolated processes on one host; provider fixtures
  establish adapter protocol behavior only.

## Known limits / next decision

- CI gates establish correctness evidence, not a UX/operability pass or production certification.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
