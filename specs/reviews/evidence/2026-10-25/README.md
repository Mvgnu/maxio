# Evidence for the managed-fabric wave

The [dated review](../../2026-10-25-managed-fabric.md) states the product conclusions,
exact build attribution, verification and limits. These files retain independent
assessments and actual machine-readable observations. They are evidence, not another
source of product contracts or a claim that all possible failures were tested.

- `authority-*`, `cache-*` and `execution-*` contain separate critics' findings and
  selected actual checks/records. The original reports preserve their original
  runtime paths and binary hashes; ephemeral path names are historical attribution.
- `eviction-interruption-*` and `eviction-cycle*.json` record two observed
  post-unlink process interruptions. `interrupted_eviction.py` plus adjacent
  `critic.py` preserve the independent Linux reproduction, using Python's standard
  library, OpenSSL and libc/inotify. Use its `--help` and a new disposable runtime
  root; it creates its own test keys and TLS materials.
- `onboarding-round1.md` preserves the actual readable-log gap. Round two records
  its closure and the separate invalid-UTF8 child-log normalization limit.
- `builder-*` are explicitly builder observations. Their unexercised list describes
  that run, not later independent experiments. `scripts/smoke_fabric.py` is the
  supported full B–E process reproduction.
- `ordinary_s3_aws.py` is an additional Journey A driver requiring an installed
  ordinary AWS CLI; its JSON records the actually used version and binary.
- `s3-retention-*` preserves the separate unsupported-operation/preservation review.
- `artifact-*.json` identifies the frozen reviewed binaries. `local-verification.json`
  separates the complete local gate from the subsequent CLI correction. The PR's
  final-head GitHub check supplies that independent clean-checkout result.

Private keys, active credentials and bulk dataset payloads are not checked in.
The process scripts generate disposable data and record exact hashes/lengths. No
authenticated Codex/Claude model execution is represented by the fixture receipts.
