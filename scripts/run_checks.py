#!/usr/bin/env python3
"""Run verification declared in the domain specs, or one complete integration gate."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

from check_architecture import ROOT, load_specs


def has_selected_tests(output):
    return bool(re.search(r"^.+: test$", output, re.MULTILINE))


def run(command, capture=False):
    print(f"+ {command}", flush=True)
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", command], cwd=ROOT,
        text=True, stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if result.returncode:
        if capture:
            print(result.stdout, end="")
        raise RuntimeError(f"command failed ({result.returncode}): {command}")
    return result.stdout or ""


def run_test_commands(command):
    # Specs deliberately use a small command vocabulary; retain an explicit cd
    # across && groups instead of duplicating domain selection in Python.
    prefix = ""
    for part in command.split(" && "):
        if part.startswith("cd "):
            prefix = part + " && "
            continue
        selected = prefix + part
        if part.startswith("cargo test "):
            listing = run(selected + " -- --list", capture=True)
            if not has_selected_tests(listing):
                raise RuntimeError(f"no tests selected: {selected}")
        run(selected)


def full_gate():
    run("python3 scripts/check_architecture.py")
    run("python3 -m unittest discover -s tests/architecture -v")
    run("cd ui && bun run check && bun run test && bun run build")
    run("cargo fmt --check")
    run("cargo check --locked --all-targets")
    run("cargo clippy --locked --all-targets -- -D warnings")
    run("cargo clippy --locked --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic")
    run_test_commands("cargo test --locked")
    run("cargo build --locked --bins")
    run("bash -n scripts/domain_check.sh tests/mc_test.sh tests/aws_cli_test.sh")
    # Respect an explicitly selected Cargo target directory; do not accidentally
    # judge a stale binary from target/ when the build went elsewhere.
    target = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
    if not target.is_absolute():
        target = ROOT / target
    import shlex
    binary = shlex.quote(str(target / "debug/maxio"))
    sync = shlex.quote(str(target / "debug/maxio-sync"))
    workspace = shlex.quote(str(target / "debug/maxio-workspace"))
    agent = shlex.quote(str(target / "debug/maxio-agent"))
    run(f"python3 scripts/smoke_standalone.py --binary {binary}")
    run(f"python3 scripts/smoke_peer_s3.py --binary {binary}")
    run(f"python3 scripts/smoke_secure_peers.py --binary {binary}")
    run(f"python3 scripts/smoke_device_sync.py --binary {binary} --sync-binary {sync}")
    run(f"python3 scripts/smoke_device_sync.py --binary {binary} --sync-binary {sync} --tls")
    run(f"python3 scripts/smoke_workspace.py --binary {binary} --workspace-binary {workspace}")
    run(f"python3 scripts/smoke_agents.py --binary {agent}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="domain name, all, or list")
    args = parser.parse_args()
    try:
        specs = load_specs()
        if args.domain == "list":
            print("\n".join(sorted(specs)))
            return 0
        if args.domain == "all":
            full_gate()
        elif args.domain in specs:
            commands = specs[args.domain]["verification"]
            run(commands["check"])
            run_test_commands(commands["test"])
            run(commands["build"])
            run(commands["architecture"])
        else:
            parser.error(f"unknown domain {args.domain!r}; use 'list'")
        print("Verification gates passed. An independent Gauntlet verdict is still required.")
        return 0
    except (RuntimeError, ValueError) as error:
        print(f"Verification FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
