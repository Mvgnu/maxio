#!/usr/bin/env python3
"""Check tracked domain contracts, source ownership, dependencies and branch scope.

This is an engineering gate, not a filesystem sandbox or a quality verdict.
Domain frontmatter is JSON (valid YAML), parsed with Python's standard library.
"""
import argparse
import fnmatch
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PM_PATHS = (
    "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml", ".bun-version",
    ".gitignore", "Dockerfile", ".dockerignore", "Justfile", ".github/",
    "AGENTS.md", "CLAUDE.md", "lop.md", "gauntlet.md", "README.md",
    "01_product_roadmap.md", "specs/00_system.md", "specs/journeys/", "specs/reviews/",
    "src/lib.rs", "src/storage/mod.rs", "src/metadata/mod.rs", "src/cluster/mod.rs",
    "src/api/mod.rs", "ui/package.json", "ui/bun.lock", "ui/vite.config.ts",
    "ui/tsconfig*.json", "ui/svelte.config.js", "scripts/check_architecture.py",
    "tests/architecture/",
)
EXPECTED = {
    "runtime_platform", "storage_engine", "cluster_transport_security",
    "cluster_metadata_plane", "s3_auth_sigv4", "s3_api_surface", "console_api",
    "web_console_ui", "device_sync", "quality_harness",
}
FORBIDDEN_DEPS = {
    "src/storage/": ("api", "server", "auth", "sync"),
    "src/metadata/": ("api", "server", "auth", "sync"),
    "src/cluster/": ("api", "server", "storage", "metadata", "sync"),
    "src/sync/": ("api", "server", "storage", "metadata", "cluster"),
}
BUILD_PATHS = ("target/", "ui/dist/", "ui/node_modules/", "data/")


def matches(path, pattern):
    return path.startswith(pattern) if pattern.endswith("/") else fnmatch.fnmatchcase(path, pattern)


def pm_owned(path):
    return any(matches(path, pattern) for pattern in PM_PATHS)


def allowed(path, spec):
    if path == f"specs/domains/{spec['name']}.md":
        return True
    if pm_owned(path) or any(matches(path, pattern) for pattern in BUILD_PATHS):
        return False
    paths = spec["paths"]
    return any(matches(path, pattern) for pattern in paths["owned"] + paths["tests"]) and not any(
        matches(path, pattern) for pattern in paths.get("exclude", [])
    )


def parse_spec(text):
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise ValueError("expected JSON frontmatter between --- lines")
    front = json.loads(text[4:].split("\n---\n", 1)[0])
    for key in ("name", "description", "paths", "exports", "consumes", "verification", "bar", "artifact"):
        if not front.get(key):
            raise ValueError(f"missing or empty {key}")
    for key in ("owned", "tests"):
        if not isinstance(front["paths"].get(key), list):
            raise ValueError(f"paths.{key} must be a list")
    if not front["paths"]["owned"]:
        raise ValueError("paths.owned must not be empty")
    for group in ("owned", "tests", "exclude"):
        for path in front["paths"].get(group, []):
            if not isinstance(path, str) or not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts or "\\" in path:
                raise ValueError(f"unsafe path pattern {path!r}")
    for key in ("check", "test", "build", "architecture"):
        if not isinstance(front["verification"].get(key), str) or not front["verification"][key].strip():
            raise ValueError(f"missing verification.{key}")
    for key in ("reference", "property", "url"):
        if not isinstance(front["bar"].get(key), str) or not front["bar"][key].strip():
            raise ValueError(f"missing bar.{key}")
    if not front["bar"]["url"].startswith("https://"):
        raise ValueError("bar.url must name an external HTTPS reference")
    return front


def git(*args, check=True):
    return subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True, check=check)


def paths_from_git(*args):
    return set(filter(None, git(*args, "-z").stdout.split("\0")))


def load_specs():
    result = {}
    for path in sorted((ROOT / "specs/domains").glob("*.md")):
        try:
            spec = parse_spec(path.read_text())
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError(f"{path.relative_to(ROOT)}: {error}") from error
        if spec["name"] != path.stem or spec["name"] in result:
            raise ValueError(f"invalid or duplicate domain name in {path.name}")
        result[spec["name"]] = spec
    if set(result) != EXPECTED:
        raise ValueError(f"domain inventory mismatch: missing={sorted(EXPECTED-set(result))}, extra={sorted(set(result)-EXPECTED)}")
    return result


def source_path(path):
    return path.startswith(("src/", "ui/src/", "scripts/", "tests/")) and Path(path).suffix in {".rs", ".ts", ".svelte", ".py", ".sh"}


def check_repository(specs):
    errors = []
    tracked = paths_from_git("ls-files")
    files = tracked | paths_from_git("ls-files", "--others", "--exclude-standard")
    for name in specs:
        path = f"specs/domains/{name}.md"
        if git("check-ignore", "--no-index", path, check=False).returncode == 0:
            errors.append(f"domain spec is ignored: {path}")
    for path in sorted(files):
        if path in tracked and any(matches(path, pattern) for pattern in BUILD_PATHS):
            errors.append(f"generated output/data is tracked: {path}")
        if not source_path(path) or pm_owned(path) or not (ROOT / path).is_file():
            continue
        owners = [name for name, spec in specs.items() if allowed(path, spec)]
        if len(owners) != 1:
            errors.append(f"source must have exactly one domain: {path} -> {owners}")
        if path.endswith(".rs"):
            text = (ROOT / path).read_text()
            for prefix, forbidden in FORBIDDEN_DEPS.items():
                if path.startswith(prefix):
                    for dependency in forbidden:
                        if re.search(r"\bcrate\s*::\s*" + dependency + r"\b", text):
                            errors.append(f"forbidden lower-layer dependency: {path} -> {dependency}")
    html = (ROOT / "ui/index.html").read_text()
    if re.search(r'(?:href|src)=["\'](?:https?:)?//', html):
        errors.append("console bootstrap has a remote asset dependency: ui/index.html")
    return errors


def check_scope(spec, base, head=None):
    # Pin the boundary and quality bar to the PM's base spec when available.
    path = f"specs/domains/{spec['name']}.md"
    baseline = git("show", f"{base}:{path}", check=False)
    boundary = spec
    errors = []
    if baseline.returncode == 0:
        boundary = parse_spec(baseline.stdout)
        if spec["paths"] != boundary["paths"]:
            errors.append("domain path changes require PM review; cannot widen your own bubble")
        if spec["bar"] != boundary["bar"]:
            errors.append("domain bar changes require PM review; cannot lower your own standard")
    changed = paths_from_git("diff", "--name-only", "--no-renames", base, head or "HEAD")
    if head is None:
        changed |= paths_from_git("diff", "--name-only", "--no-renames", "HEAD")
        changed |= paths_from_git("ls-files", "--others", "--exclude-standard")
    errors += [f"outside {spec['name']} write gate: {path}" for path in sorted(changed) if not allowed(path, boundary)]
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain")
    parser.add_argument("--base", help="PM-approved branch base, required for a domain write gate")
    parser.add_argument("--head", help="inspect a committed branch instead of the worktree")
    args = parser.parse_args()
    try:
        specs = load_specs()
        errors = check_repository(specs)
        if args.domain:
            if args.domain not in specs or not args.base:
                parser.error("a known --domain and explicit --base are required together")
            errors += check_scope(specs[args.domain], args.base, args.head)
        elif args.base or args.head:
            parser.error("--base/--head require --domain")
        if errors:
            print("Architecture gate FAILED:\n" + "\n".join(f"- {error}" for error in errors), file=sys.stderr)
            return 1
        print(f"Architecture gate passed: {len(specs)} domain specs; ownership, dependency and asset checks" + (f"; {args.domain} diff" if args.domain else ""))
        return 0
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"Architecture gate FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
