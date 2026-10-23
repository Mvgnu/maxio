#!/usr/bin/env python3
"""Exercise real local execution and labelled provider protocol fixtures.

This script never authenticates to a provider or sends a model request.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(binary, root):
    source = root / "source"
    (source / "src").mkdir(parents=True)
    (source / "unselected").mkdir()
    (source / "src/input.txt").write_text("selected version\n")
    (source / "unselected/private.txt").write_text("must stay at source\n")
    (source / "src/task.py").write_text("""import json,os,pathlib,subprocess,sys,time
assert not pathlib.Path('unselected').exists()
assert not any(k.startswith(('AWS_', 'MAXIO_')) for k in os.environ)
out = pathlib.Path('results'); out.mkdir(exist_ok=True)
out.joinpath('result.txt').write_text(pathlib.Path('src/input.txt').read_text() + sys.argv[-1])
pathlib.Path('src/input.txt').write_text('unpublished edit')
print('ordinary Python executable ran', flush=True)
if sys.argv[1] == 'fail':
    print('expected failure', file=sys.stderr); sys.exit(7)
if sys.argv[1] == 'wait':
    child = subprocess.Popen([sys.executable, '-c', "import pathlib,time; p=pathlib.Path('results/heartbeat');\\nwhile True: p.write_text(str(time.time_ns())); time.sleep(0.05)"])
    out.joinpath('group.txt').write_text(str(os.getpgrp()))
    while True: time.sleep(1)
""")
    records = root / "records"
    literal = "$(touch escaped); `touch escaped2` $HOME"
    env = dict(os.environ, AWS_SECRET_ACCESS_KEY="smoke-storage-sentinel", MAXIO_SECRET_KEY="smoke-storage-sentinel")

    def command(mode, timeout=10):
        return [str(binary), "run", "--adapter", "command", "--executable", sys.executable,
                "--source", str(source), "--input", "src", "--output", "results",
                "--records", str(records), "--timeout-seconds", str(timeout),
                "--", "src/task.py", mode, literal]

    def invoke(arguments, expected):
        result = subprocess.run(arguments, env=env, text=True, capture_output=True, timeout=30)
        require(result.returncode == expected, f"unexpected CLI exit {result.returncode}: {result.stderr}")
        return json.loads(result.stdout)

    success = invoke(command("success"), 0)
    workspace = Path(success["workspace"])
    require(success["status"] == "succeeded" and not success["published"], "execution/publication states conflated")
    require(len(success["input_files"]) == 2 and len(success["output_files"]) == 1, "selected manifest is incorrect")
    require(not (workspace / "unselected").exists(), "unrelated files copied")
    require(not (workspace / "escaped").exists() and not (workspace / "escaped2").exists(), "arguments interpreted by shell")
    require((workspace / "results/result.txt").read_text().endswith(literal), "literal argv changed")
    require((source / "src/input.txt").read_text() == "selected version\n", "source was changed")
    failed = invoke(command("fail"), 1)
    require(failed["status"] == "failed" and failed["exit_code"] == 7, "failure state incorrect")
    require(Path(failed["workspace"]).joinpath("src/input.txt").read_text() == "unpublished edit", "failed edit lost")
    timed = invoke(command("wait", 1), 124)
    require(timed["status"] == "timed_out", "timeout state incorrect")
    heartbeat = Path(timed["workspace"]) / "results/heartbeat"
    stopped = heartbeat.read_text()
    time.sleep(0.2)
    require(heartbeat.read_text() == stopped, "timeout left a running descendant")

    before = set(records.iterdir())
    process = subprocess.Popen(command("wait"), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        running = None
        while time.monotonic() < deadline:
            for candidate in set(records.iterdir()) - before:
                path = candidate / "record.json"
                if path.exists():
                    record = json.loads(path.read_text())
                    if record["status"] == "running" and Path(record["workspace"]).joinpath("results/heartbeat").exists():
                        running = record
                        break
            if running:
                break
            time.sleep(0.02)
        require(running is not None, "command did not reach running state")
        cancel_request = invoke([str(binary), "cancel", "--run", str(Path(running["workspace"]).parent)], 0)
        require(cancel_request["cancellation_requested"] and not cancel_request["completed"], "request receipt implied completed cancellation")
        stdout, stderr = process.communicate(timeout=10)
        require(process.returncode == 130, f"cancel exit incorrect: {stderr}")
        cancelled = json.loads(stdout)
        require(cancelled["status"] == "cancelled", "cancellation not retained")
        heartbeat = Path(cancelled["workspace"]) / "results/heartbeat"
        stopped = heartbeat.read_text()
        time.sleep(0.2)
        require(heartbeat.read_text() == stopped, "cancellation left a running descendant")
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)

    # These executables only emit known protocol records. They are NOT Codex or
    # Claude, do not contact a provider and cannot establish model compatibility.
    fixture = root / "provider-protocol-fixture.py"
    fixture.write_text(f"#!{sys.executable}\n" + """import json,sys,pathlib
if '--version' in sys.argv: print('2.1.309 protocol-fixture'); sys.exit(0)
if '--help' in sys.argv:
    print('--ask-for-approval never --sandbox read-only workspace-write --json --cd --color --skip-git-repo-check --restricted --print --output-format stream-json --verbose --permission-mode dontAsk --permission-prompts --tools --allowedTools --disallowedTools'); sys.exit(0)
mode = sys.stdin.read().strip()
if mode == 'malformed': print('{broken'); sys.exit(0)
if mode == 'missing': print(json.dumps({'type':'fixture_info'})); sys.exit(0)
if '--restricted' in sys.argv:
    terminal = {'type':'result','subtype':'success','is_error':False,'session_id':'fixture-session','permission_denials':([{'tool_name':'Edit'}] if mode == 'denied' else [])}
    activity = {'type':'assistant','session_id':'fixture-session','message':{'role':'assistant','content':[{'type':'text','text':'next turn'}]}}
    if mode in ['queued', 'queued_followup', 'queued_reporting']: terminal['queued_turn_count'] = 1
    if mode == 'invalid_queue': terminal['queued_turn_count'] = '0'
else:
    print(json.dumps({'type':'thread.started','thread_id':'fixture-session'}))
    terminal = {'type':'turn.completed'}
    activity = {'type':'turn.started'}
print(json.dumps(terminal))
if mode in ['unfinished', 'followup', 'unfinished_idle', 'unfinished_reporting']:
    print(json.dumps(activity))
    if mode == 'followup': print(json.dumps(terminal))
if mode == 'metadata': print(json.dumps({'type':'system','subtype':'turn_duration','duration_ms':1}))
if mode == 'queued_followup':
    terminal['queued_turn_count'] = 0
    print(json.dumps(terminal))
if mode in ['idle', 'unfinished_idle', 'queued', 'queued_followup', 'invalid_queue']: print(json.dumps({'type':'system','subtype':'session_state_changed','state':'idle','session_id':'fixture-session'}))
if mode == 'suggestion': print(json.dumps({'type':'prompt_suggestion','suggestion':'Inspect the result'}))
if mode == 'task_notice': print(json.dumps({'type':'system','subtype':'task_notification','task_id':'task-1','status':'completed','output_file':'task.log','summary':'Background task ended'}))
if mode in ['informational', 'reporting', 'unfinished_reporting', 'queued_reporting']:
    print(json.dumps({'type':'system','subtype':'informational','level':'info','content':'Fixture reporting tail','prevent_continuation':True}))
if mode in ['heartbeat', 'reporting', 'unfinished_reporting', 'queued_reporting']:
    print(json.dumps({'type':'keep_alive'}))
    print(json.dumps({'type':'system','subtype':'commands_changed','commands':[]}))
    print(json.dumps({'type':'active_goal','value':None}))
""")
    fixture.chmod(0o700)
    provider_home = root / "fixture-provider-home"
    provider_home.mkdir()
    prompt = root / "prompt.txt"
    observed = {}
    for provider, mode, expected, state in [
        ("codex", "success", 0, "succeeded"),
        ("codex", "missing", 1, "protocol_failed"),
        ("codex", "malformed", 1, "protocol_failed"),
        ("codex", "unfinished", 1, "protocol_failed"),
        ("codex", "followup", 0, "succeeded"),
        ("claude", "success", 0, "succeeded"),
        ("claude", "denied", 1, "failed"),
        ("claude", "unfinished", 1, "protocol_failed"),
        ("claude", "followup", 0, "succeeded"),
        ("claude", "metadata", 0, "succeeded"),
        ("claude", "idle", 0, "succeeded"),
        ("claude", "unfinished_idle", 1, "protocol_failed"),
        ("claude", "suggestion", 0, "succeeded"),
        ("claude", "task_notice", 0, "succeeded"),
        ("claude", "queued", 1, "protocol_failed"),
        ("claude", "queued_followup", 0, "succeeded"),
        ("claude", "invalid_queue", 1, "protocol_failed"),
        ("claude", "informational", 0, "succeeded"),
        ("claude", "heartbeat", 0, "succeeded"),
        ("claude", "reporting", 0, "succeeded"),
        ("claude", "unfinished_reporting", 1, "protocol_failed"),
        ("claude", "queued_reporting", 1, "protocol_failed"),
    ]:
        prompt.write_text(mode)
        record = invoke([str(binary), "run", "--adapter", provider, "--executable", str(fixture),
                         "--source", str(source), "--input", "src/input.txt", "--records", str(records),
                         "--prompt-file", str(prompt), "--provider-home", str(provider_home)], expected)
        require(record["status"] == state, f"{provider} fixture status incorrect")
        observed[f"{provider}:{mode}"] = record["status"]
    print(json.dumps({
        "ordinary_command": "actual execution verified",
        "selected_inputs": 2,
        "literal_argv": "preserved",
        "source": "unchanged",
        "failure": failed["status"],
        "timeout": timed["status"],
        "cancellation": cancelled["status"],
        "owned_descendants": "stopped after timeout and explicit local cancellation request",
        "signal_cancellation": "implemented but not established by this journey",
        "publication": "never performed",
        "provider_protocol_fixtures": observed,
        "live_authenticated_providers": "NOT RUN",
        "records": str(records),
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--artifacts", type=Path, help="retain disposable journey artifacts in this new directory")
    args = parser.parse_args()
    if args.artifacts:
        args.artifacts.mkdir(parents=True, exist_ok=False)
        run(args.binary.resolve(), args.artifacts.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="maxio-agents-") as directory:
            run(args.binary.resolve(), Path(directory))


if __name__ == "__main__":
    main()
