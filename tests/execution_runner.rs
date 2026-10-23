#![cfg(unix)]

use maxio::execution::{AdapterKind, PermissionMode, RunRequest, doctor, run};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn python() -> PathBuf {
    PathBuf::from("/usr/bin/python3")
}

fn request(root: &std::path::Path, script: &str) -> RunRequest {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("task.py"), script).unwrap();
    fs::write(source.join("unrelated.txt"), "must not copy").unwrap();
    RunRequest {
        adapter: AdapterKind::Command,
        executable: python(),
        source,
        inputs: vec!["task.py".into()],
        outputs: vec!["result.txt".into()],
        records: root.join("records"),
        prompt: None,
        args: vec!["task.py".into()],
        timeout_seconds: 5,
        environment: BTreeMap::new(),
        permission: PermissionMode::WorkspaceWrite,
    }
}

#[tokio::test]
async fn selected_inputs_literal_arguments_and_real_output() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(
        root.path(),
        "import pathlib,sys,os\nassert not pathlib.Path('unrelated.txt').exists()\nassert not any(k.startswith(('MAXIO_', 'AWS_')) for k in os.environ)\npathlib.Path('result.txt').write_text(sys.argv[1])\nprint('real command completed')\n",
    );
    let literal = "$(touch oops); `touch other` $HOME";
    req.args.push(literal.into());
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "succeeded");
    assert!(!record.published);
    assert_eq!(record.input_files.len(), 1);
    assert_eq!(record.output_files.len(), 1);
    assert_eq!(
        fs::read_to_string(record.workspace.join("result.txt")).unwrap(),
        literal
    );
    assert!(!record.workspace.join("oops").exists());
    assert!(root.path().join("source/unrelated.txt").exists());
    assert!(
        fs::read_to_string(record.stdout_log)
            .unwrap()
            .contains("real command completed")
    );
}

#[tokio::test]
async fn failure_retains_unpublished_edit_and_exit() {
    let root = tempfile::tempdir().unwrap();
    let req = request(
        root.path(),
        "import pathlib,sys\npathlib.Path('result.txt').write_text('recover me')\nprint('failure detail', file=sys.stderr)\nsys.exit(7)\n",
    );
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "failed");
    assert_eq!(record.exit_code, Some(7));
    assert!(!record.published);
    assert_eq!(
        fs::read_to_string(record.workspace.join("result.txt")).unwrap(),
        "recover me"
    );
    assert!(
        fs::read_to_string(record.stderr_log)
            .unwrap()
            .contains("failure detail")
    );
}

#[tokio::test]
async fn timeout_preserves_work() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(
        root.path(),
        "import pathlib,time\npathlib.Path('result.txt').write_text('unfinished')\ntime.sleep(20)\n",
    );
    req.timeout_seconds = 1;
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "timed_out");
    assert_eq!(
        fs::read_to_string(record.workspace.join("result.txt")).unwrap(),
        "unfinished"
    );
}

#[tokio::test]
async fn selected_environment_is_redacted_and_not_persisted() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(
        root.path(),
        "import os,sys,pathlib\nassert os.environ['TASK_LABEL'] == 'chosen-private-value'\nprint(os.environ['TASK_LABEL'])\npathlib.Path('result.txt').write_text(sys.stdin.read())\n",
    );
    req.environment
        .insert("TASK_LABEL".into(), "chosen-private-value".into());
    req.prompt = Some("private prompt not a record field".into());
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "succeeded");
    let persisted =
        fs::read_to_string(record.workspace.parent().unwrap().join("record.json")).unwrap();
    assert!(!persisted.contains("chosen-private-value"));
    assert!(!persisted.contains("private prompt not a record field"));
    assert_eq!(
        fs::read_to_string(record.stdout_log).unwrap(),
        "[REDACTED]\n"
    );
}

#[tokio::test]
async fn storage_credentials_and_runtime_overrides_are_rejected() {
    for name in [
        "MAXIO_SECRET_KEY",
        "AWS_ACCESS_KEY_ID",
        "S3_TOKEN",
        "R2_STORAGE_KEY",
        "LD_PRELOAD",
        "HOME",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(root.path(), "raise AssertionError('must not run')\n");
        req.environment
            .insert(name.into(), "not-to-be-logged".into());
        let error = run(req).await.unwrap_err().to_string();
        assert!(!error.contains("not-to-be-logged"));
        assert!(!root.path().join("records").exists());
    }
}

#[tokio::test]
async fn input_symlinks_and_control_paths_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(root.path(), "raise AssertionError('must not run')\n");
    std::os::unix::fs::symlink("unrelated.txt", req.source.join("linked.txt")).unwrap();
    req.inputs.push("linked.txt".into());
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "failed");
    assert!(record.detail.unwrap().contains("symlink"));
    let root = tempfile::tempdir().unwrap();
    let mut req = request(root.path(), "raise AssertionError('must not run')\n");
    req.inputs.push(".git/config".into());
    assert!(run(req).await.is_err());
}

#[tokio::test]
async fn unsafe_outputs_are_not_proposed_and_originals_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let req = request(
        root.path(),
        "import pathlib\npathlib.Path('result.txt').symlink_to('/etc/passwd')\npathlib.Path('task.py').write_text('local edit')\n",
    );
    let original = fs::read(req.source.join("task.py")).unwrap();
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "failed");
    assert!(record.output_files.is_empty());
    assert_eq!(
        fs::read(root.path().join("source/task.py")).unwrap(),
        original
    );
    assert_eq!(
        fs::read_to_string(record.workspace.join("task.py")).unwrap(),
        "local edit"
    );
}

#[tokio::test]
async fn actual_command_logs_are_bounded() {
    let root = tempfile::tempdir().unwrap();
    let req = request(
        root.path(),
        "import sys\nfor _ in range(6000): print('x' * 1023)\n",
    );
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "succeeded");
    assert_eq!(
        fs::metadata(record.stdout_log).unwrap().len(),
        4 * 1024 * 1024
    );
    assert!(record.detail.unwrap().contains("truncated"));
}

fn provider_fixture(root: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("provider-protocol-fixture.py");
    fs::write(&path, r#"#!/usr/bin/python3
# This is a protocol fixture. It makes no model requests.
import sys,json,pathlib
if '--version' in sys.argv:
    print('2.1.309 protocol-fixture'); sys.exit(0)
if '--help' in sys.argv:
    print('--ask-for-approval never --sandbox read-only workspace-write --json --cd --color --skip-git-repo-check --restricted --print --output-format stream-json --verbose --permission-mode dontAsk --permission-prompts --tools --allowedTools --disallowedTools'); sys.exit(0)
assert not any(arg in sys.argv for arg in ['--dangerously-skip-permissions','--dangerously-bypass-approvals-and-sandbox','--yolo'])
mode = sys.stdin.read().strip()
if '--restricted' in sys.argv:
    assert '--permission-prompts' in sys.argv and 'none' in sys.argv
    assert 'Bash' not in ','.join(sys.argv)
    event = {'type':'result','subtype':'success','is_error':False,'session_id':'fixture-session','permission_denials':[]}
    if mode == 'error': event['is_error'] = True
    if mode == 'denied': event['permission_denials'] = [{'tool_name':'Edit'}]
else:
    assert sys.argv[1:4] == ['--ask-for-approval','never','exec']
    assert '--skip-git-repo-check' in sys.argv and sys.argv[-1] == '-'
    print(json.dumps({'type':'thread.started','thread_id':'fixture-session'}))
    event = {'type':'turn.completed'}
    if mode == 'error': print(json.dumps({'type':'error','message':'fixture failure'}))
pathlib.Path('result.txt').write_text('protocol fixture output')
if mode.startswith('{'):
    sequence = json.loads(mode)
    for message in sequence['events']: print(json.dumps(message))
    sys.exit(sequence.get('exit_code', 0))
if mode == 'malformed': print('{invalid JSON')
elif mode != 'missing': print(json.dumps(event))
if mode == 'nonzero': sys.exit(9)
"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[tokio::test]
async fn provider_protocol_fixtures_require_successful_exit_and_terminal_event() {
    for (kind, mode, expected) in [
        (AdapterKind::Codex, "success", "succeeded"),
        (AdapterKind::Codex, "missing", "protocol_failed"),
        (AdapterKind::Codex, "malformed", "protocol_failed"),
        (AdapterKind::Codex, "error", "failed"),
        (AdapterKind::Codex, "nonzero", "failed"),
        (AdapterKind::Claude, "success", "succeeded"),
        (AdapterKind::Claude, "missing", "protocol_failed"),
        (AdapterKind::Claude, "malformed", "protocol_failed"),
        (AdapterKind::Claude, "denied", "failed"),
        (AdapterKind::Claude, "error", "failed"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(root.path(), "# selected context only\n");
        req.adapter = kind;
        req.executable = provider_fixture(root.path());
        req.args.clear();
        req.prompt = Some(mode.into());
        req.environment.insert(
            if kind == AdapterKind::Codex {
                "CODEX_API_KEY"
            } else {
                "ANTHROPIC_API_KEY"
            }
            .into(),
            "fixture-only-not-a-credential".into(),
        );
        let record = run(req).await.unwrap();
        assert_eq!(
            record.status, expected,
            "{kind:?} {mode}: {:?}",
            record.detail
        );
        assert!(!record.published);
        assert!(record.workspace.join("result.txt").exists());
    }
}

#[tokio::test]
async fn provider_protocol_fixtures_require_the_final_turn_to_complete() {
    use serde_json::json;
    let codex_success = json!({"type":"turn.completed"});
    let codex_start = json!({"type":"turn.started"});
    let claude_success = json!({"type":"result","subtype":"success","is_error":false,"session_id":"fixture-session"});
    let claude_activity = json!({"type":"assistant","message":{"role":"assistant","content":[]},"session_id":"fixture-session"});
    for (kind, events, exit_code, expected) in [
        (
            AdapterKind::Codex,
            vec![codex_success.clone(), codex_start.clone()],
            0,
            "protocol_failed",
        ),
        (
            AdapterKind::Codex,
            vec![
                codex_success.clone(),
                json!({"type":"item.completed","item":{"type":"agent_message","text":"unfinished next turn"}}),
            ],
            0,
            "protocol_failed",
        ),
        (
            AdapterKind::Codex,
            vec![
                codex_success.clone(),
                codex_start.clone(),
                codex_success.clone(),
            ],
            0,
            "succeeded",
        ),
        (
            AdapterKind::Codex,
            vec![codex_success.clone(), codex_start.clone()],
            9,
            "failed",
        ),
        (
            AdapterKind::Codex,
            vec![
                json!({"type":"error","message":"earlier failure"}),
                codex_success.clone(),
                codex_start,
                codex_success,
            ],
            0,
            "failed",
        ),
        (
            AdapterKind::Claude,
            vec![claude_success.clone(), claude_activity.clone()],
            0,
            "protocol_failed",
        ),
        (
            AdapterKind::Claude,
            vec![
                claude_success.clone(),
                json!({"type":"stream_event","event":{"type":"message_start"}}),
            ],
            0,
            "protocol_failed",
        ),
        (
            AdapterKind::Claude,
            vec![
                claude_success.clone(),
                json!({"type":"tool_progress","tool_name":"Read"}),
            ],
            0,
            "protocol_failed",
        ),
        (
            AdapterKind::Claude,
            vec![
                claude_success.clone(),
                claude_activity.clone(),
                claude_success.clone(),
            ],
            0,
            "succeeded",
        ),
        (
            AdapterKind::Claude,
            vec![
                claude_success.clone(),
                json!({"type":"system","subtype":"turn_duration","duration_ms":1}),
            ],
            0,
            "succeeded",
        ),
        (
            AdapterKind::Claude,
            vec![
                claude_success.clone(),
                claude_activity.clone(),
                claude_success.clone(),
            ],
            9,
            "failed",
        ),
        (
            AdapterKind::Claude,
            vec![
                json!({"type":"system","subtype":"permission_denied"}),
                claude_success.clone(),
                claude_activity,
                claude_success.clone(),
            ],
            0,
            "failed",
        ),
        (
            AdapterKind::Claude,
            vec![
                claude_success.clone(),
                json!({"type":"system","subtype":"api_error"}),
                claude_success,
            ],
            0,
            "failed",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(root.path(), "# selected context only\n");
        req.adapter = kind;
        req.executable = provider_fixture(root.path());
        req.args.clear();
        req.prompt = Some(json!({"events":events,"exit_code":exit_code}).to_string());
        req.environment.insert(
            if kind == AdapterKind::Codex {
                "CODEX_API_KEY"
            } else {
                "ANTHROPIC_API_KEY"
            }
            .into(),
            "fixture-only-not-a-credential".into(),
        );
        let record = run(req).await.unwrap();
        assert_eq!(
            record.status, expected,
            "{kind:?}: {events:?}: {:?}",
            record.detail
        );
        assert!(!record.published);
        assert!(record.workspace.join("result.txt").exists());
    }
}

#[tokio::test]
async fn doctor_rejects_missing_safety_flags_without_running_a_task() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let fixture = root.path().join("old-provider-fixture.py");
    fs::write(&fixture, "#!/usr/bin/python3\nimport sys\nif '--version' in sys.argv: print('2.1.1 fixture')\nelif '--help' in sys.argv: print('--print')\nelse: raise AssertionError('doctor must not execute a task')\n").unwrap();
    fs::set_permissions(&fixture, fs::Permissions::from_mode(0o700)).unwrap();
    let report = doctor(AdapterKind::Claude, &fixture).await.unwrap();
    assert!(!report.supported);
    assert!(report.detail.contains("capability"));
}

#[tokio::test]
async fn provider_overrides_and_credential_source_overlap_fail_before_preparation() {
    for mode in ["flags", "endpoint", "credential_source"] {
        let root = tempfile::tempdir().unwrap();
        let mut req = request(root.path(), "# must not run\n");
        req.adapter = AdapterKind::Codex;
        req.args.clear();
        req.prompt = Some("provider fixture prompt".into());
        req.environment
            .insert("CODEX_API_KEY".into(), "fixture-only-key".into());
        match mode {
            "flags" => req.args.push("--yolo".into()),
            "endpoint" => {
                req.environment
                    .insert("OPENAI_BASE_URL".into(), "https://example.invalid".into());
            }
            _ => {
                req.environment.insert(
                    "CODEX_HOME".into(),
                    req.source.to_string_lossy().into_owned(),
                );
            }
        }
        assert!(run(req).await.is_err());
        assert!(!root.path().join("records").exists());
    }
}

#[tokio::test]
async fn explicit_runtime_path_is_supported_without_inheriting_other_variables() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request(
        root.path(),
        "import os,pathlib\nassert os.environ['PATH'] == '/usr/bin:/bin'\nassert 'AWS_SECRET_ACCESS_KEY' not in os.environ\npathlib.Path('result.txt').write_text('explicit runtime')\n",
    );
    req.environment
        .insert("PATH".into(), "/usr/bin:/bin".into());
    let record = run(req).await.unwrap();
    assert_eq!(record.status, "succeeded");
    assert_eq!(record.environment_names, ["PATH"]);
}

#[tokio::test]
async fn explicit_cancellation_is_confirmed_by_a_retained_terminal_record() {
    let root = tempfile::tempdir().unwrap();
    let req = request(
        root.path(),
        "import pathlib,time\npathlib.Path('result.txt').write_text('cancelled work survives')\ntime.sleep(20)\n",
    );
    let records = req.records.clone();
    let running = tokio::spawn(run(req));
    let directory = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(entries) = fs::read_dir(&records) {
                for entry in entries.flatten() {
                    if entry.path().join("workspace/result.txt").exists() {
                        return entry.path();
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let id = maxio::execution::runner::request_cancel(&directory).unwrap();
    let record = running.await.unwrap().unwrap();
    assert_eq!(record.id, id);
    assert_eq!(record.status, "cancelled");
    assert_eq!(
        fs::read_to_string(record.workspace.join("result.txt")).unwrap(),
        "cancelled work survives"
    );
    assert!(maxio::execution::runner::request_cancel(&directory).is_err());
}

#[tokio::test]
async fn cancellation_rejects_forged_identity_and_symlink_controls() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let mut record = run(request(root.path(), "print('finished')\n"))
        .await
        .unwrap();
    let directory = record.workspace.parent().unwrap().to_path_buf();
    let path = directory.join("record.json");
    // A retained-record fixture tests validation without signaling any process.
    record.status = "running".into();
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let link = root.path().join("run-link");
    symlink(&directory, &link).unwrap();
    assert!(maxio::execution::runner::request_cancel(&link).is_err());
    let original_id = record.id.clone();
    record.id = uuid::Uuid::new_v4().to_string();
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(maxio::execution::runner::request_cancel(&directory).is_err());
    record.id = original_id;
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let unrelated = root.path().join("unrelated");
    fs::write(&unrelated, "preserve").unwrap();
    symlink(&unrelated, directory.join("cancel.request")).unwrap();
    assert!(maxio::execution::runner::request_cancel(&directory).is_err());
    assert_eq!(fs::read_to_string(unrelated).unwrap(), "preserve");
    fs::remove_file(directory.join("cancel.request")).unwrap();
    fs::rename(&path, directory.join("saved.json")).unwrap();
    symlink(directory.join("saved.json"), &path).unwrap();
    assert!(maxio::execution::runner::request_cancel(&directory).is_err());
}
