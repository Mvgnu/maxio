//! Worker-side process regressions. These use real ordinary executables; they do
//! not authenticate providers or substitute a mock completion for a child process.
use maxio::execution::{AdapterKind, PermissionMode};
use maxio::fabric::contract::*;
use maxio::fabric::worker::{ExecutionProfile, execute_prepared, validate_profiles};
use maxio::workspace::{FileVersion, RevisionRef};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::sync::watch;

fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn profile() -> ExecutionProfile {
    ExecutionProfile {
        name: "python".into(),
        adapter: AdapterKind::Command,
        executable: "/usr/bin/python3".into(),
        args: vec!["task.py".into(), "literal;$HOME".into()],
        permission: PermissionMode::WorkspaceWrite,
        environment: BTreeMap::new(),
    }
}

fn assignment(source: &Path) -> ClaimedJob {
    let (sha256, size) = maxio::files::hash_file(&source.join("task.py")).unwrap();
    let workspace_id = id();
    let revision = RevisionRef {
        revision: id(),
        sha256: "a".repeat(64),
    };
    let job_id = id();
    ClaimedJob {
        job: JobRecord {
            job_id: job_id.clone(),
            submitted_by: id(),
            workspace_id: workspace_id.clone(),
            base: ManagedHead {
                authority_id: id(),
                workspace_id,
                generation: 1,
                revision: revision.clone(),
            },
            profile: "python".into(),
            inputs: vec![JobInput {
                path: "task.py".into(),
                revision,
                version: FileVersion {
                    sha256,
                    size,
                    blob: format!("maxio-workspaces/jobs/blobs/{}", id()),
                },
            }],
            output_selectors: vec![PathScope::Exact {
                path: "result.txt".into(),
            }],
            resources: Resources::default(),
            timeout_seconds: 10,
            required_worker: None,
            output_policy: OutputPolicy::Retain,
            state: JobState::Running,
            created_at_unix_ms: 0,
            cancel_requested: false,
            decision: None,
            attempts: vec![],
        },
        attempt: AttemptBinding {
            job_id,
            attempt_id: id(),
            worker_id: id(),
            worker_incarnation: id(),
        },
        lease: None,
        prompt: None,
    }
}

#[test]
fn local_profiles_refuse_duplicate_names_and_unsafe_adapter_arguments() {
    assert!(validate_profiles(&[profile()]).is_ok());
    assert!(validate_profiles(&[profile(), profile()]).is_err());
    let mut relative = profile();
    relative.executable = "python3".into();
    assert!(validate_profiles(&[relative]).is_err());
    let mut provider = profile();
    provider.adapter = AdapterKind::Codex;
    assert!(validate_profiles(&[provider]).is_err());
    let mut readonly = profile();
    readonly.permission = PermissionMode::ReadOnly;
    assert!(validate_profiles(&[readonly]).is_err());
}

#[tokio::test]
async fn admitted_worker_runs_real_command_and_preserves_unselected_source() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("task.py"), "import os,pathlib,sys\nassert sys.argv[1] == 'literal;$HOME'\nassert not any(k.startswith(('MAXIO_', 'AWS_')) for k in os.environ)\nassert not pathlib.Path('unrelated.txt').exists()\npathlib.Path('result.txt').write_text('actual remote worker core')\nprint('worker ran')\n").unwrap();
    fs::write(source.join("unrelated.txt"), "preserve").unwrap();
    let claim = assignment(&source);
    let (_sender, receiver) = watch::channel(false);
    let record = execute_prepared(
        &profile(),
        &claim,
        &source,
        &root.path().join("runs"),
        receiver,
    )
    .await
    .unwrap();
    assert_eq!(record.status, "succeeded");
    assert!(!record.published);
    assert_eq!(record.input_files.len(), 1);
    assert_eq!(record.output_files.len(), 1);
    assert_eq!(
        fs::read_to_string(record.workspace.join("result.txt")).unwrap(),
        "actual remote worker core"
    );
    assert_eq!(
        fs::read_to_string(source.join("unrelated.txt")).unwrap(),
        "preserve"
    );
    assert!(!source.join("result.txt").exists());
}

#[tokio::test]
async fn changed_admitted_input_never_launches_and_retains_failed_run() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("task.py"), "raise SystemExit('original')\n").unwrap();
    let claim = assignment(&source);
    fs::write(
        source.join("task.py"),
        "import pathlib\npathlib.Path('result.txt').write_text('must not launch')\n",
    )
    .unwrap();
    let (_sender, receiver) = watch::channel(false);
    let record = execute_prepared(
        &profile(),
        &claim,
        &source,
        &root.path().join("runs"),
        receiver,
    )
    .await
    .unwrap();
    assert_eq!(record.status, "failed");
    assert!(record.detail.unwrap().contains("input identity mismatch"));
    assert!(!record.workspace.join("result.txt").exists());
    assert!(record.workspace.join("task.py").exists());
}

#[tokio::test]
async fn remote_stop_intent_uses_live_runner_cancellation_and_keeps_edits() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("task.py"), "import pathlib,time\npathlib.Path('result.txt').write_text('partial work survives')\nprint('started', flush=True)\ntime.sleep(30)\n").unwrap();
    let claim = assignment(&source);
    let records = root.path().join("runs");
    let (sender, receiver) = watch::channel(false);
    let selected = profile();
    let execution = execute_prepared(&selected, &claim, &source, &records, receiver);
    let cancel = async {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if records.exists() {
                    for entry in fs::read_dir(&records).unwrap() {
                        if entry.unwrap().path().join("workspace/result.txt").exists() {
                            sender.send(true).unwrap();
                            return;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    };
    let (record, ()) = tokio::join!(execution, cancel);
    let record = record.unwrap();
    assert_eq!(record.status, "cancelled");
    assert_eq!(
        fs::read_to_string(record.workspace.join("result.txt")).unwrap(),
        "partial work survives"
    );
    assert!(
        record
            .workspace
            .parent()
            .unwrap()
            .join("cancel.request")
            .exists()
    );
    assert!(!record.published);
}

#[tokio::test]
async fn named_provider_profiles_reuse_real_adapters_with_labelled_fixtures() {
    use std::os::unix::fs::PermissionsExt;
    for adapter in [AdapterKind::Codex, AdapterKind::Claude] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("task.py"), "# selected provider context\n").unwrap();
        let mut claim = assignment(&source);
        claim.prompt = Some("worker protocol fixture prompt".into());
        let executable = root.path().join("provider-protocol-fixture");
        fs::write(&executable, r#"#!/usr/bin/python3
# Protocol fixture only. This executable performs no authentication or model call.
import sys,json,pathlib
if '--version' in sys.argv:
    print('2.1.309 worker-protocol-fixture'); sys.exit(0)
if '--help' in sys.argv:
    print('--ask-for-approval never --sandbox read-only workspace-write --json --cd --color --skip-git-repo-check --restricted --print --output-format stream-json --verbose --permission-mode dontAsk --permission-prompts --tools --allowedTools --disallowedTools'); sys.exit(0)
assert sys.stdin.read() == 'worker protocol fixture prompt'
assert pathlib.Path('task.py').is_file()
assert not any(arg in sys.argv for arg in ['--yolo','--dangerously-skip-permissions'])
pathlib.Path('result.txt').write_text('labelled provider fixture output')
if '--restricted' in sys.argv:
    assert 'Bash' not in ','.join(sys.argv)
    print(json.dumps({'type':'result','subtype':'success','is_error':False,'session_id':'worker-fixture','permission_denials':[]}))
else:
    assert sys.argv[1:4] == ['--ask-for-approval','never','exec']
    print(json.dumps({'type':'thread.started','thread_id':'worker-fixture'}))
    print(json.dumps({'type':'turn.completed'}))
"#).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let mut selected = profile();
        selected.adapter = adapter;
        selected.executable = executable;
        selected.args.clear();
        selected.environment.insert(
            if adapter == AdapterKind::Codex {
                "CODEX_API_KEY"
            } else {
                "ANTHROPIC_API_KEY"
            }
            .into(),
            "fixture-only-not-a-provider-credential".into(),
        );
        let (_sender, receiver) = watch::channel(false);
        let record = execute_prepared(
            &selected,
            &claim,
            &source,
            &root.path().join("runs"),
            receiver,
        )
        .await
        .unwrap();
        assert_eq!(record.status, "succeeded", "{:?}", record.detail);
        assert_eq!(record.adapter, adapter);
        assert_eq!(
            record.provider_session_id.as_deref(),
            Some("worker-fixture")
        );
        assert!(!record.published);
        assert_eq!(
            fs::read_to_string(record.workspace.join("result.txt")).unwrap(),
            "labelled provider fixture output"
        );
    }
}
