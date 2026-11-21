use super::*;

struct Fixture {
    _root: tempfile::TempDir,
    repository: PathBuf,
    workspaces: PathBuf,
    base: String,
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-C"])
        .arg(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("repository");
    let workspaces = root.path().join("workspaces");
    fs::create_dir(&repository).unwrap();
    fs::create_dir(&workspaces).unwrap();
    git(&repository, &["init", "--quiet"]);
    fs::write(repository.join("file.txt"), b"base\n").unwrap();
    git(&repository, &["add", "file.txt"]);
    git(&repository, &["commit", "--quiet", "-m", "initial"]);
    let base = git(&repository, &["rev-parse", "HEAD"]).trim().to_owned();
    Fixture {
        _root: root,
        repository,
        workspaces,
        base,
    }
}
fn binding(f: &Fixture) -> OwnerWorkspaceBinding {
    OwnerWorkspaceBinding::new(
        "fixture-repo",
        &f.repository,
        &f.workspaces,
        &f.base,
        "owned",
    )
    .unwrap()
}
fn request(f: &Fixture) -> WorkspaceSpec {
    WorkspaceSpec {
        repo_identity: "fixture-repo".into(),
        base_revision: f.base.clone(),
        destination_selector: "owned".into(),
        context_refs: vec![],
        patch_ref: None,
    }
}
#[test]
fn workspace_explicit_base_and_owner_identity_survive_recovery() {
    let f = fixture();
    let owner = binding(&f);
    let prepared = WorkspacePlan::prepare(
        &owner,
        &request(&f),
        "execution-1",
        "fixture-workspace-nonce",
    )
    .unwrap()
    .create()
    .unwrap();
    assert_eq!(
        fs::read(prepared.path().join("file.txt")).unwrap(),
        b"base\n"
    );
    let encoded = serde_json::to_string(prepared.identity()).unwrap();
    let identity: OwnedWorkspaceIdentity = serde_json::from_str(&encoded).unwrap();
    drop(prepared);
    let recovered = PreparedWorkspace::recover(&owner, identity).unwrap();
    let destination = recovered.path().to_owned();
    recovered.cleanup().unwrap();
    assert!(!destination.exists());
}
#[test]
fn workspace_head_change_is_refused_before_creation() {
    let f = fixture();
    let plan = WorkspacePlan::prepare(
        &binding(&f),
        &request(&f),
        "execution-head",
        "fixture-workspace-nonce",
    )
    .unwrap();
    let destination = plan.destination().to_owned();
    fs::write(f.repository.join("file.txt"), b"new-head\n").unwrap();
    git(&f.repository, &["add", "file.txt"]);
    git(&f.repository, &["commit", "--quiet", "-m", "head change"]);
    let result = plan.create();
    assert!(
        !destination.exists(),
        "changed HEAD created workspace before refusal"
    );
    assert!(matches!(result, Err(WorkspaceError::RepositoryChanged)));
}
#[test]
fn workspace_inventory_change_is_refused_before_creation() {
    let f = fixture();
    let plan = WorkspacePlan::prepare(
        &binding(&f),
        &request(&f),
        "execution-inventory",
        "fixture-workspace-nonce",
    )
    .unwrap();
    let destination = plan.destination().to_owned();
    let other = f.workspaces.join("unrelated");
    git(
        &f.repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            other.to_str().unwrap(),
            &f.base,
        ],
    );
    let result = plan.create();
    assert!(
        !destination.exists(),
        "changed inventory created workspace before refusal"
    );
    assert!(matches!(result, Err(WorkspaceError::RepositoryChanged)));
}
#[test]
fn workspace_dirty_source_is_refused_without_copying_auth_file() {
    let f = fixture();
    let owner = binding(&f);
    fs::write(f.repository.join("file.txt"), b"unsaved\n").unwrap();
    fs::write(f.repository.join("auth-canary"), b"fixture-only\n").unwrap();
    let result = WorkspacePlan::prepare(
        &owner,
        &request(&f),
        "execution-dirty",
        "fixture-workspace-nonce",
    );
    assert!(!f.workspaces.join("execution-dirty").exists());
    assert!(matches!(result, Err(WorkspaceError::Dirty)));
}
#[test]
fn workspace_owner_base_repo_and_selector_are_not_caller_authority() {
    let f = fixture();
    let owner = binding(&f);
    for field in ["repo", "base", "destination"] {
        let mut spec = request(&f);
        match field {
            "repo" => spec.repo_identity = "other".into(),
            "base" => spec.base_revision = "a".repeat(40),
            _ => spec.destination_selector = "elsewhere".into(),
        };
        let result =
            WorkspacePlan::prepare(&owner, &spec, "execution-scope", "fixture-workspace-nonce");
        assert!(!f.workspaces.join("execution-scope").exists());
        assert!(matches!(result, Err(WorkspaceError::OutsideBinding)));
    }
    for component in ["../escape", "-option", "a/b", ""] {
        assert!(
            WorkspacePlan::prepare(&owner, &request(&f), component, "fixture-workspace-nonce")
                .is_err()
        );
    }
}
#[test]
fn workspace_owner_context_data_is_verified_not_copied_from_checkout() {
    let f = fixture();
    let context = f._root.path().join("context");
    fs::write(&context, b"bounded context").unwrap();
    let digest = hex::encode(Sha256::digest(b"bounded context"));
    let owner = binding(&f)
        .with_reference("context-one", &context, &digest)
        .unwrap();
    let mut spec = request(&f);
    spec.context_refs.push(DigestRef {
        reference: "context-one".into(),
        sha256: digest.clone(),
    });
    let prepared = WorkspacePlan::prepare(
        &owner,
        &spec,
        "execution-context",
        "fixture-workspace-nonce",
    )
    .unwrap()
    .create()
    .unwrap();
    assert_eq!(prepared.contexts()[0].bytes, b"bounded context");
    assert_eq!(prepared.contexts()[0].sha256, digest);
    assert!(!prepared.path().join("context").exists());
    prepared.cleanup().unwrap();
}
#[test]
fn workspace_wrong_requested_digest_has_no_creation_effect() {
    let f = fixture();
    let context = f._root.path().join("context");
    fs::write(&context, b"bounded context").unwrap();
    let digest = hex::encode(Sha256::digest(b"bounded context"));
    let owner = binding(&f)
        .with_reference("context-one", &context, &digest)
        .unwrap();
    let mut spec = request(&f);
    spec.context_refs.push(DigestRef {
        reference: "context-one".into(),
        sha256: "b".repeat(64),
    });
    let result =
        WorkspacePlan::prepare(&owner, &spec, "execution-digest", "fixture-workspace-nonce")
            .and_then(WorkspacePlan::create);
    assert!(
        !f.workspaces.join("execution-digest").exists(),
        "wrong context digest created a workspace"
    );
    assert!(matches!(result, Err(WorkspaceError::Reference)));
}
#[test]
fn workspace_context_change_after_plan_has_no_creation_effect() {
    let f = fixture();
    let context = f._root.path().join("context");
    fs::write(&context, b"bounded context").unwrap();
    let digest = hex::encode(Sha256::digest(b"bounded context"));
    let owner = binding(&f)
        .with_reference("context-one", &context, &digest)
        .unwrap();
    let mut spec = request(&f);
    spec.context_refs.push(DigestRef {
        reference: "context-one".into(),
        sha256: digest,
    });
    let plan = WorkspacePlan::prepare(
        &owner,
        &spec,
        "execution-context-change",
        "fixture-workspace-nonce",
    )
    .unwrap();
    fs::write(context, b"changed").unwrap();
    let result = plan.create();
    assert!(
        !f.workspaces.join("execution-context-change").exists(),
        "changed context created a workspace"
    );
    assert!(matches!(result, Err(WorkspaceError::Reference)));
}
#[test]
fn workspace_digest_pinned_patch_applies_only_inside_owned_tree() {
    let f = fixture();
    let patch = f._root.path().join("patch");
    let bytes=b"diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-base\n+patched\n";
    fs::write(&patch, bytes).unwrap();
    let digest = hex::encode(Sha256::digest(bytes));
    let owner = binding(&f)
        .with_reference("patch-one", &patch, &digest)
        .unwrap();
    let mut spec = request(&f);
    spec.patch_ref = Some(DigestRef {
        reference: "patch-one".into(),
        sha256: digest,
    });
    let prepared =
        WorkspacePlan::prepare(&owner, &spec, "execution-patch", "fixture-workspace-nonce")
            .unwrap()
            .create()
            .unwrap();
    assert_eq!(
        fs::read(prepared.path().join("file.txt")).unwrap(),
        b"patched\n"
    );
    assert_eq!(fs::read(f.repository.join("file.txt")).unwrap(), b"base\n");
    let destination = prepared.path().to_owned();
    assert!(matches!(prepared.cleanup(), Err(WorkspaceError::Dirty)));
    assert_eq!(
        fs::read(destination.join("file.txt")).unwrap(),
        b"patched\n"
    );
}
#[test]
fn workspace_dirty_cleanup_preserves_work() {
    let f = fixture();
    let prepared = WorkspacePlan::prepare(
        &binding(&f),
        &request(&f),
        "execution-cleanup",
        "fixture-workspace-nonce",
    )
    .unwrap()
    .create()
    .unwrap();
    let destination = prepared.path().to_owned();
    fs::write(destination.join("file.txt"), b"user-work\n").unwrap();
    let result = prepared.cleanup();
    let preserved = fs::read(destination.join("file.txt"));
    assert!(
        matches!(preserved.as_deref(), Ok(bytes) if bytes == b"user-work\n"),
        "dirty cleanup discarded user work"
    );
    assert!(matches!(result, Err(WorkspaceError::Dirty)));
}
#[test]
fn workspace_replaced_clean_tree_is_not_cleanup_authority() {
    let f = fixture();
    let prepared = WorkspacePlan::prepare(
        &binding(&f),
        &request(&f),
        "execution-replacement",
        "fixture-workspace-nonce",
    )
    .unwrap()
    .create()
    .unwrap();
    let destination = prepared.path().to_owned();
    git(
        &f.repository,
        &["worktree", "remove", destination.to_str().unwrap()],
    );
    git(
        &f.repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            destination.to_str().unwrap(),
            &f.base,
        ],
    );
    let result = prepared.cleanup();
    assert!(
        destination.exists(),
        "replacement worktree was removed using old ownership"
    );
    assert!(matches!(result, Err(WorkspaceError::Ownership)));
}
#[test]
fn workspace_repository_hook_is_not_executed() {
    let f = fixture();
    let marker = f._root.path().join("hook-fired");
    let hook = f.repository.join(".git/hooks/post-checkout");
    let shell = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("sh"))
        .find(|p| p.is_file())
        .unwrap()
        .canonicalize()
        .unwrap();
    fs::write(
        &hook,
        format!(
            "#!{}\nprintf marker > '{}'\n",
            shell.display(),
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = WorkspacePlan::prepare(
        &binding(&f),
        &request(&f),
        "execution-hook",
        "fixture-workspace-nonce",
    )
    .unwrap()
    .create()
    .unwrap();
    assert!(
        !marker.exists(),
        "repository checkout hook ran during preparation"
    );
    prepared.cleanup().unwrap();
}
#[test]
fn workspace_local_filters_and_includes_are_refused() {
    for section in ["filter.toy.smudge", "include.path"] {
        let f = fixture();
        git(&f.repository, &["config", section, "fixture-only"]);
        let result = OwnerWorkspaceBinding::new(
            "fixture-repo",
            &f.repository,
            &f.workspaces,
            &f.base,
            "owned",
        );
        assert!(matches!(result, Err(WorkspaceError::UnsafeConfiguration)));
        assert!(fs::read_dir(&f.workspaces).unwrap().next().is_none());
    }
}

#[test]
fn workspace_incarnation_marker_is_required_before_cleanup() {
    let f = fixture();
    let prepared = WorkspacePlan::prepare(
        &binding(&f),
        &request(&f),
        "execution-marker",
        "fixture-workspace-nonce",
    )
    .unwrap()
    .create()
    .unwrap();
    let destination = prepared.path().to_owned();
    let marker = git_directory(&destination).unwrap().join(OWNERSHIP_MARKER);
    fs::write(
        marker,
        b"executor-workspace-v1\nexecution-marker\nother-incarnation\n",
    )
    .unwrap();
    let result = prepared.cleanup();
    assert!(
        destination.exists(),
        "mismatched workspace incarnation marker removed checkout"
    );
    assert!(matches!(result, Err(WorkspaceError::Ownership)));
}

#[test]
fn workspace_local_worktree_config_cannot_redirect_patch_effect() {
    let f = fixture();
    let other = f._root.path().join("unrelated");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("file.txt"), b"base\n").unwrap();
    git(
        &f.repository,
        &["config", "core.worktree", other.to_str().unwrap()],
    );
    let patch = f._root.path().join("patch");
    let bytes=b"diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-base\n+patched\n";
    fs::write(&patch, bytes).unwrap();
    let digest = hex::encode(Sha256::digest(bytes));
    let owner = binding(&f)
        .with_reference("patch-one", &patch, &digest)
        .unwrap();
    let mut spec = request(&f);
    spec.patch_ref = Some(DigestRef {
        reference: "patch-one".into(),
        sha256: digest,
    });
    let prepared = WorkspacePlan::prepare(
        &owner,
        &spec,
        "execution-redirect",
        "fixture-workspace-nonce",
    )
    .unwrap()
    .create()
    .unwrap();
    assert_eq!(
        fs::read(other.join("file.txt")).unwrap(),
        b"base\n",
        "repository config redirected patch outside owned tree"
    );
    assert_eq!(
        fs::read(prepared.path().join("file.txt")).unwrap(),
        b"patched\n"
    );
}
