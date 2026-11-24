#[path = "support/spawn.rs"]
mod spawn;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, PermissionsExt},
            net::UnixListener,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use xmsg::install_paths::{FixtureHomeLookup, Platform, ResolveEnv, ResolveRequest};

struct Process(Option<Child>);
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            if child.try_wait().ok().flatten().is_none() {
                if let Ok(pid) = i32::try_from(child.id()) {
                    if unsafe { libc::getpgid(pid) } == pid {
                        unsafe { libc::kill(-pid, libc::SIGKILL) };
                    }
                }
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}
fn run(mut command: Command, input: &[u8]) -> Output {
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = Process(Some(command.spawn().unwrap()));
    let mut stdin = child.0.as_mut().unwrap().stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "owned adapter command did not finish"
        );
        thread::yield_now();
    }
    child.0.take().unwrap().wait_with_output().unwrap()
}
struct FakeAgent {
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
    events: Arc<Mutex<Vec<(PathBuf, String)>>>,
    sockets: Vec<(PathBuf, u64, u64)>,
    directories: Vec<(PathBuf, u64, u64)>,
}
impl FakeAgent {
    fn bind(paths: BTreeSet<PathBuf>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut this = Self {
            stop,
            threads: Vec::new(),
            events,
            sockets: Vec::new(),
            directories: Vec::new(),
        };
        for socket in paths {
            let parent = socket.parent().unwrap();
            if !this.directories.iter().any(|(p, _, _)| p == parent) {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(parent)
                    .expect("fixture must never reuse an incumbent namespace");
                let m = fs::symlink_metadata(parent).unwrap();
                this.directories
                    .push((parent.to_path_buf(), m.dev(), m.ino()));
            }
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            let m = fs::symlink_metadata(&socket).unwrap();
            this.sockets.push((socket.clone(), m.dev(), m.ino()));
            listener.set_nonblocking(true).unwrap();
            let stopped = this.stop.clone();
            let received = this.events.clone();
            this.threads.push(thread::spawn(move||{
                let mut registrations=Vec::new();
                while !stopped.load(Ordering::Acquire){
                    let (mut stream,_)=match listener.accept(){Ok(value)=>value,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{let mut fd=libc::pollfd{fd:listener.as_raw_fd(),events:libc::POLLIN,revents:0};unsafe{libc::poll(&mut fd,1,20)};continue;},Err(_)=>return};
                    stream.set_nonblocking(false).unwrap();stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                    let mut line=String::new();if BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).is_err(){continue;}
                    let frame:Value=match serde_json::from_str(&line){Ok(frame)=>frame,Err(_)=>continue};let action=frame["action"].as_str().unwrap_or("").to_string();received.lock().unwrap().push((socket.clone(),action.clone()));
                    let answer=if action=="list"{json!({"status":"ok","recipients":[],"nodes":[],"total":0,"truncated":false})}else{json!({"status":"ok"})};let _=writeln!(stream,"{answer}");
                    if action=="mcp_start"{registrations.push(stream);}
                }
            }));
        }
        this
    }
}
impl Drop for FakeAgent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.threads.drain(..) {
            let _ = worker.join();
        }
        for (file, dev, ino) in &self.sockets {
            if fs::symlink_metadata(file).is_ok_and(|m| m.dev() == *dev && m.ino() == *ino) {
                let _ = fs::remove_file(file);
            }
        }
        for (folder, dev, ino) in self.directories.iter().rev() {
            if fs::symlink_metadata(folder).is_ok_and(|m| m.dev() == *dev && m.ino() == *ino) {
                let _ = fs::remove_dir(folder);
            }
        }
    }
}
fn environment<'a>(home: &Path, runtime: &Path, lookup: &'a FixtureHomeLookup) -> ResolveEnv<'a> {
    ResolveEnv {
        home: Some(home.as_os_str().to_owned()),
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: Some(runtime.as_os_str().to_owned()),
        darwin_user_temp_dir: None,
        system_tmp: "/tmp".into(),
        platform: Platform::current(),
        euid: unsafe { libc::geteuid() },
        home_lookup: lookup,
    }
}
fn command(executable: &Path, home: &Path, wrong_runtime: &Path, wrong_db: &Path) -> Command {
    let mut command = spawn::command(executable);
    command
        .env_clear()
        .env("HOME", home)
        .env("XDG_RUNTIME_DIR", wrong_runtime)
        .env("XDG_STATE_HOME", home.join("changed-xdg-state"))
        .env("XDG_CONFIG_HOME", home.join("changed-xdg-config"))
        .env("XMSG_DB_PATH", wrong_db)
        .env("XMSG_URL", "http://127.0.0.1:0");
    if let Some(build_top) = std::env::var_os("NIX_BUILD_TOP") {
        command.env("NIX_BUILD_TOP", build_top);
    }
    command
}

fn verify_artifact(executable: &Path, artifact: &Value, test_hooks: bool) {
    assert_eq!(
        fs::canonicalize(executable).unwrap(),
        fs::canonicalize(artifact["executable"].as_str().unwrap()).unwrap(),
        "executed command is not the captured compiler artifact"
    );
    assert_eq!(
        hex::encode(Sha256::digest(fs::read(executable).unwrap())),
        artifact["sha256"].as_str().unwrap(),
        "compiler artifact changed before or after execution"
    );
    let features = artifact["features"].as_array().unwrap();
    assert_eq!(features.iter().any(|f| f == "test-hooks"), test_hooks);
    assert_eq!(artifact["profile"]["test"], false);
}

#[test]
fn installed_mcp_and_hook_keep_selected_endpoints_after_environment_changes() {
    check_command_pins(false);
    check_command_pins(true);
}
fn check_command_pins(original_runtime_unset: bool) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home ' $(printf wrong)");
    fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
    let system_tmp = fs::canonicalize("/tmp").unwrap();
    let runtime_a = tempfile::Builder::new()
        .prefix("xa-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&system_tmp)
        .unwrap();
    let runtime_b = tempfile::Builder::new()
        .prefix("xb-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&system_tmp)
        .unwrap();
    let lookup = FixtureHomeLookup(Some(home.clone()));
    assert_eq!(
        fs::metadata(runtime_a.path()).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(runtime_b.path()).unwrap().mode() & 0o777,
        0o700
    );
    let mut selected = environment(&home, runtime_a.path(), &lookup);
    if original_runtime_unset {
        selected.xdg_runtime_dir = None;
    }
    let db = home.join("selected-state/xmsg.db");
    let input = ResolveRequest {
        db_path: Some(db.clone()),
        ..Default::default()
    };
    let binary = home.join("candidate ' executable");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_xmsg"), &binary).unwrap();
    let request = xmsg::install::Request::resolve(&input, &selected, binary, None)
        .unwrap()
        .with_fixture_policy_roots(vec![home.join("synthetic-managed-policy")]);
    xmsg::install::plan(&request, xmsg::install::Action::Install)
        .unwrap()
        .apply()
        .unwrap();
    let wrong_db = home.join("other-state/xmsg.db");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(wrong_db.parent().unwrap())
        .unwrap();
    let expected = xmsg::install_paths::resolve_install(&input, &selected)
        .unwrap()
        .agent_sock
        .unwrap()
        .path;
    let mut endpoints = BTreeSet::new();
    for state in [&db, &wrong_db] {
        for runtime in [None, Some(runtime_a.path()), Some(runtime_b.path())] {
            let mut env = environment(&home, runtime_a.path(), &lookup);
            env.xdg_runtime_dir = runtime.map(|p| p.as_os_str().to_owned());
            let req = ResolveRequest {
                db_path: Some(state.clone()),
                ..Default::default()
            };
            endpoints.insert(
                xmsg::install_paths::resolve_install(&req, &env)
                    .unwrap()
                    .agent_sock
                    .unwrap()
                    .path,
            );
        }
    }
    let peers = FakeAgent::bind(endpoints);
    let installed: Value =
        serde_json::from_slice(&fs::read(home.join(".claude.json")).unwrap()).unwrap();
    let mcp = &installed["mcpServers"]["xmsg"];
    let executable = PathBuf::from(mcp["command"].as_str().unwrap());
    let provenance = std::env::var_os("XMSG_CLAUDE_COMMAND_PROVENANCE").map(|file| {
        let receipt: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
        verify_artifact(&executable, &receipt["candidate"], true);
        receipt
    });
    let mut client = command(&executable, &home, runtime_b.path(), &wrong_db);
    for argument in mcp["args"].as_array().unwrap() {
        client.arg(argument.as_str().unwrap());
    }
    for (key, value) in mcp["env"].as_object().unwrap() {
        client.env(key, value.as_str().unwrap());
    }
    let mcp_input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list\",\"arguments\":{}}}\n";
    let output = run(client, mcp_input);
    assert!(
        output.status.success(),
        "installed MCP command failed: status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let replies = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let answer = replies
        .iter()
        .find(|reply| reply["id"] == 2)
        .expect("MCP tool reply");
    assert_ne!(
        answer["result"]["isError"], true,
        "installed MCP command did not reach a controlled endpoint"
    );
    let settings: Value =
        serde_json::from_slice(&fs::read(home.join(".claude/settings.json")).unwrap()).unwrap();
    let hook = settings["hooks"]["SubagentStart"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let mut shell = command(Path::new("/bin/sh"), &home, runtime_b.path(), &wrong_db);
    shell.arg("-c").arg(hook);
    let output=run(shell,b"{\"hook_event_name\":\"SubagentStart\",\"agent_id\":\"22222222-2222-4222-8222-222222222222\",\"agent_type\":\"fixture\"}");
    assert!(
        output.status.success(),
        "installed hook command failed: status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let events = peers.events.lock().unwrap().clone();
    assert!(events.iter().all(|(endpoint,_)|*endpoint==expected),"installed commands resolved changed-environment endpoints instead of the selected endpoint: {events:?}");
    assert_eq!(
        events.iter().filter(|(_, action)| action == "list").count(),
        1,
        "installed MCP command did not perform its list operation"
    );
    assert_eq!(
        events
            .iter()
            .filter(|(_, action)| action == "subagent")
            .count(),
        1,
        "installed hook command did not perform its lifecycle operation"
    );
    assert!(events.iter().any(|(_, action)| action == "mcp_start"));
    if let Some(receipt) = provenance {
        verify_artifact(&executable, &receipt["candidate"], true);
        if original_runtime_unset {
            let release = PathBuf::from(receipt["release"]["executable"].as_str().unwrap());
            verify_artifact(&release, &receipt["release"], false);
            assert!(std::env::var_os("NIX_BUILD_TOP").is_some());
            let tmp = fs::metadata(fs::canonicalize("/tmp").unwrap()).unwrap();
            assert_eq!(tmp.uid(), 65534, "unsafe shared-tmp fixture is unavailable");
            assert_ne!(tmp.mode() & 0o1000, 0);
            let before = peers.events.lock().unwrap().len();
            let mut release_command = command(&release, &home, runtime_b.path(), &wrong_db);
            for argument in mcp["args"].as_array().unwrap() {
                release_command.arg(argument.as_str().unwrap());
            }
            for (key, value) in mcp["env"].as_object().unwrap() {
                release_command.env(key, value.as_str().unwrap());
            }
            let refused = run(release_command, mcp_input);
            assert_eq!(
                peers.events.lock().unwrap().len(),
                before,
                "release control reached an agent endpoint"
            );
            assert!(
                !refused.status.success(),
                "release control accepted unsafe shared tmp"
            );
            assert!(
                String::from_utf8_lossy(&refused.stderr).contains("UnsafeSharedTmp"),
                "release control returned a different error: {}",
                String::from_utf8_lossy(&refused.stderr)
            );
            verify_artifact(&release, &receipt["release"], false);
            eprintln!("default-release: typed UnsafeSharedTmp refusal, zero agent operations");
        }
    }
}

#[test]
fn adapter_argument_refusals_and_help_never_echo_values() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_xmsg"));
    let canary = "SYNTHETIC_ARGUMENT_VALUE_CANARY";
    let mut invalid = command(binary, root.path(), root.path(), root.path());
    invalid.args(["install", "claude", canary]);
    let output = run(invalid, b"");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(canary));
    let mut help = command(binary, root.path(), root.path(), Path::new(canary));
    help.args(["install", "claude", "--help"]);
    let output = run(help, b"");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(canary));
    assert_eq!(
        fs::read_dir(root.path()).unwrap().count(),
        0,
        "argument handling prepared an adapter directory"
    );
}
