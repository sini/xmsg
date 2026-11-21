use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use super::authority::{
    Audit, Authority, AuthorityConfig, AuthorityError, Class, DelegatedGrant, Record, Scope,
};

const SOCKET: &str = "admin.sock";
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(clap::Args, Debug)]
pub struct Args {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand, Debug)]
enum Action {
    Mint {
        #[command(subcommand)]
        class: Mint,
    },
    List,
    Revoke {
        record_id: String,
    },
    Rebind {
        #[arg(long)]
        owner: String,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        subject: String,
    },
    Audit,
}

#[derive(clap::Subcommand, Debug)]
enum Mint {
    Machine {
        #[arg(long)]
        owner: String,
        #[arg(long)]
        name: String,
        #[arg(long, required = true)]
        scope: Vec<String>,
        #[arg(long)]
        expires_at: Option<i64>,
        #[arg(long)]
        rate: u32,
    },
    Delegated {
        #[arg(long)]
        owner: String,
        #[arg(long)]
        grant_file: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    MintMachine {
        owner: String,
        name: String,
        scope: Vec<Scope>,
        expires_at: Option<i64>,
        rate: u32,
    },
    MintDelegated {
        owner: String,
        grant: DelegatedGrant,
    },
    List {},
    Revoke {
        record_id: String,
    },
    Rebind {
        owner: String,
        issuer: String,
        subject: String,
    },
    Audit {},
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Issued { handle: String },
    Listed { records: Vec<ListedRecord> },
    Audited { records: Vec<Audit> },
    Done {},
    Refused {},
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListedRecord {
    record_id: String,
    class: Class,
    principal: String,
    on_behalf_of: Option<String>,
    created_at: i64,
    last_used_at: i64,
}

impl From<Record> for ListedRecord {
    fn from(record: Record) -> Self {
        Self {
            record_id: record.record_id,
            class: record.class,
            principal: record.principal,
            on_behalf_of: record.on_behalf_of,
            created_at: record.created_at,
            last_used_at: record.last_used_at,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("invalid Mission Control administrative configuration or input")]
    Configuration,
    #[error("Mission Control admin socket unavailable")]
    Socket,
    #[error("Mission Control administrative request refused")]
    Refused,
    #[error("Mission Control admin exchange interrupted; result may be unknown")]
    Interrupted,
    #[error("Mission Control administrative output unavailable")]
    Output,
}

impl TryFrom<Action> for Operation {
    type Error = AdminError;

    fn try_from(action: Action) -> Result<Self, Self::Error> {
        Ok(match action {
            Action::Mint {
                class:
                    Mint::Machine {
                        owner,
                        name,
                        scope,
                        expires_at,
                        rate,
                    },
            } => Self::MintMachine {
                owner,
                name,
                scope: scope
                    .iter()
                    .map(|value| serde_json::from_str(value).map_err(|_| AdminError::Configuration))
                    .collect::<Result<_, _>>()?,
                expires_at,
                rate,
            },
            Action::Mint {
                class: Mint::Delegated { owner, grant_file },
            } => {
                let file = fs::File::open(grant_file).map_err(|_| AdminError::Configuration)?;
                let mut bytes = Vec::new();
                io::Read::read_to_end(
                    &mut io::Read::take(file, MAX_FRAME_BYTES as u64 + 1),
                    &mut bytes,
                )
                .map_err(|_| AdminError::Configuration)?;
                if bytes.len() > MAX_FRAME_BYTES {
                    return Err(AdminError::Configuration);
                }
                Self::MintDelegated {
                    owner,
                    grant: serde_json::from_slice(&bytes).map_err(|_| AdminError::Configuration)?,
                }
            }
            Action::List => Self::List {},
            Action::Revoke { record_id } => Self::Revoke { record_id },
            Action::Rebind {
                owner,
                issuer,
                subject,
            } => Self::Rebind {
                owner,
                issuer,
                subject,
            },
            Action::Audit => Self::Audit {},
        })
    }
}

fn apply(authority: &Authority, operation: Operation) -> Reply {
    let label = match &operation {
        Operation::MintMachine { .. } => "mint_machine",
        Operation::MintDelegated { .. } => "mint_delegated",
        Operation::List {} => "list",
        Operation::Revoke { .. } => "revoke",
        Operation::Rebind { .. } => "rebind",
        Operation::Audit {} => "audit",
    };
    let result =
        match operation {
            Operation::MintMachine {
                owner,
                name,
                scope,
                expires_at,
                rate,
            } => authority
                .mint_machine(&owner, &name, scope, expires_at, rate)
                .map(|issued| Reply::Issued {
                    handle: issued.handle,
                }),
            Operation::MintDelegated { owner, grant } => authority
                .mint_delegated(&owner, grant)
                .map(|issued| Reply::Issued {
                    handle: issued.handle,
                }),
            Operation::List {} => authority.list().map(|records| Reply::Listed {
                records: records.into_iter().map(ListedRecord::from).collect(),
            }),
            Operation::Revoke { record_id } => authority.revoke(&record_id).map(|_| Reply::Done {}),
            Operation::Rebind {
                owner,
                issuer,
                subject,
            } => authority
                .rebind(&owner, &issuer, &subject)
                .map(|_| Reply::Done {}),
            Operation::Audit {} => authority
                .audit_records()
                .map(|records| Reply::Audited { records }),
        };
    result.unwrap_or_else(|_| {
        let _ = authority.audit_admin_refusal(label);
        Reply::Refused {}
    })
}

fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn owner_directory(directory: &Path) -> Result<(), AdminError> {
    let meta = fs::symlink_metadata(directory).map_err(|_| AdminError::Socket)?;
    if !meta.is_dir() || meta.uid() != uid() || meta.mode() & 0o7777 != 0o700 {
        return Err(AdminError::Socket);
    }
    Ok(())
}

fn check_peer(stream: &UnixStream, owner_uid: u32) -> Result<(), AdminError> {
    match stream.peer_cred() {
        Ok(peer) if peer.uid() == owner_uid => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => Ok(()),
        _ => Err(AdminError::Socket),
    }
}

pub(crate) struct Listener {
    inner: UnixListener,
    socket: PathBuf,
    identity: (u64, u64),
}

impl Drop for Listener {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.socket).is_ok_and(|meta| {
            (meta.dev(), meta.ino()) == self.identity && meta.file_type().is_socket()
        }) {
            let _ = fs::remove_file(&self.socket);
        }
    }
}

pub(crate) fn bind(directory: &Path, _authority: &Authority) -> Result<Listener, AdminError> {
    owner_directory(directory)?;
    let socket = directory.join(SOCKET);
    match fs::symlink_metadata(&socket) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == uid() => {
            fs::remove_file(&socket).map_err(|_| AdminError::Socket)?;
        }
        Ok(_) => return Err(AdminError::Socket),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(AdminError::Socket),
    }
    let inner = UnixListener::bind(&socket).map_err(|_| AdminError::Socket)?;
    let meta = fs::symlink_metadata(&socket).map_err(|_| AdminError::Socket)?;
    let listener = Listener {
        inner,
        socket,
        identity: (meta.dev(), meta.ino()),
    };
    fs::set_permissions(&listener.socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| AdminError::Socket)?;
    Ok(listener)
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, AdminError> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| AdminError::Interrupted)? as usize;
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(AdminError::Interrupted);
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| AdminError::Interrupted)?;
    serde_json::from_slice(&bytes).map_err(|_| AdminError::Interrupted)
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, frame: &T) -> Result<(), AdminError> {
    let bytes = serde_json::to_vec(frame).map_err(|_| AdminError::Interrupted)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(AdminError::Interrupted);
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| AdminError::Interrupted)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| AdminError::Interrupted)
}

pub(crate) async fn serve(listener: Listener, authority: Arc<Authority>) -> Result<(), AdminError> {
    loop {
        let (mut stream, _) = listener
            .inner
            .accept()
            .await
            .map_err(|_| AdminError::Socket)?;
        if check_peer(&stream, uid()).is_err() {
            continue;
        }
        let Ok(Ok(operation)) = tokio::time::timeout(IPC_TIMEOUT, read_frame(&mut stream)).await
        else {
            continue;
        };
        let authority = authority.clone();
        let reply = tokio::task::spawn_blocking(move || apply(&authority, operation))
            .await
            .map_err(|_| AdminError::Interrupted)?;
        let _ = tokio::time::timeout(IPC_TIMEOUT, write_frame(&mut stream, &reply)).await;
    }
}

async fn call_live(directory: &Path, operation: &Operation) -> Result<Reply, AdminError> {
    owner_directory(directory)?;
    let mut stream = tokio::time::timeout(IPC_TIMEOUT, UnixStream::connect(directory.join(SOCKET)))
        .await
        .map_err(|_| AdminError::Socket)?
        .map_err(|_| AdminError::Socket)?;
    check_peer(&stream, uid())?;
    tokio::time::timeout(IPC_TIMEOUT, async {
        write_frame(&mut stream, operation).await?;
        read_frame(&mut stream).await
    })
    .await
    .map_err(|_| AdminError::Interrupted)?
}

fn print_reply(reply: Reply, mut output: impl Write) -> Result<(), AdminError> {
    match reply {
        Reply::Issued { handle } => writeln!(output, "{handle}").map_err(|_| AdminError::Output),
        Reply::Listed { records } => {
            serde_json::to_writer(&mut output, &records).map_err(|_| AdminError::Output)?;
            writeln!(output).map_err(|_| AdminError::Output)
        }
        Reply::Audited { records } => {
            serde_json::to_writer(&mut output, &records).map_err(|_| AdminError::Output)?;
            writeln!(output).map_err(|_| AdminError::Output)
        }
        Reply::Done {} => Ok(()),
        Reply::Refused {} => Err(AdminError::Refused),
    }
}

async fn execute(
    directory: &Path,
    operation: Operation,
    load_config: impl FnOnce() -> Result<AuthorityConfig, AuthorityError>,
) -> Result<(Reply, bool), AdminError> {
    match Authority::open_with_config(directory, load_config) {
        Ok(authority) => Ok((apply(&authority, operation), true)),
        Err(AuthorityError::Busy) => Ok((call_live(directory, &operation).await?, false)),
        Err(_) => Err(AdminError::Configuration),
    }
}

pub(crate) async fn run(
    args: Args,
    load_config: impl FnOnce(&Path) -> Result<AuthorityConfig, AdminError>,
) -> Result<(), AdminError> {
    let operation = args.action.try_into()?;
    let (reply, offline) = execute(&args.state_dir, operation, || {
        let config = args.config.as_deref().ok_or(AuthorityError::Invalid)?;
        load_config(config).map_err(|_| AuthorityError::Invalid)
    })
    .await?;
    print_reply(reply, io::stdout().lock())?;
    if offline {
        eprintln!("Administrative action ran offline. Changes take effect at the next start.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::{json, Value};

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: Args,
    }

    fn state_dir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn owner_cli_and_ipc_require_explicit_scope_and_endpoint_targets() {
        assert!(Cli::try_parse_from([
            "admin",
            "--state-dir",
            ".",
            "mint",
            "machine",
            "--owner",
            "owner@example.test",
            "--name",
            "monitor",
            "--rate",
            "2",
        ])
        .is_err());
        assert!(serde_json::from_value::<Operation>(json!({
            "action": "mint_delegated", "owner": "owner@example.test",
            "grant": {
                "holder": "agent", "verbs": ["send"], "targets": [{"node": "node"}],
                "expires_at": 123, "rate": 2
            }
        }))
        .is_err());
        assert!(
            serde_json::from_value::<Operation>(json!({"action": "list", "extra": true})).is_err()
        );
        assert!(
            serde_json::from_value::<Reply>(json!({"status": "done", "handle": "unexpected"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn owner_ipc_rejects_mismatched_peer_uid_and_oversize_frames() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        assert!(check_peer(&sender, uid()).is_ok());
        if let Ok(peer) = sender.peer_cred() {
            assert!(check_peer(&sender, peer.uid().wrapping_add(1)).is_err());
        }
        sender.write_u32(MAX_FRAME_BYTES as u32 + 1).await.unwrap();
        assert!(matches!(
            read_frame::<Operation>(&mut receiver).await,
            Err(AdminError::Interrupted)
        ));
    }

    #[tokio::test]
    async fn owner_ipc_lock_held_without_socket_refuses_before_opening_store() {
        let directory = state_dir();
        let authority = Authority::open(directory.path(), AuthorityConfig::default()).unwrap();
        let sqlite = directory.path().join("authority.sqlite");
        let before = fs::read(&sqlite).unwrap();
        let result = execute(
            directory.path(),
            Operation::Revoke {
                record_id: "fixture-record".into(),
            },
            || panic!("live CLI must not load offline configuration"),
        )
        .await;
        assert!(matches!(result, Err(AdminError::Socket)));
        assert_eq!(fs::read(&sqlite).unwrap(), before);
        drop(authority);
    }

    #[tokio::test]
    async fn owner_cli_issues_once_lists_metadata_and_revokes_live_then_offline() {
        use super::super::authority::{handle_digest, Carrier};

        let directory = state_dir();
        let email = "owner@example.test";
        let config = AuthorityConfig {
            allowlist: vec![email.to_owned()],
            nodes: vec!["laptop".into()],
            ..AuthorityConfig::default()
        };
        let authority = Authority::open(directory.path(), config.clone()).unwrap();
        let browser = authority
            .login(email, "https://issuer.example.test", "fixture-owner", None)
            .unwrap();
        let owner = browser.record.principal.clone();
        let listener = bind(directory.path(), &authority).unwrap();
        assert_eq!(
            fs::symlink_metadata(directory.path().join(SOCKET))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        let server = tokio::spawn(serve(listener, authority.clone()));

        let (reply, offline) = execute(
            directory.path(),
            Operation::MintMachine {
                owner: owner.clone(),
                name: "fixture-monitor".into(),
                scope: vec![Scope::Fleet],
                expires_at: None,
                rate: 2,
            },
            || panic!("live CLI must not reload config"),
        )
        .await
        .unwrap();
        assert!(!offline);
        let Reply::Issued { handle } = reply else {
            panic!("expected a live issue reply");
        };
        let mut output = Vec::new();
        print_reply(
            Reply::Issued {
                handle: handle.clone(),
            },
            &mut output,
        )
        .unwrap();
        assert!(output == format!("{handle}\n").as_bytes());

        let grant = directory.path().join("grant.json");
        fs::write(
            &grant,
            json!({
                "holder": "fixture-agent",
                "verbs": ["send"],
                "targets": [{"node": "laptop", "endpoint": "worker@laptop"}],
                "expires_at": crate::storage::now_epoch_secs() + 60,
                "rate": 1,
                "read_scope": [{"kind": "node", "node": "laptop"}]
            })
            .to_string(),
        )
        .unwrap();
        let operation = Operation::try_from(Action::Mint {
            class: Mint::Delegated {
                owner: owner.clone(),
                grant_file: grant,
            },
        })
        .unwrap();
        let (reply, offline) = execute(directory.path(), operation, || unreachable!())
            .await
            .unwrap();
        assert!(!offline);
        let Reply::Issued { handle: delegated } = reply else {
            panic!("expected a staged delegated record");
        };
        assert!(
            matches!(
                authority.admit(&delegated, Carrier::Bearer),
                Err(AuthorityError::Denied)
            ),
            "production admits a delegated record before the management panel"
        );

        let record = authority.admit(&handle, Carrier::Bearer).unwrap();
        let (reply, offline) = execute(directory.path(), Operation::List {}, || unreachable!())
            .await
            .unwrap();
        assert!(!offline);
        let mut output = Vec::new();
        print_reply(reply, &mut output).unwrap();
        let digest = hex::encode(handle_digest(&handle).unwrap());
        let text = std::str::from_utf8(&output).unwrap();
        assert!(!text.contains(&handle));
        assert!(!text.contains(&digest[..8]));
        let listed: Vec<Value> = serde_json::from_slice(&output).unwrap();
        assert!(listed.contains(&json!({
            "record_id": record.record_id,
            "class": "machine",
            "principal": record.principal,
            "on_behalf_of": owner,
            "created_at": record.created_at,
            "last_used_at": record.last_used_at
        })));

        let (reply, offline) = execute(
            directory.path(),
            Operation::Revoke {
                record_id: record.record_id,
            },
            || unreachable!(),
        )
        .await
        .unwrap();
        assert!(!offline);
        assert!(matches!(reply, Reply::Done {}));
        assert!(authority.admit(&handle, Carrier::Bearer).is_err());
        assert!(authority
            .audit_records()
            .unwrap()
            .iter()
            .any(|row| row.action == "revoke"));

        server.abort();
        let _ = server.await;
        assert!(!directory.path().join(SOCKET).exists());
        drop(authority);
        let (reply, offline) = execute(
            directory.path(),
            Operation::Revoke {
                record_id: browser.record.record_id,
            },
            || Ok(config.clone()),
        )
        .await
        .unwrap();
        assert!(offline);
        assert!(matches!(reply, Reply::Done {}));
        let restarted = Authority::open(directory.path(), config).unwrap();
        assert!(restarted.admit(&browser.handle, Carrier::Cookie).is_err());
    }
}
