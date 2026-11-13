use clap::Args;
use serde_json::Value;
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use unicode_general_category::{get_general_category, GeneralCategory};
use xmsg::client::{NodeStatus, Recipient};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 1000;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Args, Debug)]
pub struct WatchArgs {
    /// HTTP Unix socket (defaults to the daemon's runtime directory)
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    http_sock: Option<PathBuf>,
    /// Query only this node
    #[arg(long)]
    node: Option<String>,
    /// Seconds between completed refreshes
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
    interval: u64,
    /// Print one plain snapshot and exit
    #[arg(long)]
    once: bool,
    /// Append readable snapshots without terminal control sequences
    #[arg(long)]
    plain: bool,
}

fn client(socket: &Path) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .unix_socket(socket.to_owned())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()?)
}

async fn get(client: &reqwest::Client, url: reqwest::Url) -> Result<Value> {
    let mut response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_BYTES - bytes.len() {
            return Err("response exceeds 4 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Debug, Default)]
struct Snapshot {
    rows: Vec<Recipient>,
    nodes: Vec<(String, NodeStatus)>,
    counts: [usize; 2],
    node_count: usize,
    partial: bool,
    health: String,
}

async fn fetch(client: &reqwest::Client, node: Option<&str>) -> Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    let health = get(client, reqwest::Url::parse("http://localhost/healthz")?).await?;
    snapshot.health = format!(
        "{} / sessions_dir={}",
        string(&health["status"]),
        string(&health["sessions_dir"])
    );
    for (index, status) in ["live", "inactive"].iter().enumerate() {
        let mut url = reqwest::Url::parse("http://localhost/v1/recipients")?;
        url.query_pairs_mut().append_pair("status", status);
        if let Some(node) = node {
            url.query_pairs_mut().append_pair("node", node);
        }
        let mut value = get(client, url).await?;
        let rows = value["recipients"]
            .as_array_mut()
            .ok_or("missing recipients array")?;
        snapshot.counts[index] = rows.len();
        for row in rows.drain(..) {
            if snapshot.rows.len() < MAX_ROWS {
                snapshot.rows.push(serde_json::from_value(row)?);
            }
        }
        let nodes = value["nodes"].as_array_mut().ok_or("missing nodes array")?;
        snapshot.node_count += nodes.len();
        for node in nodes.drain(..) {
            let node: NodeStatus = serde_json::from_value(node)?;
            snapshot.partial |= node.status != "ok";
            if snapshot.nodes.len() < MAX_ROWS {
                snapshot.nodes.push((status.to_string(), node));
            }
        }
    }
    snapshot.rows.sort_by(|a, b| {
        (&a.node, &a.kind, &a.harness, &a.address).cmp(&(&b.node, &b.kind, &b.harness, &b.address))
    });
    Ok(snapshot)
}

fn string(value: &Value) -> &str {
    value.as_str().unwrap_or("unknown")
}

#[derive(Default)]
struct State {
    snapshot: Option<Snapshot>,
    updated: Option<Instant>,
    error: Option<String>,
}

impl State {
    fn apply(&mut self, result: Result<Snapshot>, now: Instant) {
        match result {
            Ok(snapshot) => {
                self.snapshot = Some(snapshot);
                self.updated = Some(now);
                self.error = None;
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }
}

fn terminal_text(value: &str) -> String {
    let mut text = String::new();
    for c in value.chars() {
        let piece = if c.is_control() || get_general_category(c) == GeneralCategory::Format {
            format!("\\u{{{:x}}}", c as u32)
        } else {
            c.to_string()
        };
        if text.chars().count() + piece.chars().count() > 80 {
            text.push('…');
            break;
        }
        text.push_str(&piece);
    }
    text
}

fn render(state: &State, now: Instant, epoch: i64) -> String {
    let mut out = String::from("xmsg watch — recipient roster snapshot (no traffic data)\n");
    let age = state
        .updated
        .map(|t| now.saturating_duration_since(t).as_secs());
    let _ = writeln!(
        out,
        "{} | roster age: {}",
        if state.error.is_some() {
            "STALE"
        } else {
            "CURRENT"
        },
        age.map(|n| format!("{n}s"))
            .unwrap_or_else(|| "never refreshed".into())
    );
    if let Some(error) = &state.error {
        let _ = writeln!(out, "Refresh error: {}", terminal_text(error));
    }
    let Some(snapshot) = &state.snapshot else {
        return out;
    };
    let _ = writeln!(out, "Health: {}", terminal_text(&snapshot.health));
    let _ = writeln!(
        out,
        "{} | source counts: live={} inactive={} | shown={}",
        if snapshot.partial {
            "PARTIAL: node errors"
        } else {
            "Complete node responses"
        },
        snapshot.counts[0],
        snapshot.counts[1],
        snapshot.rows.len()
    );
    if snapshot.counts.iter().sum::<usize>() > snapshot.rows.len()
        || snapshot.node_count > snapshot.nodes.len()
    {
        let _ = writeln!(out, "TRUNCATED: limit {MAX_ROWS} recipient rows / {MAX_ROWS} node responses; source node responses={}", snapshot.node_count);
    }
    for (source, node) in &snapshot.nodes {
        let _ = writeln!(
            out,
            "Node [{}] {}: {} {}",
            source,
            terminal_text(&node.node),
            terminal_text(&node.status),
            terminal_text(node.detail.as_deref().unwrap_or(""))
        );
    }
    let mut group = None;
    for row in &snapshot.rows {
        let key = (&row.node, &row.kind, &row.harness);
        if group != Some(key) {
            let _ = writeln!(
                out,
                "\n{} / {} / {}",
                terminal_text(&row.node),
                terminal_text(&row.kind),
                terminal_text(row.harness.as_deref().unwrap_or("-"))
            );
            let _ = writeln!(
                out,
                "TYPE  LABEL  STATUS  AGE (since registration / last seen)  ADDRESS"
            );
            group = Some(key);
        }
        let timestamp = if row.status == "live" {
            row.registered_at
        } else {
            row.last_seen
        };
        let age = timestamp
            .map(|t| format!("{}s", epoch.saturating_sub(t).max(0)))
            .unwrap_or_else(|| "unknown".into());
        let _ = writeln!(
            out,
            "{}  {}  {}  {}  {}",
            terminal_text(&row.kind),
            terminal_text(row.label.as_deref().unwrap_or("-")),
            terminal_text(&row.status),
            age,
            terminal_text(&row.address)
        );
    }
    out
}

pub async fn run(args: WatchArgs) -> Result<()> {
    let socket = match args.http_sock {
        Some(socket) => socket,
        None => xmsg::http::default_http_sock_path()?,
    };
    let client = client(&socket)?;
    let terminal = io::stdout().is_terminal()
        && !args.once
        && !args.plain
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|term| term != "dumb");
    let mut state = State::default();
    loop {
        let result = tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            result = tokio::time::timeout(DEADLINE, fetch(&client, args.node.as_deref())) => result.unwrap_or_else(|_| Err("refresh deadline exceeded".into())),
        };
        state.apply(result, Instant::now());
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .min(i64::MAX as u64) as i64;
        let mut stdout = io::stdout().lock();
        if terminal {
            write!(stdout, "\x1b[2J\x1b[H")?;
        }
        writeln!(stdout, "{}", render(&state, Instant::now(), epoch))?;
        stdout.flush()?;
        drop(stdout);
        if args.once {
            return if state.error.is_some() {
                Err("watch refresh failed".into())
            } else {
                Ok(())
            };
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(args.interval)) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server(
        responses: Vec<(u16, String)>,
    ) -> (
        tempfile::TempDir,
        reqwest::Client,
        tokio::task::JoinHandle<Vec<String>>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("http.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let client = client(&socket).unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (code, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buf = [0; 1024];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                    if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                requests.push(
                    String::from_utf8(bytes)
                        .unwrap()
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                let header = format!("HTTP/1.1 {code} Test\r\nConnection: close\r\nLocation: http://localhost/v1/messages/secret\r\nContent-Length: {}\r\n\r\n", body.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(body.as_bytes()).await.unwrap();
            }
            requests
        });
        (dir, client, task)
    }

    fn roster(rows: usize) -> String {
        json!({"recipients": (0..rows).map(|i| json!({"address":format!("id{i}"),"kind":"instance","harness":"codex","label":"hello","status":"live","node":"local","user":"user","registered_at":90})).collect::<Vec<_>>(), "nodes":[{"node":"local","status":"ok"}]}).to_string()
    }

    #[tokio::test]
    async fn request_allowlist_and_node_encoding() {
        let (_dir, client, task) =
            server(vec![(200, "{}".into()), (200, roster(1)), (200, roster(0))]).await;
        let snapshot = tokio::time::timeout(DEADLINE, fetch(&client, Some("local&status=other")))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.rows.len(), 1);
        assert_eq!(
            task.await.unwrap(),
            [
                "GET /healthz HTTP/1.1",
                "GET /v1/recipients?status=live&node=local%26status%3Dother HTTP/1.1",
                "GET /v1/recipients?status=inactive&node=local%26status%3Dother HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn redirects_are_never_followed() {
        let (_dir, client, task) = server(vec![(302, "{}".into())]).await;
        assert!(fetch(&client, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("302"));
        assert_eq!(task.await.unwrap(), ["GET /healthz HTTP/1.1"]);
    }

    #[tokio::test]
    async fn refresh_failure_retains_roster_age() {
        let (_dir, client, task) = server(vec![
            (200, "{}".into()),
            (200, roster(1)),
            (200, roster(0)),
            (200, "{}".into()),
            (500, "{}".into()),
        ])
        .await;
        let now = Instant::now();
        let mut state = State::default();
        state.apply(fetch(&client, None).await, now);
        state.apply(fetch(&client, None).await, now + Duration::from_secs(20));
        let text = render(&state, now + Duration::from_secs(25), 100);
        assert!(text.contains("STALE | roster age: 25s"));
        assert!(text.contains("hello"));
        assert_eq!(task.await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn truncation_and_partial_nodes_visible() {
        let mut partial: Value = serde_json::from_str(&roster(3)).unwrap();
        partial["nodes"] = json!([{"node":"remote","status":"timeout","detail":"offline"}]);
        let (_dir, client, task) = server(vec![
            (200, "{}".into()),
            (200, roster(1002)),
            (200, partial.to_string()),
        ])
        .await;
        let mut state = State::default();
        let now = Instant::now();
        state.apply(fetch(&client, None).await, now);
        assert_eq!(state.snapshot.as_ref().unwrap().rows.len(), 1000);
        let text = render(&state, now, 100);
        assert!(text.contains("TRUNCATED"));
        assert!(text.contains("live=1002 inactive=3 | shown=1000"));
        assert!(text.contains("PARTIAL: node errors"));
        assert!(text.contains("remote: timeout offline"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn terminal_fields_are_inert() {
        let hostile = "name\u{1b}]52;c;secret\u{7}\n\r\u{85}\u{202e}\u{2066}雪";
        let mut response: Value = serde_json::from_str(&roster(1)).unwrap();
        for field in ["address", "kind", "harness", "label", "status", "node"] {
            response["recipients"][0][field] = json!(hostile);
        }
        response["nodes"] = json!([{"node":hostile,"status":hostile,"detail":hostile}]);
        let (_dir, client, task) = server(vec![
            (
                200,
                json!({"status":hostile,"sessions_dir":hostile}).to_string(),
            ),
            (200, response.to_string()),
            (200, roster(0)),
        ])
        .await;
        let mut state = State::default();
        let now = Instant::now();
        state.apply(fetch(&client, None).await, now);
        let text = render(&state, now, 100);
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{7}'));
        assert!(!text.contains('\u{85}'));
        assert!(!text.contains('\u{202e}'));
        assert!(!text.contains("\n\r"));
        assert!(text.contains("\\u{1b}"));
        assert_eq!(terminal_text("雪 café"), "雪 café");
        assert!(terminal_text(&"x".repeat(1000)).chars().count() <= 81);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_response_is_refused() {
        let (_dir, client, task) = server(vec![(200, " ".repeat(MAX_BYTES + 1))]).await;
        assert!(fetch(&client, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("4 MiB"));
        task.await.unwrap();
    }
}
