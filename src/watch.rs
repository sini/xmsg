use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
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
const MAX_EVENT_BYTES: usize = 4 * 1024;
const MAX_PAGE_BYTES: usize = 256 * 1024;
const PAGE_LIMIT: usize = 100;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    node: String,
    epoch: String,
    sequence: i64,
    source_at: Option<i64>,
    observed_at: i64,
    persisted_at: i64,
    kind: String,
    from: Option<String>,
    to: Option<String>,
    message_id: Option<String>,
    reply_id: Option<i64>,
    thread_id: Option<String>,
    outcome: Option<String>,
    reason: Option<String>,
    body_availability: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Gap {
    reason: String,
    unknown_loss: bool,
    count: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Losses {
    capacity: u64,
    ttl: u64,
    queue: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    node: String,
    epoch: String,
    events: Vec<Event>,
    next: i64,
    floor: i64,
    head: i64,
    has_more: bool,
    gaps: Vec<Gap>,
    losses: Losses,
    available: bool,
    initial_omitted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cursor {
    epoch: String,
    after: i64,
}

impl Page {
    fn validate(&self, cursor: Option<&Cursor>) -> Result<()> {
        if !self.available {
            return Err("observer unavailable".into());
        }
        if self.node.is_empty()
            || self.node.len() > 512
            || self.epoch.is_empty()
            || self.epoch.len() > 128
            || self.events.len() > PAGE_LIMIT
            || self.gaps.len() > 200
            || self
                .gaps
                .iter()
                .any(|gap| gap.reason.is_empty() || gap.reason.len() > 128)
            || self.floor < 0
            || self.head < 0
            || self.next < 0
            || self.next > self.head
            || self.floor > self.head.saturating_add(1)
        {
            return Err("invalid observation page bounds".into());
        }
        let reset = self
            .gaps
            .iter()
            .any(|gap| matches!(gap.reason.as_str(), "epoch_changed" | "cursor_ahead"));
        if let Some(cursor) = cursor {
            if (cursor.epoch != self.epoch || cursor.after > self.head) && !reset {
                return Err("observation cursor reset missing".into());
            }
            if !reset
                && cursor.after < self.floor.saturating_sub(1)
                && !self.gaps.iter().any(|gap| gap.reason == "cursor_evicted")
            {
                return Err("observation retention gap missing".into());
            }
        }
        let mut previous = if reset {
            0
        } else {
            cursor.map_or(0, |c| c.after)
        };
        let mut coverage = cursor
            .filter(|_| !reset)
            .map(|cursor| cursor.after.max(self.floor.saturating_sub(1)));
        let mut missing = 0u64;
        for event in &self.events {
            if event.node != self.node
                || event.epoch != self.epoch
                || event.sequence <= previous
                || event.sequence < self.floor
                || event.sequence > self.head
                || serde_json::to_vec(event)?.len() > MAX_EVENT_BYTES
            {
                return Err("invalid observation event or ordering".into());
            }
            if let Some(covered) = coverage {
                missing += (event.sequence - covered - 1) as u64;
            }
            coverage = Some(event.sequence);
            previous = event.sequence;
        }
        if !self.has_more {
            missing += (self.head - coverage.unwrap_or(self.head)) as u64;
        }
        let declared: Vec<_> = self
            .gaps
            .iter()
            .filter(|gap| gap.reason == "sequence_gap")
            .collect();
        if (missing == 0 && !declared.is_empty())
            || (missing > 0
                && (declared.len() != 1
                    || declared[0].unknown_loss
                    || declared[0].count != Some(missing)))
        {
            return Err("observation sequence gap missing or count incorrect".into());
        }
        if self
            .events
            .last()
            .is_some_and(|event| event.sequence != self.next)
            || (self.has_more && (self.events.is_empty() || self.next >= self.head))
            || (self.events.is_empty() && cursor.is_some_and(|c| !reset && self.next != c.after))
        {
            return Err("observation next cursor does not match page".into());
        }
        Ok(())
    }
}

enum TimelineFetch {
    Unsupported,
    Pages(Vec<Page>),
}

#[derive(Default)]
struct TimelineState {
    rows: VecDeque<Event>,
    cursor: Option<Cursor>,
    updated: Option<Instant>,
    error: Option<String>,
    unsupported: bool,
    node: String,
    gaps: Vec<Gap>,
    losses: Losses,
    catching_up: bool,
    truncated: u64,
    initial_omitted: u64,
    new_sequences: HashSet<i64>,
}

impl TimelineState {
    fn apply(&mut self, result: Result<TimelineFetch>, now: Instant) {
        self.new_sequences.clear();
        match result {
            Err(error) => {
                self.unsupported = false;
                self.error = Some(error.to_string());
            }
            Ok(TimelineFetch::Unsupported) => {
                self.unsupported = true;
                self.error = None;
            }
            Ok(TimelineFetch::Pages(pages)) => {
                let prior = self.cursor.clone();
                for page in pages {
                    if self.cursor.as_ref().is_some_and(|c| c.epoch != page.epoch)
                        || page.gaps.iter().any(|gap| {
                            matches!(gap.reason.as_str(), "epoch_changed" | "cursor_ahead")
                        })
                    {
                        self.rows.clear();
                        self.gaps.clear();
                        self.new_sequences.clear();
                    }
                    for gap in page.gaps {
                        if !self.gaps.contains(&gap) {
                            self.gaps.push(gap);
                            if self.gaps.len() > 100 {
                                self.gaps.remove(0);
                            }
                        }
                    }
                    for event in page.events {
                        if prior.as_ref().is_some_and(|cursor| {
                            cursor.epoch == event.epoch && event.sequence > cursor.after
                        }) {
                            self.new_sequences.insert(event.sequence);
                        }
                        self.rows.push_back(event);
                        if self.rows.len() > MAX_ROWS {
                            self.rows.pop_front();
                            self.truncated = self.truncated.saturating_add(1);
                        }
                    }
                    self.node = page.node;
                    self.cursor = Some(Cursor {
                        epoch: page.epoch,
                        after: page.next,
                    });
                    self.losses = page.losses;
                    self.initial_omitted =
                        self.initial_omitted.saturating_add(page.initial_omitted);
                    self.catching_up = page.has_more;
                }
                self.unsupported = false;
                self.error = None;
                self.updated = Some(now);
            }
        }
    }
}

async fn fetch_timeline(
    client: &reqwest::Client,
    mut cursor: Option<Cursor>,
) -> Result<TimelineFetch> {
    let mut pages = Vec::new();
    for _ in 0..2 {
        let mut url = reqwest::Url::parse("http://localhost/v1/observe/events")?;
        url.query_pairs_mut()
            .append_pair("limit", &PAGE_LIMIT.to_string());
        if let Some(cursor) = &cursor {
            url.query_pairs_mut()
                .append_pair("epoch", &cursor.epoch)
                .append_pair("after", &cursor.after.to_string());
        }
        let mut response = client.get(url).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(TimelineFetch::Unsupported);
        }
        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status()).into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > MAX_PAGE_BYTES - bytes.len() {
                return Err("observation response exceeds 256 KiB".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let page: Page = serde_json::from_slice(&bytes)?;
        page.validate(cursor.as_ref())?;
        cursor = Some(Cursor {
            epoch: page.epoch.clone(),
            after: page.next,
        });
        let more = page.has_more;
        pages.push(page);
        if !more {
            break;
        }
    }
    Ok(TimelineFetch::Pages(pages))
}

#[derive(Args, Debug)]
pub struct WatchArgs {
    /// HTTP Unix socket (defaults to the daemon's runtime directory)
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    http_sock: Option<PathBuf>,
    /// Filter the roster to this node (the observation timeline stays local)
    #[arg(long)]
    node: Option<String>,
    /// Seconds between completed refreshes
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
    interval: u64,
    /// Print one plain roster and observation snapshot and exit
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
    let mut out = String::from("xmsg watch — recipient roster snapshot\n");
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

fn render_timeline(state: &TimelineState, now: Instant) -> String {
    let mut out =
        String::from("\nLocal exchange observations — best effort, not complete history\n");
    if state.unsupported {
        out.push_str("UNSUPPORTED: this daemon has no observation endpoint\n");
        return out;
    }
    let age = state
        .updated
        .map(|time| now.saturating_duration_since(time).as_secs());
    let _ = writeln!(
        out,
        "{} | event age: {} | node: {}",
        if state.error.is_some() {
            "STALE"
        } else if state.updated.is_some() {
            "CURRENT"
        } else {
            "UNAVAILABLE"
        },
        age.map(|age| format!("{age}s"))
            .unwrap_or_else(|| "never refreshed".into()),
        terminal_text(&state.node)
    );
    if let Some(error) = &state.error {
        let _ = writeln!(out, "Observation refresh error: {}", terminal_text(error));
    }
    let _ = writeln!(
        out,
        "Loss counters: capacity={} ttl={} queue={}",
        state.losses.capacity, state.losses.ttl, state.losses.queue
    );
    if state.initial_omitted > 0 {
        let _ = writeln!(
            out,
            "Initial tail omitted {} older observations (intentional)",
            state.initial_omitted
        );
    }
    if state.truncated > 0 {
        let _ = writeln!(
            out,
            "LOCAL TRUNCATION: {} older observations removed; limit {MAX_ROWS}",
            state.truncated
        );
    }
    if state.catching_up {
        out.push_str("CATCHING UP: more stored observations; at most two pages per refresh\n");
    }
    for gap in &state.gaps {
        let _ = writeln!(
            out,
            "GAP: {} | unknown loss={} | count={}",
            terminal_text(&gap.reason),
            gap.unknown_loss,
            gap.count
                .map(|count| count.to_string())
                .unwrap_or_else(|| "unknown".into())
        );
    }
    if let Some(cursor) = &state.cursor {
        let _ = writeln!(
            out,
            "Journal {} after {}",
            terminal_text(&cursor.epoch),
            cursor.after
        );
    }
    for event in &state.rows {
        let _ = writeln!(out, "{}#{} {} {} -> {} | message={} reply={} thread={} | outcome={} reason={} | source={} observed={} persisted={} | body={}",
            if state.new_sequences.contains(&event.sequence) { "* " } else { "  " },
            event.sequence, terminal_text(&event.kind), terminal_text(event.from.as_deref().unwrap_or("unknown")), terminal_text(event.to.as_deref().unwrap_or("unknown")),
            terminal_text(event.message_id.as_deref().unwrap_or("-")), event.reply_id.map(|id| id.to_string()).unwrap_or_else(|| "-".into()), terminal_text(event.thread_id.as_deref().unwrap_or("-")),
            terminal_text(event.outcome.as_deref().unwrap_or("-")), terminal_text(event.reason.as_deref().unwrap_or("-")), event.source_at.map(|time| time.to_string()).unwrap_or_else(|| "unknown".into()), event.observed_at, event.persisted_at, terminal_text(&event.body_availability));
    }
    out
}

async fn refresh(
    client: &reqwest::Client,
    node: Option<&str>,
    state: &mut State,
    timeline: &mut TimelineState,
) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    let result = tokio::time::timeout_at(deadline, fetch(client, node))
        .await
        .unwrap_or_else(|_| Err("refresh deadline exceeded".into()));
    state.apply(result, Instant::now());
    let result = tokio::time::timeout_at(deadline, fetch_timeline(client, timeline.cursor.clone()))
        .await
        .unwrap_or_else(|_| Err("observation refresh deadline exceeded".into()));
    timeline.apply(result, Instant::now());
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
    let mut timeline = TimelineState::default();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = refresh(&client, args.node.as_deref(), &mut state, &mut timeline) => {},
        };
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .min(i64::MAX as u64) as i64;
        let mut stdout = io::stdout().lock();
        if terminal {
            write!(stdout, "\x1b[2J\x1b[H")?;
        }
        writeln!(stdout, "{}", render(&state, Instant::now(), epoch))?;
        writeln!(stdout, "{}", render_timeline(&timeline, Instant::now()))?;
        stdout.flush()?;
        drop(stdout);
        if args.once {
            return if state.error.is_some() || timeline.error.is_some() {
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

    fn event(sequence: i64) -> Event {
        Event {
            node: "local".into(),
            epoch: "epoch".into(),
            sequence,
            source_at: Some(10),
            observed_at: 11,
            persisted_at: 12,
            kind: "outcome_changed".into(),
            from: Some("sender@local".into()),
            to: Some("recipient@local".into()),
            message_id: Some("message".into()),
            reply_id: None,
            thread_id: Some("thread".into()),
            outcome: Some("queued".into()),
            reason: None,
            body_availability: "not_recorded".into(),
        }
    }

    fn page(first: i64, last: i64, head: i64) -> Page {
        Page {
            node: "local".into(),
            epoch: "epoch".into(),
            events: (first..=last).map(event).collect(),
            next: last.max(0),
            floor: 1,
            head,
            has_more: last < head,
            gaps: Vec::new(),
            losses: Losses::default(),
            available: true,
            initial_omitted: 0,
        }
    }

    #[tokio::test]
    async fn refresh_requests_only_roster_and_observation_endpoints() {
        let (_dir, client, task) = server(vec![
            (200, "{}".into()),
            (200, roster(1)),
            (200, roster(0)),
            (200, serde_json::to_string(&page(1, 1, 1)).unwrap()),
        ])
        .await;
        let mut state = State::default();
        let mut timeline = TimelineState::default();
        refresh(
            &client,
            Some("local&status=other"),
            &mut state,
            &mut timeline,
        )
        .await;
        assert!(state.error.is_none());
        assert!(timeline.error.is_none());
        assert_eq!(timeline.cursor.unwrap().after, 1);
        assert_eq!(
            task.await.unwrap(),
            [
                "GET /healthz HTTP/1.1",
                "GET /v1/recipients?status=live&node=local%26status%3Dother HTTP/1.1",
                "GET /v1/recipients?status=inactive&node=local%26status%3Dother HTTP/1.1",
                "GET /v1/observe/events?limit=100 HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn timeline_reads_at_most_two_pages_then_resumes_encoded_cursor() {
        let mut first = page(1, 100, 300);
        first.epoch = "epoch&after=bad".into();
        for event in &mut first.events {
            event.epoch = first.epoch.clone();
        }
        let mut second = page(101, 200, 300);
        second.epoch = first.epoch.clone();
        for event in &mut second.events {
            event.epoch = second.epoch.clone();
        }
        let (_dir, client, task) = server(vec![
            (200, serde_json::to_string(&first).unwrap()),
            (200, serde_json::to_string(&second).unwrap()),
        ])
        .await;
        let mut state = TimelineState::default();
        let now = Instant::now();
        state.apply(fetch_timeline(&client, None).await, now);
        assert!(state.error.is_none());
        assert_eq!(state.rows.len(), 200);
        assert_eq!(state.cursor.as_ref().unwrap().after, 200);
        assert!(state.catching_up);
        assert!(render_timeline(&state, now).contains("CATCHING UP"));
        assert_eq!(
            task.await.unwrap(),
            [
                "GET /v1/observe/events?limit=100 HTTP/1.1",
                "GET /v1/observe/events?limit=100&epoch=epoch%26after%3Dbad&after=100 HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn failed_second_page_preserves_cursor_rows_and_event_age() {
        let now = Instant::now();
        let mut state = TimelineState::default();
        state.apply(Ok(TimelineFetch::Pages(vec![page(1, 1, 1)])), now);
        let (_dir, client, task) = server(vec![
            (200, serde_json::to_string(&page(2, 2, 3)).unwrap()),
            (500, "{}".into()),
        ])
        .await;
        state.apply(
            fetch_timeline(&client, state.cursor.clone()).await,
            now + Duration::from_secs(20),
        );
        assert_eq!(state.cursor.as_ref().unwrap().after, 1);
        assert_eq!(state.rows.len(), 1);
        assert!(render_timeline(&state, now + Duration::from_secs(25))
            .contains("STALE | event age: 25s"));
        assert_eq!(task.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn older_daemon_and_failed_events_leave_roster_current() {
        let (_dir, client, task) = server(vec![
            (200, "{}".into()),
            (200, roster(1)),
            (200, roster(0)),
            (404, "{}".into()),
            (200, "{}".into()),
            (200, roster(1)),
            (200, roster(0)),
            (500, "{}".into()),
        ])
        .await;
        let mut state = State::default();
        let mut timeline = TimelineState::default();
        refresh(&client, None, &mut state, &mut timeline).await;
        assert!(state.error.is_none());
        assert!(render_timeline(&timeline, Instant::now()).contains("UNSUPPORTED"));
        refresh(&client, None, &mut state, &mut timeline).await;
        assert!(render(&state, Instant::now(), 100).contains("CURRENT | roster age: 0s"));
        assert!(render_timeline(&timeline, Instant::now()).contains("STALE"));
        assert_eq!(task.await.unwrap().len(), 8);
    }

    #[test]
    fn timeline_bounds_gaps_reset_and_inert_fields_are_visible() {
        let now = Instant::now();
        let mut state = TimelineState::default();
        for batch in 0..11 {
            let mut batch_page = page(batch * 100 + 1, batch * 100 + 100, batch * 100 + 100);
            if batch == 0 {
                batch_page.initial_omitted = 7;
            }
            state.apply(Ok(TimelineFetch::Pages(vec![batch_page])), now);
        }
        assert_eq!(state.rows.len(), MAX_ROWS);
        assert_eq!(state.rows.front().unwrap().sequence, 101);
        assert_eq!(state.truncated, 100);
        let hostile = "\u{1b}]52;c;secret\u{7}\n\r\u{202e}\u{2066}雪";
        let mut next = page(1101, 1101, 1101);
        next.gaps = vec![Gap {
            reason: format!("writer_restart{hostile}"),
            unknown_loss: true,
            count: None,
        }];
        next.losses = Losses {
            capacity: 8,
            ttl: 9,
            queue: 10,
        };
        next.events[0].kind = hostile.into();
        next.events[0].body_availability = hostile.into();
        let e = &mut next.events[0];
        e.from = Some(hostile.into());
        e.to = Some(hostile.into());
        e.message_id = Some(hostile.into());
        e.thread_id = Some(hostile.into());
        e.outcome = Some(hostile.into());
        e.reason = Some(hostile.into());
        state.apply(Ok(TimelineFetch::Pages(vec![next])), now);
        let text = render_timeline(&state, now);
        assert!(text.contains("capacity=8 ttl=9 queue=10"));
        assert!(text.contains("GAP: writer_restart"));
        assert!(text.contains("unknown loss=true"));
        assert!(text.contains("Initial tail omitted 7"));
        assert!(text.contains("LOCAL TRUNCATION"));
        assert!(text.contains("* #1101"));
        for control in ['\u{1b}', '\u{7}', '\u{202e}', '\u{2066}', '\r'] {
            assert!(!text.contains(control));
        }
        assert!(text.contains("\\u{1b}"));
        state.apply(Ok(TimelineFetch::Pages(vec![page(1102, 1101, 1101)])), now);
        assert!(render_timeline(&state, now).contains("GAP: writer_restart"));
        assert!(state.new_sequences.is_empty());
        let mut reset = page(1, 1, 1);
        reset.epoch = "new".into();
        reset.events[0].epoch = "new".into();
        reset.gaps.push(Gap {
            reason: "epoch_changed".into(),
            unknown_loss: true,
            count: None,
        });
        reset.validate(state.cursor.as_ref()).unwrap();
        state.apply(Ok(TimelineFetch::Pages(vec![reset])), now);
        assert_eq!(state.rows.len(), 1);
        assert_eq!(state.cursor.unwrap().epoch, "new");
    }

    #[tokio::test]
    async fn explicit_known_sequence_hole_is_rendered_and_silent_holes_are_refused() {
        let mut with_gap = page(1, 3, 3);
        with_gap.events.remove(1);
        with_gap.gaps.push(Gap {
            reason: "sequence_gap".into(),
            unknown_loss: false,
            count: Some(1),
        });
        let (_dir, client, task) =
            server(vec![(200, serde_json::to_string(&with_gap).unwrap())]).await;
        let mut state = TimelineState::default();
        let now = Instant::now();
        state.apply(fetch_timeline(&client, None).await, now);
        assert!(
            state.error.is_none(),
            "explicit known hole must remain usable: {:?}",
            state.error
        );
        assert_eq!(
            state
                .rows
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(state.cursor.as_ref().unwrap().after, 3);
        assert!(render_timeline(&state, now)
            .contains("GAP: sequence_gap | unknown loss=false | count=1"));
        task.await.unwrap();

        let mut continuation = with_gap.clone();
        continuation.events.remove(0);
        let mut trailing = page(1, 1, 3);
        trailing.has_more = false;
        trailing.gaps.push(Gap {
            reason: "sequence_gap".into(),
            unknown_loss: false,
            count: Some(2),
        });
        let mut empty_continuation = trailing.clone();
        empty_continuation.events.clear();
        let cursor = Cursor {
            epoch: "epoch".into(),
            after: 1,
        };
        for (valid, after) in [
            (continuation, Some(cursor.clone())),
            (trailing, None),
            (empty_continuation, Some(cursor)),
        ] {
            let expected = valid.next;
            let (_dir, client, task) =
                server(vec![(200, serde_json::to_string(&valid).unwrap())]).await;
            let mut accepted = TimelineState::default();
            accepted.apply(fetch_timeline(&client, after).await, now);
            assert!(
                accepted.error.is_none(),
                "known prefix/trailing hole rejected: {:?}",
                accepted.error
            );
            assert_eq!(accepted.cursor.unwrap().after, expected);
            task.await.unwrap();
        }

        let mut silent = with_gap.clone();
        silent.gaps.clear();
        let mut wrong_count = with_gap.clone();
        wrong_count.gaps[0].count = Some(2);
        let mut unknown = with_gap.clone();
        unknown.gaps[0].unknown_loss = true;
        let mut reversed = with_gap.clone();
        reversed.events.reverse();
        let mut duplicate = with_gap.clone();
        duplicate.events.insert(0, duplicate.events[0].clone());
        for invalid in [silent, wrong_count, unknown, reversed, duplicate] {
            let (_dir, client, task) =
                server(vec![(200, serde_json::to_string(&invalid).unwrap())]).await;
            let mut initial = TimelineState::default();
            initial.apply(fetch_timeline(&client, None).await, now);
            assert!(initial.error.is_some());
            assert!(initial.cursor.is_none());
            assert!(initial.rows.is_empty());
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_or_oversized_observation_page_never_advances_cursor() {
        let now = Instant::now();
        let mut initial = TimelineState::default();
        initial.apply(Ok(TimelineFetch::Pages(vec![page(1, 1, 1)])), now);
        let mut wrong = page(2, 2, 2);
        wrong.next = 1;
        let mut duplicate = page(1, 1, 2);
        duplicate.has_more = false;
        let mut missing = page(3, 3, 3);
        missing.has_more = false;
        let mut over_limit = page(2, 102, 102);
        over_limit.has_more = false;
        let mut over_event = page(2, 2, 2);
        over_event.events[0].kind = "x".repeat(MAX_EVENT_BYTES);
        let mut over_gap = page(2, 2, 2);
        over_gap.gaps.push(Gap {
            reason: "x".repeat(129),
            unknown_loss: true,
            count: None,
        });
        let mut hidden_body = serde_json::to_value(page(2, 2, 2)).unwrap();
        hidden_body["events"][0]["text"] = json!("BODY_CANARY");
        for body in [
            serde_json::to_string(&wrong).unwrap(),
            serde_json::to_string(&duplicate).unwrap(),
            serde_json::to_string(&missing).unwrap(),
            serde_json::to_string(&over_limit).unwrap(),
            serde_json::to_string(&over_event).unwrap(),
            serde_json::to_string(&over_gap).unwrap(),
            hidden_body.to_string(),
            " ".repeat(MAX_PAGE_BYTES + 1),
        ] {
            let (_dir, client, task) = server(vec![(200, body)]).await;
            initial.apply(
                fetch_timeline(&client, initial.cursor.clone()).await,
                now + Duration::from_secs(10),
            );
            assert_eq!(initial.cursor.as_ref().unwrap().after, 1);
            assert_eq!(initial.rows.len(), 1);
            assert!(initial.error.is_some());
            task.await.unwrap();
        }
    }
}
