use clap::Args;
use serde_json::{json, Value};
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Args, Debug)]
pub struct Options {
    /// HTTP Unix socket (defaults to the daemon's runtime directory)
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    http_sock: Option<PathBuf>,
    /// Print the server's JSON response on one line
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[command(flatten)]
    options: Options,
    /// Query only this node
    #[arg(long)]
    node: Option<String>,
    #[arg(long, value_parser = ["service", "instance", "subagent"])]
    kind: Option<String>,
    #[arg(long, value_parser = ["live", "inactive"])]
    status: Option<String>,
    /// Only live whole instances carrying this exact tag
    #[arg(long)]
    tag: Option<String>,
    /// Maximum recipients after filtering (newest first)
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=500))]
    limit: u16,
}

#[derive(Args, Debug)]
pub struct TagArgs {
    /// Agent socket path (defaults to $XDG_RUNTIME_DIR/xmsg/agent.sock)
    #[arg(long, env = "XMSG_AGENT_SOCK")]
    agent_sock: Option<PathBuf>,
    /// Print the server's JSON response on one line
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    action: TagAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum TagAction {
    /// Add a tag to the calling session
    Add { name: String },
    /// Remove a tag from the calling session
    Remove { name: String },
}

#[derive(Args, Debug)]
pub struct SendArgs {
    #[command(flatten)]
    options: Options,
    /// Recipient address or unique label
    to: String,
    /// Message text; '-' or omission reads stdin
    text: Option<String>,
    /// Anonymous display label; the daemon determines sender identity
    #[arg(long, default_value = "cli", value_parser = plain_label)]
    from: String,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct RepliesArgs {
    #[command(flatten)]
    options: Options,
    message_id: String,
    /// Wait up to this many seconds for the first reply
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=60))]
    wait: u64,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    #[command(flatten)]
    options: Options,
    message_id: String,
}

fn plain_label(value: &str) -> std::result::Result<String, String> {
    if value.contains(['@', '/']) {
        return Err("--from is a plain label and must not contain '@' or '/'".into());
    }
    Ok(value.into())
}

fn endpoint(segments: &[&str]) -> reqwest::Url {
    let mut url = reqwest::Url::parse("http://localhost").unwrap();
    url.path_segments_mut().unwrap().extend(segments);
    url
}

fn request(
    options: &Options,
    method: &str,
    url: reqwest::Url,
    body: Option<Value>,
    timeout: Duration,
) -> Result<Value> {
    let socket = match &options.http_sock {
        Some(socket) => socket.clone(),
        None => xmsg::http::default_http_sock_path()?,
    };
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let body = body.map(|body| body.to_string());
    let (status, body) =
        xmsg::http::http_request_unix_within(&socket, method, &path, body.as_deref(), timeout)?;
    let value: Value = serde_json::from_str(&body)?;
    if !status.is_success() {
        if options.json {
            println!("{value}");
        }
        let code = value["error"].as_str().unwrap_or("http_error");
        let detail = value["detail"].as_str().unwrap_or("request refused");
        return Err(format!("{code}: {detail} (HTTP {status})").into());
    }
    Ok(value)
}

fn print_json(value: &Value, compact: bool) -> Result<()> {
    if compact {
        println!("{value}");
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn print_context(context: &xmsg::session_context::SessionContext) {
    let fields = &context.fields;
    let values = [
        ("repo", fields.repo.as_deref()),
        ("branch", fields.branch.as_deref()),
        ("worktree", fields.worktree.as_deref()),
        ("task", fields.task.as_deref()),
        ("pr", fields.pr.as_deref()),
    ];
    let tags = values
        .into_iter()
        .filter_map(|(key, value)| {
            value.map(|value| format!("{key}={}", xmsg::locator::inert(value)))
        })
        .collect::<Vec<_>>();
    let stale = if context.stale { " [stale]" } else { "" };
    println!("  {}{stale}", tags.join("  "));
}

pub fn list(args: ListArgs) -> Result<()> {
    let mut url = endpoint(&["v1", "recipients"]);
    for (key, value) in [
        ("node", args.node),
        ("kind", args.kind),
        ("status", args.status),
        ("tag", args.tag),
    ] {
        if let Some(value) = value {
            url.query_pairs_mut().append_pair(key, &value);
        }
    }
    url.query_pairs_mut()
        .append_pair("limit", &args.limit.to_string());
    let value = request(&args.options, "GET", url, None, Duration::from_secs(5))?;
    if args.options.json {
        return print_json(&value, true);
    }
    let text = |value: &Value| value.as_str().unwrap_or("-").to_owned();
    println!(
        "{:<36} {:<9} {:<20} {:<8} NODE",
        "ADDRESS", "KIND", "LABEL", "STATUS"
    );
    for row in value["recipients"].as_array().ok_or("missing recipients")? {
        println!(
            "{:<36} {:<9} {:<20} {:<8} {}",
            text(&row["address"]),
            text(&row["kind"]),
            text(&row["label"]),
            text(&row["status"]),
            text(&row["node"])
        );
        if let Some(context) = row.get("context") {
            print_context(&serde_json::from_value(context.clone())?);
        }
        if let Some(tags) = row.get("tags").and_then(Value::as_array) {
            let names: Vec<&str> = tags.iter().filter_map(Value::as_str).collect();
            if !names.is_empty() {
                println!("  tags: {}", names.join(", "));
            }
        }
    }
    println!("\nNODE\tSTATUS");
    for row in value["nodes"].as_array().ok_or("missing nodes")? {
        println!(
            "{}\t{}{}",
            text(&row["node"]),
            text(&row["status"]),
            row["detail"]
                .as_str()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default()
        );
    }
    if value["truncated"] == true {
        println!(
            "\nShowing {} of {}; narrow filters or raise --limit.",
            value["recipients"]
                .as_array()
                .ok_or("missing recipients")?
                .len(),
            value["total"]
        );
    }
    if let Some(cov) = value.get("coverage").filter(|c| !c.is_null()) {
        if cov["complete"] == false {
            println!(
                "\ncoverage incomplete (unanswered: {:?}, tag_incapable: {:?})",
                cov["unanswered"], cov["tag_incapable"]
            );
        }
    }
    Ok(())
}

pub fn send(args: SendArgs) -> Result<()> {
    let text = match args.text.as_deref() {
        Some(text) if text != "-" => text.to_owned(),
        _ => {
            let mut text = String::new();
            io::stdin().read_to_string(&mut text)?;
            text
        }
    };
    let mut body = json!({"to": args.to, "text": text, "from": args.from});
    if let Some(key) = args.idempotency_key {
        body["idempotency_key"] = json!(key);
    }
    let value = request(
        &args.options,
        "POST",
        endpoint(&["v1", "messages"]),
        Some(body),
        Duration::from_secs(5),
    )?;
    if args.options.json {
        print_json(&value, true)
    } else {
        println!(
            "{} {} {}",
            value["message_id"].as_str().ok_or("missing message id")?,
            value["outcome"].as_str().ok_or("missing outcome")?,
            value["address"].as_str().ok_or("missing address")?
        );
        Ok(())
    }
}

pub fn replies(args: RepliesArgs) -> Result<()> {
    let mut url = endpoint(&["v1", "messages", &args.message_id, "replies"]);
    url.query_pairs_mut()
        .append_pair("wait", &args.wait.to_string());
    let value = request(
        &args.options,
        "GET",
        url,
        None,
        Duration::from_secs(args.wait + 5),
    )?;
    print_json(&value, args.options.json)
}

pub fn show(args: ShowArgs) -> Result<()> {
    let value = request(
        &args.options,
        "GET",
        endpoint(&["v1", "messages", &args.message_id]),
        None,
        Duration::from_secs(5),
    )?;
    print_json(&value, args.options.json)
}

#[derive(Args, Debug)]
#[command(group(clap::ArgGroup::new("target").required(true).args(["address", "label"])))]
pub struct LocateArgs {
    #[command(flatten)]
    options: Options,
    address: Option<String>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long)]
    detail: bool,
    /// Viewer-only TOML preferences and display-only reach hints
    #[arg(long)]
    locate_config: Option<PathBuf>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocateFile {
    #[serde(default)]
    locate: LocatePreferences,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocatePreferences {
    #[serde(default)]
    detail: bool,
    #[serde(default)]
    reach: std::collections::BTreeMap<String, String>,
}

pub fn locate(args: LocateArgs) -> Result<()> {
    let config: LocateFile = match &args.locate_config {
        Some(file) => toml::from_str(&std::fs::read_to_string(file)?)?,
        None => LocateFile::default(),
    };
    let detail = args.detail && config.locate.detail;
    let mut url = endpoint(&["v1", "locate"]);
    if let Some(address) = &args.address {
        url.query_pairs_mut().append_pair("address", address);
    }
    if let Some(label) = &args.label {
        url.query_pairs_mut().append_pair("label", label);
    }
    url.query_pairs_mut()
        .append_pair("detail", if detail { "true" } else { "false" });
    let raw = request(&args.options, "GET", url, None, Duration::from_secs(10))?;
    let mut result: xmsg::locator::Located = serde_json::from_value(raw)?;
    if !detail {
        for item in &mut result.locators {
            item.cwd = None;
            if let Some(env) = &mut item.env {
                env.reference = None;
            }
        }
    }
    if args.options.json {
        return print_json(&serde_json::to_value(result)?, true);
    }
    let inert = xmsg::locator::inert;
    if result.locators.is_empty() {
        println!("No matching sessions in the nodes that answered.");
    }
    for item in result.locators {
        let row = item.recipient;
        println!(
            "{}  harness={}  status={}  label={}",
            inert(&row.address),
            inert(row.harness.as_deref().unwrap_or("unknown")),
            inert(&row.status),
            inert(row.label.as_deref().unwrap_or("-"))
        );
        let resume_display = match &item.resume {
            Some(argv) => format!(
                "[{}]",
                argv.iter()
                    .map(|token| inert(token))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => "none".to_string(),
        };
        println!(
            "  native_id={}  resume={} ({})",
            inert(item.native_id.as_deref().unwrap_or("unknown")),
            resume_display,
            inert(&item.reason)
        );
        if let Some(env) = item.env {
            println!(
                "  env={}{}",
                serde_json::to_string(&env.kind)?,
                env.reference
                    .map(|s| format!(" ref={}", inert(&s)))
                    .unwrap_or_default()
            );
        }
        if let Some(context) = &row.context {
            print_context(context);
        }
        if let Some(cwd) = item.cwd {
            println!("  cwd={}", inert(&cwd));
        }
        if item.native_id.is_none() {
            println!(
                "  For local detail, run xmsg locate on {}.",
                inert(&row.node)
            );
        }
    }
    for node in result.nodes {
        println!(
            "node {}: {}{}",
            inert(&node.node),
            inert(&node.status),
            node.detail
                .map(|s| format!(" ({})", inert(&s)))
                .unwrap_or_default()
        );
        if let Some(hint) = config.locate.reach.get(&node.node) {
            println!("\nReach hint (display only):\n  {}\n", inert(hint));
        }
    }
    Ok(())
}

#[derive(Args, Debug)]
pub struct HarnessArgs {
    #[command(subcommand)]
    pub action: HarnessAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum HarnessAction {
    /// Immediately security-revoke a declared harness on the local daemon (zero drain delay)
    Revoke {
        name: String,
        #[command(flatten)]
        options: Options,
    },
    /// Atomically reload --harnesses-file on the local daemon
    Reload {
        #[command(flatten)]
        options: Options,
    },
}

pub fn harness(args: HarnessArgs) -> Result<()> {
    match args.action {
        HarnessAction::Revoke { name, options } => {
            let value = request(
                &options,
                "POST",
                endpoint(&["v1", "harnesses", &name, "revoke"]),
                None,
                Duration::from_secs(5),
            )?;
            if options.json {
                print_json(&value, true)
            } else {
                println!("revoked harness {}", xmsg::locator::inert(&name));
                Ok(())
            }
        }
        HarnessAction::Reload { options } => {
            let value = request(
                &options,
                "POST",
                endpoint(&["v1", "harnesses", "reload"]),
                None,
                Duration::from_secs(5),
            )?;
            if options.json {
                print_json(&value, true)
            } else {
                println!("reloaded harnesses file");
                Ok(())
            }
        }
    }
}

pub fn tag(args: TagArgs) -> Result<()> {
    let sock = match args.agent_sock {
        Some(path) => path,
        None => xmsg::agent::default_agent_sock_path()?,
    };
    let frame = match args.action {
        TagAction::Add { name } => json!({
            "action": "tag",
            "schema_version": xmsg::surface::MCP_SCHEMA_VERSION,
            "add": name,
        }),
        TagAction::Remove { name } => json!({
            "action": "tag",
            "schema_version": xmsg::surface::MCP_SCHEMA_VERSION,
            "remove": name,
        }),
    };
    let resp = xmsg::mcp::call_agent_sock(&sock, &frame)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    if args.json {
        print_json(&resp, true)
    } else {
        let addr = resp["address"].as_str().unwrap_or("");
        let tags: Vec<&str> = resp["tags"]
            .as_array()
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if tags.is_empty() {
            println!("{addr}: (no tags)");
        } else {
            println!("{addr}: {}", tags.join(", "));
        }
        Ok(())
    }
}
