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

pub fn list(args: ListArgs) -> Result<()> {
    let mut url = endpoint(&["v1", "recipients"]);
    for (key, value) in [
        ("node", args.node),
        ("kind", args.kind),
        ("status", args.status),
    ] {
        if let Some(value) = value {
            url.query_pairs_mut().append_pair(key, &value);
        }
    }
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
