use crate::observe_collector_store::{NodeStatus, NodeView};
use crate::observe_export::EndpointKind;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::fmt::Write;

pub const MAX_HTML: usize = 4 * 1024 * 1024;
pub const PAGE_ROWS: usize = 200;
pub const MAX_ENDPOINTS: usize = 200;
pub const CSS: &str = "body{margin:0;background:#151311;color:#f7f2eb;font:16px system-ui,sans-serif;line-height:1.5}main{max-width:1100px;margin:auto;padding:24px}a{color:#ff7a59}h1,h2,h3{line-height:1.2}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}.tile,section{background:#1d1b18;border:1px solid #554a41;border-radius:8px;padding:16px;margin:12px 0}.muted,small{color:#c2b9ad}.warning{color:#ff7a59}svg{display:block;max-width:100%;height:auto;overflow:hidden}svg text{fill:#f7f2eb;font:14px system-ui,sans-serif}svg circle,svg rect{fill:#1d1b18;stroke:#ff7a59;stroke-width:2}svg line{stroke:#ff7a59;stroke-width:2}table{width:100%;border-collapse:collapse;table-layout:fixed}td,th{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid #554a41;overflow-wrap:anywhere}code{overflow-wrap:anywhere}nav{display:flex;gap:24px}a:focus{outline:2px solid #ff7a59;outline-offset:4px}";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub node: Option<usize>,
    pub page: usize,
}
impl Filter {
    pub fn parse(query: Option<&str>, nodes: usize) -> Result<Self, &'static str> {
        let mut filter = Self::default();
        let mut seen_node = false;
        let mut seen_page = false;
        for item in query
            .unwrap_or_default()
            .split('&')
            .filter(|s| !s.is_empty())
        {
            let (key, value) = item.split_once('=').ok_or("invalid filter")?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid filter");
            }
            let number = value.parse::<usize>().map_err(|_| "invalid filter")?;
            match key {
                "node" if !seen_node && number < nodes => {
                    seen_node = true;
                    filter.node = Some(number);
                }
                "page" if !seen_page && number < 50 => {
                    seen_page = true;
                    filter.page = number;
                }
                _ => return Err("invalid filter"),
            }
        }
        if filter.node.is_none() && filter.page != 0 {
            return Err("invalid filter");
        }
        Ok(filter)
    }
    pub fn read_limit(self) -> usize {
        ((self.page + 1) * PAGE_ROWS + 1).min(10_000)
    }
}

pub fn content_security_policy() -> String {
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(CSS.as_bytes()));
    format!("default-src 'self'; script-src 'none'; style-src 'sha256-{hash}'; img-src 'self'; font-src 'self'; connect-src 'none'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'")
}

fn html_text(value: &str) -> String {
    escape(value)
}
fn svg_text(value: &str) -> String {
    escape(value)
}
fn escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
fn name<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}
fn status(value: NodeStatus) -> &'static str {
    match value {
        NodeStatus::HiddenPendingRevalidation => "pending revalidation",
        NodeStatus::Healthy => "healthy",
        NodeStatus::Stale => "stale: exporter unavailable",
        NodeStatus::Denied => "denied",
        NodeStatus::Unsupported => "unsupported: outbound-only source",
        NodeStatus::StorageFull => "storage full",
    }
}
struct Document {
    html: String,
    cap: usize,
    truncated: bool,
}
impl Document {
    fn push(&mut self, part: &str) {
        if self.html.len() + part.len() + 180 <= self.cap {
            self.html.push_str(part);
        } else {
            self.truncated = true;
        }
    }
}

pub fn render(summaries: &[NodeView], detail: Option<&NodeView>, filter: Filter) -> String {
    render_with_cap(summaries, detail, filter, MAX_HTML)
}
fn render_with_cap(
    summaries: &[NodeView],
    detail: Option<&NodeView>,
    filter: Filter,
    cap: usize,
) -> String {
    let mut out = Document {
        html: String::new(),
        cap,
        truncated: false,
    };
    out.push(&format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"refresh\" content=\"5\"><title>xmsg fleet observer</title><style>{CSS}</style></head><body><main><h1>Fleet observer</h1><p class=\"muted\">Read-only metadata from configured direct exporters. Source clocks are independent; these observations do not establish agent reads or completion.</p><nav><a href=\"/\">All nodes</a></nav><div class=\"tiles\">"));
    for (index, node) in summaries.iter().take(64).enumerate() {
        let mut tile = format!(
            "<article class=\"tile\"><h2><a href=\"/?node={index}\">{}</a></h2><p>{}</p>",
            html_text(&node.node),
            status(node.status)
        );
        if node.history_hidden && node.status != NodeStatus::Unsupported {
            tile.push_str("<p class=\"warning\">history hidden until this node answers</p>");
        }
        tile.push_str("</article>");
        out.push(&tile);
    }
    out.push("</div>");
    if let Some(node) = detail {
        out.push(&format!(
            "<section><h2>{}</h2><p>{}</p>",
            html_text(&node.node),
            status(node.status)
        ));
        if node.history_hidden {
            out.push("<p class=\"warning\">history hidden until this node answers</p>");
        } else {
            if node.backfill {
                out.push(
                    "<p class=\"warning\">Backfill pending: retained history is incomplete.</p>",
                );
            }
            if node.truncated {
                out.push(
                    "<p class=\"warning\">History truncated by retention or this bounded page.</p>",
                );
            }
            for gap in &node.gaps {
                out.push(&format!(
                    "<p class=\"warning\">Source boundary: {}; unknown loss: {}</p>",
                    name(gap.reason),
                    gap.unknown_loss
                ));
            }
            if let Some(snapshot) = &node.latest_snapshot {
                out.push(&format!("<h3>Latest source inventory</h3><p>Availability: {}; truncated: {}. Source observation: {} (age {} s); collector receipt: {} (age {} s).</p>",name(snapshot.snapshot.available),snapshot.snapshot.truncated,snapshot.snapshot.observed_at,snapshot.source_age_seconds,snapshot.received_at,snapshot.receipt_age_seconds));
                let endpoints = &snapshot.snapshot.endpoints;
                if endpoints.len() > MAX_ENDPOINTS {
                    out.push("<p class=\"warning\">Endpoint objects truncated to 200.</p>");
                }
                for endpoint in endpoints.iter().take(MAX_ENDPOINTS) {
                    let shape = match endpoint.kind {
                        EndpointKind::Instance | EndpointKind::Subagent => {
                            "<circle cx=\"18\" cy=\"22\" r=\"10\"/>"
                        }
                        EndpointKind::Service => {
                            "<rect x=\"8\" y=\"12\" width=\"20\" height=\"20\"/>"
                        }
                        EndpointKind::Unknown => "<text x=\"10\" y=\"27\">?</text>",
                    };
                    out.push(&format!("<svg class=\"endpoint\" role=\"img\" aria-label=\"reported endpoint\" viewBox=\"0 0 1000 62\">{shape}<text x=\"40\" y=\"22\">{}</text><text x=\"40\" y=\"46\">{}</text></svg><p class=\"endpoint-label\">{} <small>kind: {}; harness: {}; state: {}</small></p>", svg_text(&endpoint.id),svg_text(endpoint.label.as_deref().unwrap_or("label not reported")),html_text(endpoint.label.as_deref().unwrap_or("label not reported")),name(endpoint.kind),name(endpoint.harness),name(endpoint.state)));
                }
            } else {
                out.push("<p>Source inventory unknown: no retained snapshot.</p>");
            }
            out.push("<h3>Reported exchanges</h3><p class=\"muted\">Lanes show only the from/to values reported by this source. Missing endpoints remain unknown.</p>");
            let first = filter.page * PAGE_ROWS;
            let events = node.events.iter().skip(first).take(PAGE_ROWS);
            for cached in events {
                let event = &cached.event;
                let endpoint = |id: Option<&str>| -> String {
                    let Some(id) = id else {
                        return "unknown".into();
                    };
                    let descriptor = node
                        .latest_snapshot
                        .as_ref()
                        .and_then(|s| s.snapshot.endpoints.iter().find(|e| e.id == id));
                    match descriptor.and_then(|e| e.label.as_deref()) {
                        Some(label) => format!("{id} ({label})"),
                        None => id.to_owned(),
                    }
                };
                let from = endpoint(event.from.as_deref());
                let to = endpoint(event.to.as_deref());
                let mut part = format!("<article class=\"event\"><h3>Epoch {} · sequence {}</h3><svg class=\"lane\" role=\"img\" aria-label=\"reported exchange\" viewBox=\"0 0 1000 80\"><text x=\"10\" y=\"20\">{}</text><line x1=\"20\" y1=\"38\" x2=\"980\" y2=\"38\"/><text x=\"10\" y=\"65\">{}</text></svg><p>{}; outcome: {}; reason: {}; availability at capture: {}.</p><p>Source event time: {}; source observation: {} (age {} s); source persistence: {}. Collector receipt: {} (age {} s).</p>",html_text(&cached.epoch),event.sequence,svg_text(&from),svg_text(&to),name(event.kind),event.outcome.map(name).unwrap_or_else(|| "unknown".into()),event.reason.map(name).unwrap_or_else(|| "unknown".into()),name(event.available),event.source_at.map(|v|v.to_string()).unwrap_or_else(||"unknown".into()),event.observed_at,cached.source_age_seconds,event.persisted_at,cached.received_at,cached.receipt_age_seconds);
                for (label, value) in [
                    ("Message", event.message_id.as_deref()),
                    ("Thread", event.thread_id.as_deref()),
                ] {
                    if let Some(value) = value {
                        let _ = write!(part, "<p>{label}: <code>{}</code></p>", html_text(value));
                    }
                }
                part.push_str("</article>");
                out.push(&part);
            }
            if let Some(index) = filter.node {
                out.push("<nav aria-label=\"History pages\">");
                if filter.page > 0 {
                    out.push(&format!(
                        "<a href=\"/?node={index}&amp;page={}\">Previous page</a>",
                        filter.page - 1
                    ));
                }
                if node.events.len() > first + PAGE_ROWS && filter.page < 49 {
                    out.push(&format!(
                        "<a href=\"/?node={index}&amp;page={}\">Next page</a>",
                        filter.page + 1
                    ));
                }
                out.push("</nav>");
            }
        }
        out.push("</section>");
    }
    if out.truncated {
        out.html
            .push_str("<p class=\"warning\">Output truncated by the response byte limit.</p>");
    }
    out.html.push_str("</main></body></html>");
    out.html
}

#[cfg(test)]
#[path = "observe_collector_web_tests.rs"]
mod tests;
