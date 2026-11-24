use super::assets::{CSS_PATH, JS_PATH};
use super::hub::Snapshot;
use super::protocol::{Delivery, Status};
use hyper::header::HeaderMap;
use std::fmt::Write as _;

pub(super) const CANONICAL_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'";

pub(super) fn sec_fetch_site(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for value in headers.get_all("sec-fetch-site") {
        let s = value.to_str().ok()?.trim();
        if s.is_empty() || found.is_some() {
            return None;
        }
        found = Some(s);
    }
    found
}

pub(super) fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub(super) fn signin_shell() -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Mission Control</title><link rel=\"stylesheet\" href=\"{CSS_PATH}\"></head><body><main><header class=\"mc-shell-bar\"><h1>Mission Control</h1><nav class=\"mc-shell-actions\"><a class=\"mc-btn\" href=\"/login\">Sign in</a></nav></header><p class=\"mc-muted\">Sign in to inspect this fleet.</p></main></body></html>"
    )
}

pub(super) fn no_data_shell() -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Mission Control</title><link rel=\"stylesheet\" href=\"{CSS_PATH}\"></head><body><main><header class=\"mc-shell-bar\"><h1>Mission Control</h1><nav class=\"mc-shell-actions\"><a class=\"mc-btn\" href=\"/\">Open Mission Control</a></nav></header><p class=\"mc-muted\">Open Mission Control directly to view fleet state.</p></main></body></html>"
    )
}

pub(super) fn callback_bridge() -> &'static str {
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=/\"><title>Signing in</title></head><body><main><p>Signed in. <a href=\"/\">Continue</a></p></main></body></html>"
}

pub(super) fn authenticated_shell(csrf_token: &str, snapshot: Option<&Snapshot>) -> String {
    let mut ssr = String::new();
    if let Some(snap) = snapshot {
        if snap.nodes.is_empty() {
            ssr.push_str("<p class=\"mc-muted\">No nodes configured in scope.</p>");
        } else {
            for node in &snap.nodes {
                let status = match node.status {
                    Status::Loading => "loading",
                    Status::PendingRevalidation => "pending_revalidation",
                    Status::Healthy => "healthy",
                    Status::Stale => "stale",
                    Status::Denied => "denied",
                    Status::UnsupportedOutboundOnly => "unsupported_outbound_only",
                    Status::UnsupportedTransport => "unsupported_transport",
                    Status::StorageFull => "storage_full",
                    Status::RemovedRetained => "removed_retained",
                };
                let delivery = match node.delivery {
                    Delivery::Live => "live",
                    Delivery::Delayed => "delayed",
                };
                let _ = write!(
                    ssr,
                    "<section class=\"mc-node\" data-ssr-node=\"{}\"><div class=\"mc-node-header\"><h2 class=\"mc-node-name\">{}</h2><span class=\"mc-tag\">{}</span><span class=\"mc-tag\">{}</span></div>",
                    escape_html(&node.node),
                    escape_html(&node.node),
                    status,
                    delivery,
                );
                if node.history_hidden {
                    ssr.push_str("<p class=\"mc-muted\">History masked by node policy.</p>");
                } else if node.endpoints.is_empty() {
                    ssr.push_str("<p class=\"mc-muted\">No active endpoints.</p>");
                } else {
                    ssr.push_str("<table class=\"mc-table\"><thead><tr><th scope=\"col\">Agent</th><th scope=\"col\">Harness</th><th scope=\"col\">State</th><th scope=\"col\">Manage</th></tr></thead><tbody>");
                    for ep in &node.endpoints {
                        let label = ep
                            .descriptor
                            .label
                            .as_deref()
                            .map(|l| format!("{} ({})", escape_html(l), escape_html(&ep.descriptor.id)))
                            .unwrap_or_else(|| escape_html(&ep.descriptor.id));
                        let harness_json = serde_json::to_string(&ep.descriptor.harness)
                            .unwrap_or_else(|_| "\"unknown\"".to_owned());
                        let harness = escape_html(harness_json.trim_matches('"'));
                        let state = ep
                            .activity
                            .as_ref()
                            .map(|a| format!("{:?}", a.state).to_lowercase())
                            .unwrap_or_else(|| "unknown".to_owned());
                        let _ = write!(
                            ssr,
                            "<tr><td>{label}</td><td class=\"mc-mono\">{harness}</td><td>{state}</td><td class=\"mc-muted\">Disabled: inspect-only rollout</td></tr>"
                        );
                    }
                    ssr.push_str("</tbody></table>");
                }
                ssr.push_str("</section>");
            }
        }
    }
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Mission Control</title><link rel=\"stylesheet\" href=\"{CSS_PATH}\"><script defer src=\"{JS_PATH}\"></script></head><body><main><header class=\"mc-shell-bar\"><h1>Mission Control</h1><nav class=\"mc-shell-actions\"><a class=\"mc-btn\" href=\"/device\">Connect a device</a><form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf_token}\"><button class=\"mc-btn\" type=\"submit\">Sign out</button></form></nav></header><div id=\"mc-live\"></div><div id=\"mc-ssr\">{ssr}</div></main></body></html>"
    )
}
