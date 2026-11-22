use super::json_edit::{Document, Kind, Node};
use super::*;
use serde_json::{json, Value};

pub(super) const SKILL: &[u8] = include_bytes!("../../assets/claude/xmsg/SKILL.md");
fn value(document: &Document, node: &Node) -> Result<Value, Error> {
    document.value(node).map_err(|_| Error::InvalidJson)
}
fn document(bytes: &[u8]) -> Result<Document, Error> {
    let d = Document::parse(bytes).map_err(|_| Error::InvalidJson)?;
    if !matches!(d.root.kind, Kind::Object(_)) {
        return Err(Error::Unsupported);
    }
    Ok(d)
}
fn at<'a>(d: &'a Document, path: &[&str]) -> Result<Option<&'a Node>, Error> {
    d.at(path).map_err(|_| Error::Unsupported)
}
fn set(bytes: &[u8], parent: &[&str], key: &str, new: &Value) -> Result<Vec<u8>, Error> {
    let d = document(bytes)?;
    let node = at(&d, parent)?.ok_or(Error::Unsupported)?;
    match d
        .set_member(node, key, new)
        .map_err(|_| Error::Unsupported)?
    {
        Some(edit) => d.render(&[edit]).map_err(|_| Error::InvalidJson),
        None => Ok(bytes.to_vec()),
    }
}
fn remove(bytes: &[u8], parent: &[&str], key: &str) -> Result<Vec<u8>, Error> {
    let d = document(bytes)?;
    let node = at(&d, parent)?.ok_or(Error::Unsupported)?;
    match d.remove_member(node, key).map_err(|_| Error::Unsupported)? {
        Some(edit) => d.render(&[edit]).map_err(|_| Error::InvalidJson),
        None => Ok(bytes.to_vec()),
    }
}
fn raw_hash(d: &Document, node: &Node) -> String {
    hash(&d.source[node.span.clone()])
}
fn quote_text(text: &str) -> Result<String, Error> {
    if text.contains('\0') {
        return Err(Error::Unsafe);
    }
    Ok(format!("'{}'", text.replace('\'', "'\\''")))
}
fn quote(path: &std::path::Path) -> Result<String, Error> {
    let text = path.to_str().ok_or(Error::Unsupported)?;
    if !path.is_absolute() || text.contains('\0') {
        return Err(Error::Unsafe);
    }
    quote_text(text)
}
type DesiredHooks = Vec<(ManagedField, String, Value)>;
fn desired(request: &Request) -> Result<(Value, DesiredHooks), Error> {
    let executable = request.executable.to_str().ok_or(Error::Unsupported)?;
    let mut args = vec![json!("mcp"), json!("--db-path"), json!(request.db_path)];
    if let Some(path) = &request.agent_socket {
        args.extend([json!("--agent-sock"), json!(path)]);
    }
    if let Some(path) = &request.http_socket {
        args.extend([json!("--http-sock"), json!(path)]);
    }
    let mcp =
        json!({"type":"stdio","command":executable,"args":args,"env":request.command_environment});
    let mut command = String::new();
    for (name, value) in &request.command_environment {
        command.push_str(&format!("{name}={} ", quote_text(value)?));
    }
    command.push_str(&format!(
        "{} register claude --hook --db-path {}",
        quote(&request.executable)?,
        quote(&request.db_path)?
    ));
    if let Some(path) = &request.agent_socket {
        command.push_str(&format!(" --sock {}", quote(path)?));
    }
    let hook = json!({"type":"command","command":command});
    let mut groups = Vec::new();
    for prefix in ["mcp__xmsg", "mcp__plugin_hm_xmsg"] {
        let matcher = format!("^{prefix}__(send|reply|inbox|list|replies)$");
        groups.push((
            ManagedField::PreToolUse,
            matcher.clone(),
            json!({"matcher":matcher,"hooks":[hook.clone()]}),
        ));
    }
    groups.push((
        ManagedField::PostToolUse,
        "^(Agent|SendMessage)$".into(),
        json!({"matcher":"^(Agent|SendMessage)$","hooks":[hook.clone()]}),
    ));
    groups.push((
        ManagedField::SubagentStart,
        String::new(),
        json!({"hooks":[hook.clone()]}),
    ));
    groups.push((
        ManagedField::SubagentStop,
        String::new(),
        json!({"hooks":[hook]}),
    ));
    Ok((mcp, groups))
}
fn event(field: ManagedField) -> &'static str {
    match field {
        ManagedField::PreToolUse => "PreToolUse",
        ManagedField::PostToolUse => "PostToolUse",
        ManagedField::SubagentStart => "SubagentStart",
        ManagedField::SubagentStop => "SubagentStop",
        _ => unreachable!(),
    }
}
fn changed(changes: &mut Vec<Change>, field: ManagedField, operation: Operation) {
    changes.push(Change { field, operation });
}
fn mcp(
    bytes: &[u8],
    wanted: &Value,
    old: &Ownership,
    new: &mut Ownership,
    action: Action,
    changes: &mut Vec<Change>,
) -> Result<Vec<u8>, Error> {
    let d = document(bytes)?;
    let current = at(&d, &["mcpServers", "xmsg"])?;
    let owned = old
        .entries
        .iter()
        .find(|entry| entry.field == ManagedField::Mcp);
    if let Some(entry) = owned {
        if current.is_none_or(|node| raw_hash(&d, node) != entry.hash) {
            if action == Action::Install {
                return Err(Error::Conflict);
            }
            changed(changes, ManagedField::Mcp, Operation::Conflict);
            new.entries.push(entry.clone());
            return Ok(bytes.to_vec());
        }
    }
    match action {
        Action::Install => {
            if let Some(node) = current {
                if owned.is_none() {
                    if value(&d, node)? != *wanted {
                        return Err(Error::Conflict);
                    }
                    changed(changes, ManagedField::Mcp, Operation::Reuse);
                    return Ok(bytes.to_vec());
                }
                if value(&d, node)? == *wanted {
                    new.entries.push(owned.unwrap().clone());
                    return Ok(bytes.to_vec());
                }
            }
            let base = if at(&d, &["mcpServers"])?.is_none() {
                new.created_containers.insert("mcpServers".into());
                set(bytes, &[], "mcpServers", &json!({}))?
            } else {
                bytes.to_vec()
            };
            let out = set(&base, &["mcpServers"], "xmsg", wanted)?;
            let doc = document(&out)?;
            let node = at(&doc, &["mcpServers", "xmsg"])?.ok_or(Error::Conflict)?;
            new.entries.push(OwnedEntry {
                field: ManagedField::Mcp,
                selector: String::new(),
                value: wanted.clone(),
                hash: raw_hash(&doc, node),
            });
            changed(
                changes,
                ManagedField::Mcp,
                if current.is_some() {
                    Operation::Replace
                } else {
                    Operation::Add
                },
            );
            Ok(out)
        }
        Action::Uninstall => {
            if owned.is_none() {
                return Ok(bytes.to_vec());
            }
            let mut out = remove(bytes, &["mcpServers"], "xmsg")?;
            let d = document(&out)?;
            if old.created_containers.contains("mcpServers")
                && at(&d, &["mcpServers"])?
                    .is_some_and(|n| matches!(&n.kind,Kind::Object(m) if m.is_empty()))
            {
                out = remove(&out, &[], "mcpServers")?;
            }
            changed(changes, ManagedField::Mcp, Operation::Remove);
            Ok(out)
        }
    }
}
fn groups(
    bytes: &[u8],
    wanted: &[(ManagedField, String, Value)],
    old: &Ownership,
    new: &mut Ownership,
    action: Action,
    changes: &mut Vec<Change>,
) -> Result<Vec<u8>, Error> {
    let mut out = bytes.to_vec();
    let entries: Vec<_> = match action {
        Action::Install => wanted.to_vec(),
        Action::Uninstall => old
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.field,
                    ManagedField::PreToolUse
                        | ManagedField::PostToolUse
                        | ManagedField::SubagentStart
                        | ManagedField::SubagentStop
                )
            })
            .map(|e| (e.field, e.selector.clone(), e.value.clone()))
            .collect(),
    };
    for (field, selector, wanted) in entries {
        let name = event(field);
        let old_entry = old
            .entries
            .iter()
            .find(|entry| entry.field == field && entry.selector == selector);
        let d = document(&out)?;
        let current = at(&d, &["hooks", name])?;
        let nodes = match current {
            Some(Node {
                kind: Kind::Array(nodes),
                ..
            }) => nodes.as_slice(),
            None => &[],
            _ => return Err(Error::Unsupported),
        };
        let expected = old_entry.map(|e| &e.value).unwrap_or(&wanted);
        let mut matches = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            if value(&d, node)? == *expected {
                matches.push((index, node));
            }
        }
        if matches.len() > 1 {
            return Err(Error::Conflict);
        }
        let matched = matches.first().copied();
        if let Some(entry) = old_entry {
            if matched.is_none_or(|(_, node)| raw_hash(&d, node) != entry.hash) {
                if action == Action::Install {
                    return Err(Error::Conflict);
                }
                changed(changes, field, Operation::Conflict);
                new.entries.push(entry.clone());
                continue;
            }
        }
        match action {
            Action::Install => {
                if let Some((_, node)) = matched {
                    if old_entry.is_none() {
                        changed(changes, field, Operation::Reuse);
                        continue;
                    }
                    if value(&d, node)? == wanted {
                        new.entries.push(old_entry.unwrap().clone());
                        continue;
                    }
                    let edit = super::json_edit::Edit {
                        span: node.span.clone(),
                        replacement: serde_json::to_vec(&wanted).map_err(|_| Error::InvalidJson)?,
                    };
                    out = d.render(&[edit]).map_err(|_| Error::InvalidJson)?;
                    changed(changes, field, Operation::Replace);
                } else {
                    for node in nodes {
                        let v = value(&d, node)?;
                        if v.get("matcher").and_then(|v| v.as_str()).unwrap_or("") == selector
                            && v.get("hooks")
                                .and_then(|v| v.as_array())
                                .is_some_and(|hooks| {
                                    hooks.iter().any(|h| {
                                        h.get("command")
                                            .and_then(|v| v.as_str())
                                            .is_some_and(|c| c.contains("register claude --hook"))
                                    })
                                })
                        {
                            return Err(Error::Conflict);
                        }
                    }
                    if at(&d, &["hooks"])?.is_none() {
                        out = set(&out, &[], "hooks", &json!({}))?;
                        new.created_containers.insert("hooks".into());
                    }
                    let d = document(&out)?;
                    if at(&d, &["hooks", name])?.is_none() {
                        out = set(&out, &["hooks"], name, &json!([]))?;
                        new.created_containers.insert(format!("hooks.{name}"));
                    }
                    let d = document(&out)?;
                    let array = at(&d, &["hooks", name])?.ok_or(Error::Conflict)?;
                    let edit = d
                        .append_element(array, &wanted)
                        .map_err(|_| Error::Unsupported)?;
                    out = d.render(&[edit]).map_err(|_| Error::InvalidJson)?;
                    changed(changes, field, Operation::Add);
                }
                let d = document(&out)?;
                let Some(Node {
                    kind: Kind::Array(nodes),
                    ..
                }) = at(&d, &["hooks", name])?
                else {
                    return Err(Error::Conflict);
                };
                let mut found = None;
                for node in nodes {
                    if value(&d, node)? == wanted {
                        if found.is_some() {
                            return Err(Error::Conflict);
                        }
                        found = Some(node);
                    }
                }
                new.entries.push(OwnedEntry {
                    field,
                    selector,
                    value: wanted,
                    hash: raw_hash(&d, found.ok_or(Error::Conflict)?),
                });
            }
            Action::Uninstall => {
                let Some((index, _)) = matched else { continue };
                let edit = d
                    .remove_element(current.ok_or(Error::Conflict)?, index)
                    .map_err(|_| Error::Unsupported)?;
                out = d.render(&[edit]).map_err(|_| Error::InvalidJson)?;
                let d = document(&out)?;
                if old.created_containers.contains(&format!("hooks.{name}"))
                    && at(&d, &["hooks", name])?
                        .is_some_and(|n| matches!(&n.kind,Kind::Array(v) if v.is_empty()))
                {
                    out = remove(&out, &["hooks"], name)?;
                }
                changed(changes, field, Operation::Remove);
            }
        }
    }
    let d = document(&out)?;
    if action == Action::Uninstall
        && old.created_containers.contains("hooks")
        && at(&d, &["hooks"])?.is_some_and(|n| matches!(&n.kind,Kind::Object(v) if v.is_empty()))
    {
        out = remove(&out, &[], "hooks")?;
    }
    Ok(out)
}

pub(super) fn plan(request: &Request, action: Action) -> Result<Plan, Error> {
    if request.uid != unsafe { libc::geteuid() } || !request.account_home.is_absolute() {
        return Err(Error::Unsafe);
    }
    let home = transaction::canonical(&request.account_home)?;
    if request.config_dir.is_some() {
        return Err(Error::Unsupported);
    }
    if super::claude_observe::inspect(request)?.managed_policy == "conflict" {
        return Err(Error::Conflict);
    }
    let targets = vec![
        home.join(".claude.json"),
        home.join(".claude/settings.json"),
        home.join(".claude/skills/xmsg/SKILL.md"),
    ]
    .into_iter()
    .map(|p| transaction::canonical(&p))
    .collect::<Result<Vec<_>, _>>()?;
    let mut sorted = targets.clone();
    sorted.sort();
    let key = hash(&serde_json::to_vec(&sorted).map_err(|_| Error::Unsupported)?);
    let loaded = transaction::load_ownership(request, &key)?;
    let mut old = loaded
        .as_ref()
        .map(|(o, _)| o.clone())
        .unwrap_or(Ownership {
            version: 1,
            set_id: key.clone(),
            targets: sorted.clone(),
            active: false,
            entries: Vec::new(),
            created_files: BTreeSet::new(),
            created_containers: BTreeSet::new(),
        });
    if old.targets != sorted {
        return Err(Error::Conflict);
    }
    let pending = transaction::pending(request, &key)?;
    if !old.active && action == Action::Uninstall && !pending {
        return Ok(Plan {
            report: Report {
                action,
                status: "no_op",
                changes: Vec::new(),
            },
            request: request.clone(),
            targets: Vec::new(),
            ownership: old,
            before_ownership: loaded.map(|(_, hash)| hash),
            pending: false,
            metadata_change: false,
        });
    }
    if !old.active {
        old.entries.clear();
        old.created_files.clear();
        old.created_containers.clear();
    }
    let mut ownership = old.clone();
    ownership.entries.clear();
    ownership.active = action == Action::Install;
    if pending {
        return Ok(Plan {
            report: Report {
                action,
                status: "recovery_pending",
                changes: vec![Change {
                    field: ManagedField::Recovery,
                    operation: Operation::Recover,
                }],
            },
            request: request.clone(),
            targets: Vec::new(),
            ownership,
            before_ownership: loaded.map(|(_, h)| h),
            pending: true,
            metadata_change: true,
        });
    }
    let (wanted, group_values) = desired(request)?;
    let mut plans = Vec::new();
    let mut changes = Vec::new();
    for (kind, path) in [TargetKind::Mcp, TargetKind::Settings, TargetKind::Skill]
        .into_iter()
        .zip(targets)
    {
        let before = transaction::read(&path, request.uid)?;
        let bytes = before.as_ref().map(|s| s.bytes.as_slice()).unwrap_or(b"{}");
        let after = match kind {
            TargetKind::Mcp => Some(mcp(
                bytes,
                &wanted,
                &old,
                &mut ownership,
                action,
                &mut changes,
            )?),
            TargetKind::Settings => Some(groups(
                bytes,
                &group_values,
                &old,
                &mut ownership,
                action,
                &mut changes,
            )?),
            TargetKind::Skill => {
                let owned = old.entries.iter().find(|e| e.field == ManagedField::Skill);
                if owned.is_some_and(|e| before.as_ref().is_none_or(|s| hash(&s.bytes) != e.hash)) {
                    if action == Action::Install {
                        return Err(Error::Conflict);
                    }
                    ownership.entries.push(owned.unwrap().clone());
                    changed(&mut changes, ManagedField::Skill, Operation::Conflict);
                    before.as_ref().map(|s| s.bytes.clone())
                } else if action == Action::Install {
                    if owned.is_none() && before.as_ref().is_some_and(|s| s.bytes != SKILL) {
                        return Err(Error::Conflict);
                    }
                    if owned.is_none() && before.is_some() {
                        changed(&mut changes, ManagedField::Skill, Operation::Reuse);
                    } else {
                        ownership.entries.push(OwnedEntry {
                            field: ManagedField::Skill,
                            selector: String::new(),
                            value: Value::Null,
                            hash: hash(SKILL),
                        });
                        if before.is_none() {
                            changed(&mut changes, ManagedField::Skill, Operation::Add);
                        }
                    }
                    Some(SKILL.to_vec())
                } else if owned.is_some() {
                    changed(&mut changes, ManagedField::Skill, Operation::Remove);
                    None
                } else {
                    before.as_ref().map(|s| s.bytes.clone())
                }
            }
        };
        let mut after = after;
        if kind != TargetKind::Skill {
            if action == Action::Uninstall
                && old.created_files.contains(&kind)
                && after.as_ref().is_some_and(|b| {
                    document(b)
                        .is_ok_and(|d| matches!(d.root.kind,Kind::Object(ref m) if m.is_empty()))
                })
            {
                after = None;
            }
            if before.is_none()
                && after.as_ref().is_some_and(|b| {
                    document(b)
                        .is_ok_and(|d| matches!(d.root.kind,Kind::Object(ref m) if m.is_empty()))
                })
            {
                after = None;
            }
        }
        if before.is_none() && after.is_some() {
            ownership.created_files.insert(kind);
        }
        let mode = before.as_ref().map(|s| s.mode() & 0o600).unwrap_or(0o600);
        plans.push(TargetPlan {
            path,
            before,
            after,
            mode,
        });
    }
    if action == Action::Uninstall && !ownership.entries.is_empty() {
        ownership.active = true;
    }
    let metadata_change = loaded.as_ref().is_none_or(|(o, _)| *o != ownership)
        && (action == Action::Install || loaded.is_some());
    let has_writes = plans
        .iter()
        .any(|p| p.before.as_ref().map(|s| s.bytes.as_slice()) != p.after.as_deref());
    let conflicts = changes.iter().any(|c| c.operation == Operation::Conflict);
    Ok(Plan {
        report: Report {
            action,
            status: if conflicts {
                "conflict"
            } else if has_writes || metadata_change {
                "preview"
            } else {
                "no_op"
            },
            changes,
        },
        request: request.clone(),
        targets: plans,
        ownership,
        before_ownership: loaded.map(|(_, h)| h),
        pending: false,
        metadata_change,
    })
}
