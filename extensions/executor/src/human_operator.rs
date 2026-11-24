use crate::{
    approval::{
        HumanConfirmation, HumanDecisionCall, HumanPendingQuery, HumanQueryKind, NativePending,
    },
    control::{ControlReply, ErrorCode},
    protocol::{Action, ApproveArgs, ControlRequest, Decision, Target},
    runtime_config::RuntimeConfig,
};
use std::{
    io::{BufRead, BufReader, Write},
    os::fd::{AsFd, AsRawFd},
    time::{Duration, Instant},
};

fn failure(_: impl std::fmt::Display) -> ErrorCode {
    ErrorCode::HumanRequired
}

pub(crate) fn run(
    configuration: RuntimeConfig,
    session: String,
    generation: u64,
) -> Result<(), ErrorCode> {
    let proof = configuration.human_proof()?;
    let query = HumanPendingQuery {
        operation: HumanQueryKind::Pending,
        session_id: session,
        generation,
    };
    let Some(pending) = request::<_, Option<NativePending>>(&configuration, &proof, &query)? else {
        println!("no pending native request");
        return Ok(());
    };
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(failure)?;
    if unsafe { libc::isatty(tty.as_raw_fd()) } != 1 {
        return Err(ErrorCode::HumanRequired);
    }
    let remaining = pending
        .expires_at
        .checked_sub(crate::runtime_process::unix_now()?)
        .filter(|n| *n > 0)
        .ok_or(ErrorCode::DeadlineExpired)?;
    let expires = Instant::now()
        .checked_add(Duration::from_secs(remaining as u64))
        .ok_or(ErrorCode::DeadlineExpired)?;
    let mut input = tty.try_clone().map_err(failure)?;
    let mut reader =
        BufReader::new(crate::supervisor::DeadlineIo::new(&mut input, expires).map_err(failure)?);
    let mut writer = crate::supervisor::DeadlineIo::new(&mut tty, expires).map_err(failure)?;
    let call = confirm(
        &pending,
        &mut reader,
        &mut writer,
        &crate::runtime_process::unix_now,
    )?;
    let reply: ControlReply = request(&configuration, &proof, &call)?;
    if !matches!(
        reply.receipt.authorization,
        crate::protocol::Authorization::Allowed { .. }
    ) {
        return Err(ErrorCode::HumanRequired);
    }
    println!("native decision recorded; response effect is not yet confirmed");
    Ok(())
}

fn request<B: serde::Serialize, R: serde::de::DeserializeOwned>(
    configuration: &RuntimeConfig,
    proof: &[u8],
    body: &B,
) -> Result<R, ErrorCode> {
    use xmsg::client::caller_attribution as wire;
    let socket = &configuration.paths.human_socket;
    wire::private_socket(socket, xmsg::client::current_uid()).map_err(failure)?;
    let expires = Instant::now() + Duration::from_secs(2);
    let mut stream = wire::connect(socket, expires).map_err(failure)?;
    if wire::socket_peer(stream.as_fd()).map_err(failure)?.0 != xmsg::client::current_uid() {
        return Err(ErrorCode::PeerUid);
    }
    let mut bounded = crate::supervisor::DeadlineIo::new(&mut stream, expires).map_err(failure)?;
    let encoded = serde_json::to_vec(body).map_err(failure)?;
    if encoded.len() + 1 > crate::framing::MAX_FRAME_BYTES {
        return Err(ErrorCode::MalformedFrame);
    }
    bounded.write_all(proof).map_err(failure)?;
    bounded.write_all(b"\n").map_err(failure)?;
    bounded.write_all(&encoded).map_err(failure)?;
    bounded.write_all(b"\n").map_err(failure)?;
    let bytes = crate::unix::line(
        &mut BufReader::new(bounded),
        crate::framing::MAX_FRAME_BYTES,
    )?;
    match serde_json::from_slice::<crate::unix::WireReply<R>>(&bytes).map_err(failure)? {
        crate::unix::WireReply::Ok { result } => Ok(result),
        crate::unix::WireReply::Error { code } => Err(code),
    }
}

pub(crate) fn confirm(
    pending: &NativePending,
    input: &mut impl BufRead,
    output: &mut impl Write,
    clock: &dyn Fn() -> Result<i64, ErrorCode>,
) -> Result<HumanDecisionCall, ErrorCode> {
    use crate::acp::PermissionKind;
    let options: Vec<_> = pending
        .options
        .iter()
        .filter(|option| {
            matches!(
                option.kind,
                PermissionKind::AllowOnce | PermissionKind::RejectOnce
            )
        })
        .collect();
    writeln!(
        output,
        "native request {} for {} generation {} turn {}",
        serde_json::to_string(&pending.approval_id).map_err(failure)?,
        serde_json::to_string(&pending.binding.identity.session_id).map_err(failure)?,
        pending.binding.identity.generation,
        serde_json::to_string(&pending.turn_id).map_err(failure)?
    )
    .map_err(failure)?;
    writeln!(
        output,
        "{}",
        serde_json::to_string_pretty(&pending.raw).map_err(failure)?
    )
    .map_err(failure)?;
    for (index, option) in options.iter().enumerate() {
        writeln!(
            output,
            "{}: {:?} {}",
            index + 1,
            option.kind,
            serde_json::to_string(&option.name).map_err(failure)?
        )
        .map_err(failure)?;
    }
    writeln!(
        output,
        "{}: cancel request\nType: confirm {} <number>",
        options.len() + 1,
        pending.approval_id
    )
    .map_err(failure)?;
    output.flush().map_err(failure)?;
    let mut line = Vec::new();
    std::io::Read::take(input, 512)
        .read_until(b'\n', &mut line)
        .map_err(failure)?;
    if line.last() != Some(&b'\n') || line.len() >= 512 {
        return Err(ErrorCode::HumanRequired);
    }
    let text = std::str::from_utf8(&line).map_err(failure)?;
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() != 3 || fields[0] != "confirm" || fields[1] != pending.approval_id {
        return Err(ErrorCode::HumanRequired);
    }
    let selection = fields[2].parse::<usize>().map_err(failure)?;
    let (option_id, decision) = if selection == options.len() + 1 {
        ("@cancel".to_owned(), Decision::Deny)
    } else {
        let option = selection
            .checked_sub(1)
            .and_then(|i| options.get(i))
            .ok_or(ErrorCode::HumanRequired)?;
        (
            option.option_id.clone(),
            if option.kind == PermissionKind::AllowOnce {
                Decision::AllowOnce
            } else {
                Decision::Deny
            },
        )
    };
    let now = clock()?;
    if pending.expires_at <= now {
        return Err(ErrorCode::DeadlineExpired);
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(failure)?;
    Ok(HumanDecisionCall {
        request: ControlRequest {
            version: 1,
            request_id: format!("human-{}", hex::encode(nonce)),
            target: Some(Target::Turn {
                session_id: pending.binding.identity.session_id.clone(),
                generation: pending.binding.identity.generation,
                turn_id: pending.turn_id.clone(),
            }),
            action: Action::Approve(ApproveArgs {
                approval_id: pending.approval_id.clone(),
                operation_digest: pending.operation_digest.clone(),
                policy_revision: pending.policy_revision.to_string(),
                expires_at: pending.expires_at,
                option_id,
                decision,
            }),
            deadline: Some(pending.expires_at),
        },
        confirmation: HumanConfirmation {
            approval_id: pending.approval_id.clone(),
            operation_digest: pending.operation_digest.clone(),
            confirmed_at: now,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending() -> NativePending {
        NativePending {
            approval_id: "ask".into(),
            admission_id: 1,
            request_id: crate::framing::RequestId::Number(8),
            binding: crate::lifecycle::NativeBinding {
                identity: crate::execution::ExecutionIdentity {
                    session_id: "session-1".into(),
                    generation: 2,
                    launch_nonce: "a".repeat(32),
                    policy_revision: 4,
                    protocol_version: 2,
                    build_version: "fixture".into(),
                },
                native_session_id: "native".into(),
                transport_epoch: "b".repeat(32),
                native_mode: "default".into(),
                native_model_id: "fake-model".into(),
                expires_at: 200,
            },
            turn_id: "turn".into(),
            tool_call_id: "tool".into(),
            operation_digest: "c".repeat(64),
            policy_revision: 4,
            expires_at: 180,
            options: vec![
                crate::acp::PermissionOption {
                    option_id: "once".into(),
                    kind: crate::acp::PermissionKind::AllowOnce,
                    name: "allow one operation".into(),
                },
                crate::acp::PermissionOption {
                    option_id: "always".into(),
                    kind: crate::acp::PermissionKind::AllowAlways,
                    name: "persistent not supported".into(),
                },
                crate::acp::PermissionOption {
                    option_id: "reject".into(),
                    kind: crate::acp::PermissionKind::RejectOnce,
                    name: "deny one operation".into(),
                },
            ],
            raw: serde_json::json!({"title":"synthetic request\u{1b}[2J"}),
            human_mandatory_provenance: crate::acp::HumanMandatoryProvenance::Unproven,
        }
    }
    #[test]
    fn exact_typed_confirmation_selects_once_and_carries_current_binding() {
        let mut output = Vec::new();
        let request = pending();
        let call = confirm(
            &request,
            &mut std::io::Cursor::new(b"confirm ask 1\n"),
            &mut output,
            &|| Ok(100),
        )
        .unwrap();
        let Action::Approve(args) = &call.request.action else {
            panic!("approval expected")
        };
        assert_eq!(
            (args.option_id.as_str(), &args.decision),
            ("once", &Decision::AllowOnce)
        );
        assert_eq!(call.confirmation.confirmed_at, 100);
        assert_eq!(call.confirmation.operation_digest, request.operation_digest);
        assert_eq!(
            call.request.target,
            Some(Target::Turn {
                session_id: "session-1".into(),
                generation: 2,
                turn_id: "turn".into()
            })
        );
        assert!(call.request.validate().is_ok());
        assert!(
            !output.contains(&0x1b),
            "native request injected terminal control bytes"
        );
    }
    #[test]
    fn no_blanket_yes_stale_confirmation_or_persistent_permission() {
        for line in [
            b"yes\n".as_slice(),
            b"confirm other 1\n",
            b"confirm ask always\n",
            b"\n",
        ] {
            assert!(confirm(
                &pending(),
                &mut std::io::Cursor::new(line),
                &mut Vec::new(),
                &|| Ok(100)
            )
            .is_err());
        }
        assert!(matches!(
            confirm(
                &pending(),
                &mut std::io::Cursor::new(b"confirm ask 1\n"),
                &mut Vec::new(),
                &|| Ok(181)
            ),
            Err(ErrorCode::DeadlineExpired)
        ));
        let denied = confirm(
            &pending(),
            &mut std::io::Cursor::new(b"confirm ask 3\n"),
            &mut Vec::new(),
            &|| Ok(100),
        )
        .unwrap();
        let Action::Approve(args) = denied.request.action else {
            panic!("decision expected")
        };
        assert_eq!(
            (args.option_id, args.decision),
            ("@cancel".into(), Decision::Deny)
        );
    }
}
