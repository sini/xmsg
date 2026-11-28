use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::admission::Refusal;
use super::authority::{Grants, Record, State};
use super::command_store::{self as store, Intent, Reservation, State as Phase};
use super::command_wire::{CommandRequest, PreparedRequest, Target};
use super::Issuer;

pub(super) struct UnattestedSubmitter;
const _: () = assert!(std::mem::size_of::<UnattestedSubmitter>() == 0);

pub(super) struct Commands {
    local: UnattestedSubmitter,
    work: Arc<Mutex<HashMap<String, usize>>>,
    rate: Mutex<HashMap<String, (i64, usize)>>,
    #[cfg(test)]
    double: Option<Arc<CommandDouble>>,
    #[cfg(test)]
    tasks: Mutex<tokio::task::JoinSet<()>>,
    #[cfg(test)]
    fixture: Option<Arc<ExactCommandAuthorityFixture>>,
}

struct WorkSlot {
    work: Arc<Mutex<HashMap<String, usize>>>,
    record: String,
}

impl Drop for WorkSlot {
    fn drop(&mut self) {
        if let Ok(mut work) = self.work.lock() {
            if let Some(count) = work.get_mut(&self.record) {
                *count -= 1;
                if *count == 0 {
                    work.remove(&self.record);
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) struct CommandDouble {
    pub(crate) submitted: tokio::sync::Semaphore,
    pub(super) requests: Mutex<Vec<PreparedRequest>>,
    pub(crate) outcome: Mutex<Option<DoubleOutcome>>,
    pub(crate) release: tokio::sync::Notify,
}

#[cfg(test)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum DoubleOutcome {
    Admitted,
    Unattested,
    Lost,
    Unreachable,
}

#[cfg(test)]
impl Default for CommandDouble {
    fn default() -> Self {
        Self {
            submitted: tokio::sync::Semaphore::new(0),
            requests: Mutex::default(),
            outcome: Mutex::new(None),
            release: tokio::sync::Notify::new(),
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct ExactCommandAuthorityFixture {
    at: std::sync::atomic::AtomicI64,
    sequence: std::sync::atomic::AtomicU64,
    pub(super) abandon: std::sync::atomic::AtomicBool,
    pub(super) data_send_pause: DataSendPause,
    pub(super) permits: std::sync::atomic::AtomicUsize,
    pub(super) writes: Mutex<Vec<Phase>>,
    before_submit: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    handoff: Mutex<Option<Arc<CommandHandoffGate>>>,
    pub(super) grants: std::sync::Mutex<Vec<(String, String, String)>>,
    pub(super) bindings: std::sync::Mutex<Vec<Target>>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct CommandHandoffGate {
    pub(crate) entered: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
    pub(crate) drop_reply: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
pub(super) struct DataSendPause {
    pub(super) armed: std::sync::atomic::AtomicBool,
    pub(super) entered: tokio::sync::Semaphore,
    pub(super) release: tokio::sync::Semaphore,
}

#[cfg(test)]
impl Default for DataSendPause {
    fn default() -> Self {
        Self {
            armed: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[cfg(test)]
impl ExactCommandAuthorityFixture {
    pub(crate) fn arm_command_handoff(&self) -> Arc<CommandHandoffGate> {
        let gate = Arc::new(CommandHandoffGate::default());
        *self.handoff.lock().unwrap() = Some(gate.clone());
        gate
    }

    pub(crate) fn freeze_clock(&self, at: i64) {
        self.at.store(at, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn enable_deterministic_ids(&self) {
        self.sequence.store(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn grant(&self, principal: &str, target: Value) {
        let target: Target = serde_json::from_value(target).unwrap();
        self.grants.lock().unwrap().push((
            principal.to_owned(),
            target.node.clone(),
            target.endpoint.clone(),
        ));
        self.bindings.lock().unwrap().push(target);
    }

    pub(crate) fn clear_bindings(&self) {
        self.bindings.lock().unwrap().clear();
    }
}

impl Commands {
    pub(super) fn withheld() -> Self {
        Self {
            local: UnattestedSubmitter,
            work: Arc::default(),
            rate: Mutex::default(),
            #[cfg(test)]
            double: None,
            #[cfg(test)]
            tasks: Mutex::new(tokio::task::JoinSet::new()),
            #[cfg(test)]
            fixture: None,
        }
    }

    #[cfg(test)]
    pub(super) fn exact(fixture: Arc<ExactCommandAuthorityFixture>) -> Self {
        Self {
            fixture: Some(fixture),
            ..Self::withheld()
        }
    }

    #[cfg(test)]
    pub(super) fn with_double(
        fixture: Arc<ExactCommandAuthorityFixture>,
        double: Arc<CommandDouble>,
    ) -> Self {
        Self {
            double: Some(double),
            ..Self::exact(fixture)
        }
    }

    fn now(&self) -> i64 {
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            let at = fixture.at.load(std::sync::atomic::Ordering::SeqCst);
            if at != 0 {
                return at;
            }
        }
        now_ms()
    }

    fn random_id(&self) -> Result<[u8; 16], Refusal> {
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            use std::sync::atomic::Ordering;
            if fixture.sequence.load(Ordering::SeqCst) != 0 {
                return Ok(
                    u128::from(fixture.sequence.fetch_add(1, Ordering::SeqCst)).to_be_bytes()
                );
            }
        }
        super::random::<16>().map_err(|_| Refusal::UNAVAILABLE)
    }

    fn receipt_id(&self) -> Result<String, Refusal> {
        self.random_id()
            .map(|bytes| format!("r_{}", hex::encode(bytes)))
    }

    fn charge(&self, record: &Record, at: i64) -> Result<(), Refusal> {
        let Grants::Delegated { grant } = &record.grants else {
            return Ok(());
        };
        let mut budgets = self.rate.lock().map_err(|_| Refusal::UNAVAILABLE)?;
        budgets.retain(|_, (start, _)| at.saturating_sub(*start) < 60_000);
        let (_, count) = budgets.entry(record.record_id.clone()).or_insert((at, 0));
        if *count >= grant.rate as usize {
            return Err(Refusal::RATE_LIMIT);
        }
        *count += 1;
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn pause_data_send_for_test(&self) {
        use std::sync::atomic::Ordering;
        if let Some(fixture) = &self.fixture {
            if fixture.data_send_pause.armed.swap(false, Ordering::SeqCst) {
                fixture.data_send_pause.entered.add_permits(1);
                fixture
                    .data_send_pause
                    .release
                    .acquire()
                    .await
                    .unwrap()
                    .forget();
            }
        }
    }

    #[cfg(test)]
    fn record_phase(&self, phase: Phase) {
        if let Some(fixture) = &self.fixture {
            fixture.writes.lock().unwrap().push(phase);
        }
    }

    fn work_slot(&self, record: &str, config: &super::Config) -> Result<WorkSlot, Refusal> {
        let mut work = self.work.lock().map_err(|_| Refusal::UNAVAILABLE)?;
        if work.values().sum::<usize>() >= config.command_work_max_global
            || work.get(record).copied().unwrap_or_default() >= config.command_work_max_per_record
        {
            return Err(Refusal::UNAVAILABLE);
        }
        *work.entry(record.to_owned()).or_default() += 1;
        Ok(WorkSlot {
            work: self.work.clone(),
            record: record.to_owned(),
        })
    }

    pub(super) fn available(&self) -> bool {
        #[cfg(test)]
        {
            self.fixture.is_some()
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    #[cfg(test)]
    pub(super) async fn before_handoff(&self) -> bool {
        let gate = self
            .fixture
            .as_ref()
            .and_then(|fixture| fixture.handoff.lock().unwrap().take());
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
            gate.drop_reply.load(std::sync::atomic::Ordering::SeqCst)
        } else {
            false
        }
    }

    fn allows(&self, record: &Record, target: &Target) -> bool {
        #[cfg(test)]
        {
            self.fixture.as_ref().is_some_and(|fixture| {
                fixture.grants.lock().is_ok_and(|grants| {
                    grants.iter().any(|(principal, node, endpoint)| {
                        principal == &record.principal
                            && node == &target.node
                            && endpoint == &target.endpoint
                    })
                })
            })
        }
        #[cfg(not(test))]
        {
            let _ = (record, target);
            false
        }
    }

    fn binding(&self, target: &Target) -> Result<(), &'static str> {
        #[cfg(test)]
        {
            let fixture = self.fixture.as_ref().ok_or("denied")?;
            let bindings = fixture.bindings.lock().map_err(|_| "denied")?;
            let mut candidates = bindings.iter().filter(|binding| {
                binding.node == target.node && binding.endpoint == target.endpoint
            });
            let binding = candidates.next().ok_or("denied")?;
            if candidates.next().is_some()
                || binding.selector.session_id != target.selector.session_id
            {
                return Err("denied");
            }
            if binding != target {
                return Err("target_changed");
            }
            Ok(())
        }
        #[cfg(not(test))]
        {
            let _ = target;
            Err("denied")
        }
    }
}

impl UnattestedSubmitter {
    fn refusal(&self) -> &'static str {
        "unattested"
    }
}

pub(super) struct CommandLane {
    #[cfg_attr(not(test), allow(dead_code))]
    sender: tokio::sync::mpsc::Sender<Reply>,
    #[cfg_attr(not(test), allow(dead_code))]
    overloaded: Arc<tokio::sync::Notify>,
}

impl CommandLane {
    pub(super) fn new(
        sender: tokio::sync::mpsc::Sender<Reply>,
        overloaded: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self { sender, overloaded }
    }

    #[cfg(test)]
    pub(super) fn deliver(&self, reply: Reply) {
        if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = self.sender.try_send(reply) {
            self.overloaded.notify_one();
        }
    }
}

#[derive(Clone)]
pub(super) struct Reply {
    pub(super) body: Value,
    pub(super) request: Option<PreparedRequest>,
}

impl Reply {
    fn new(mut body: Value, id: Option<u32>, request: Option<PreparedRequest>) -> Self {
        body["v"] = json!(1);
        if let Some(id) = id {
            body["re"] = json!(id);
        }
        Self { body, request }
    }
}

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |now| now.as_millis().min(i64::MAX as u128) as i64)
}

fn store_error(_: rusqlite::Error) -> Refusal {
    Refusal::UNAVAILABLE
}

fn encode(request: &PreparedRequest) -> String {
    String::from_utf8(request.canonical_bytes()).expect("canonical JSON is UTF-8")
}

fn decode(json: &str) -> Result<PreparedRequest, Refusal> {
    serde_json::from_str(json).map_err(|_| Refusal::UNAVAILABLE)
}

fn refused(
    commands: &Commands,
    id: Option<u32>,
    request_id: &str,
    code: &str,
    at: i64,
    request: Option<PreparedRequest>,
) -> Result<Reply, Refusal> {
    Ok(Reply::new(
        json!({
            "type":"receipt", "request_id":request_id, "receipt_id":commands.receipt_id()?,
            "outcome":"refused", "code":code, "at":at
        }),
        id,
        request,
    ))
}

fn stored(id: Option<u32>, item: &Reservation, lookup: bool, request: PreparedRequest) -> Reply {
    let outcome = match item.state {
        Phase::Reserved | Phase::Submitting | Phase::EffectUnknown => "effect_unknown",
        Phase::Held => "held",
        Phase::Refused => "refused",
        Phase::Admitted => "admitted",
    };
    let mut body = json!({
        "type":"receipt", "request_id":item.request_id, "receipt_id":item.receipt_id,
        "outcome":outcome,"at":item.at
    });
    if let Some(code) = &item.code {
        body["code"] = json!(code);
    }
    if lookup {
        body["lookup"] = json!(true);
    }
    Reply::new(body, id, Some(request))
}

#[allow(dead_code, reason = "internal owner decision awaits management panel")]
#[derive(PartialEq, Eq)]
enum HeldDecision {
    Confirm,
    Decline,
}

impl Issuer {
    pub(super) fn command_entitled(
        &self,
        state: &State,
        record_id: &str,
        request: &PreparedRequest,
    ) -> Result<Record, Refusal> {
        let record = state.command_record(record_id)?;
        let target = &request.target;
        let in_grant = match &record.grants {
            Grants::Owner => true,
            Grants::Delegated { grant } => {
                grant.expires_at > crate::storage::now_epoch_secs()
                    && grant.verbs.iter().any(|verb| verb == "send")
                    && grant.targets.iter().any(|allowed| {
                        allowed.node == target.node && allowed.endpoint == target.endpoint
                    })
            }
            Grants::Machine { .. } => false,
        };
        if !in_grant || !self.commands.allows(&record, target) {
            return Err(Refusal::NOT_FOUND);
        }
        Ok(record)
    }

    pub(super) fn command(
        self: &Arc<Self>,
        record: &Record,
        carrier: &str,
        message: CommandRequest,
    ) -> Result<Reply, Refusal> {
        let (action, id, supplied) = match &message {
            CommandRequest::Prepare { request, .. } => (
                "command_prepare",
                request.request_id.clone(),
                Some(request.clone()),
            ),
            CommandRequest::Commit { request_id, .. } => {
                ("command_commit", request_id.clone(), None)
            }
            CommandRequest::Lookup { request_id, .. } => {
                ("command_lookup", request_id.clone(), None)
            }
        };
        let result = self.command_inner(record, carrier, message);
        let state = self.authority.locked()?;
        let target = result
            .as_ref()
            .ok()
            .and_then(|reply| reply.request.as_ref())
            .or(supplied.as_ref());
        let (actor, owner) = match &record.grants {
            Grants::Delegated { grant } => (grant.holder.as_str(), record.on_behalf_of.as_deref()),
            _ => (record.principal.as_str(), None),
        };
        let outcome = match &result {
            Ok(reply) => reply.body["outcome"].as_str().unwrap_or("prepared"),
            Err(refusal) if *refusal == Refusal::RATE_LIMIT => "rate_limited",
            Err(refusal) if *refusal == Refusal::UNAVAILABLE => "unavailable",
            Err(_) => "denied",
        };
        state.conn.execute(
            "INSERT INTO audit(at, action, principal, record_id, actor, on_behalf_of, node, endpoint, verb, request_id, outcome)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![self.commands.now() / 1_000, action, record.principal, record.record_id,
                actor, owner, target.map(|r| r.target.node.as_str()), target.map(|r| r.target.endpoint.as_str()),
                target.map(|_| "send"), id, outcome],
        ).map_err(store_error)?;
        result
    }

    fn command_inner(
        self: &Arc<Self>,
        record: &Record,
        carrier: &str,
        message: CommandRequest,
    ) -> Result<Reply, Refusal> {
        if !self.commands.available() {
            return Err(Refusal::UNAVAILABLE);
        }

        let state = self.authority.locked()?;
        let at = self.commands.now();
        match message {
            CommandRequest::Prepare { id, request } => {
                let record = self.command_entitled(&state, &record.record_id, &request)?;
                let digest = request.digest();
                if let Some(row) =
                    store::reservation(&state.conn, &record.principal, &request.request_id)
                        .map_err(store_error)?
                {
                    let incumbent = decode(&row.request_json)?;
                    self.command_entitled(&state, &record.record_id, &incumbent)?;
                    if row.digest == digest {
                        return Ok(stored(id, &row, true, incumbent));
                    }
                    return refused(
                        &self.commands,
                        id,
                        &request.request_id,
                        "conflict",
                        at,
                        Some(incumbent),
                    );
                }
                let requested = request.requested_at as i64;
                if requested < at.saturating_sub(self.config.request_max_age_secs as i64 * 1000)
                    || requested > at.saturating_add(self.config.clock_skew_secs as i64 * 1000)
                {
                    return refused(
                        &self.commands,
                        id,
                        &request.request_id,
                        "expired_request",
                        at,
                        Some(request.clone()),
                    );
                }
                if let Err(code) = self.commands.binding(&request.target) {
                    return if code == "target_changed" {
                        refused(
                            &self.commands,
                            id,
                            &request.request_id,
                            code,
                            at,
                            Some(request.clone()),
                        )
                    } else {
                        Err(Refusal::NOT_FOUND)
                    };
                }
                if store::count_unused_intents(&state.conn, None).map_err(store_error)?
                    >= self.config.command_intents_max_global
                    || store::count_unused_intents(&state.conn, Some(&record.record_id))
                        .map_err(store_error)?
                        >= self.config.command_intents_max_per_record
                {
                    return Err(Refusal::UNAVAILABLE);
                }
                self.commands.charge(&record, at)?;
                let raw = self.commands.random_id()?;
                use base64::Engine;
                let intent = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
                let expires_at = at.saturating_add(self.config.intent_ttl_ms as i64);
                store::insert_intent(
                    &state.conn,
                    &Intent {
                        hash: Sha256::digest(intent.as_bytes()).into(),
                        principal: record.principal,
                        record_id: record.record_id,
                        transport: carrier.to_owned(),
                        request_id: request.request_id.clone(),
                        request_json: encode(&request),
                        digest: digest.clone(),
                        expires_at,
                        consumed: false,
                    },
                )
                .map_err(store_error)?;
                let target = &request.target;
                Ok(Reply::new(
                    json!({
                        "type":"prepared", "request_id":request.request_id,
                        "intent":intent,"expires_at":expires_at,"digest":digest,
                        "presentation":{
                            "verb":"send","node":target.node,"endpoint":target.endpoint,
                            "incarnation":target.incarnation,"state_epoch":target.state_epoch,
                            "selector":target.selector,"params":[{"name":"text","value":request.params.text}]
                        }
                    }),
                    id,
                    Some(request),
                ))
            }
            CommandRequest::Lookup { id, request_id } => {
                state.command_record(&record.record_id)?;
                let row = store::reservation(&state.conn, &record.principal, &request_id)
                    .map_err(store_error)?
                    .ok_or(Refusal::NOT_FOUND)?;
                let request = decode(&row.request_json)?;
                self.command_entitled(&state, &record.record_id, &request)?;
                Ok(stored(id, &row, true, request))
            }
            CommandRequest::Commit {
                id,
                request_id,
                intent,
                digest,
            } => self.command_commit(
                state,
                record,
                carrier,
                id,
                &request_id,
                &intent,
                &digest,
                at,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn command_commit(
        self: &Arc<Self>,
        mut state: std::sync::MutexGuard<'_, State>,
        record: &Record,
        carrier: &str,
        id: Option<u32>,
        request_id: &str,
        intent: &str,
        digest: &str,
        at: i64,
    ) -> Result<Reply, Refusal> {
        let hash: [u8; 32] = Sha256::digest(intent.as_bytes()).into();
        let Some(binding) = store::intent(&state.conn, &hash)
            .map_err(store_error)?
            .filter(|row| {
                row.principal == record.principal
                    && row.record_id == record.record_id
                    && row.transport == carrier
                    && row.request_id == request_id
                    && row.digest == digest
                    && (row.consumed || row.expires_at > at)
            })
        else {
            return refused(&self.commands, id, request_id, "intent_invalid", at, None);
        };
        let request = decode(&binding.request_json)?;
        let current = self.command_entitled(&state, &record.record_id, &request)?;
        let incumbent =
            store::reservation(&state.conn, &record.principal, request_id).map_err(store_error)?;
        if let Some(row) = incumbent {
            let frozen = decode(&row.request_json)?;
            self.command_entitled(&state, &record.record_id, &frozen)?;
            if !binding.consumed {
                let tx = state.conn.transaction().map_err(store_error)?;
                store::consume_intent(&tx, &hash).map_err(store_error)?;
                tx.commit().map_err(store_error)?;
            }
            return if row.digest == digest {
                Ok(stored(id, &row, true, frozen))
            } else {
                refused(&self.commands, id, request_id, "conflict", at, Some(frozen))
            };
        }
        if binding.consumed {
            return refused(&self.commands, id, request_id, "intent_invalid", at, None);
        }
        if store::count_reserved(&state.conn, None).map_err(store_error)?
            >= self.config.command_reserved_max_global
            || store::count_reserved(&state.conn, Some(&record.record_id)).map_err(store_error)?
                >= self.config.command_reserved_max_per_record
        {
            return Err(Refusal::UNAVAILABLE);
        }
        let pending_hold = matches!(&current.grants, Grants::Delegated { grant }
            if grant.confirm_verbs.iter().any(|verb| verb == "send"));
        if pending_hold
            && (store::count_holds(&state.conn, None).map_err(store_error)?
                >= self.config.command_holds_max_global
                || store::count_holds(&state.conn, Some(&record.record_id)).map_err(store_error)?
                    >= self.config.command_holds_max_per_record)
        {
            return Err(Refusal::UNAVAILABLE);
        }
        let slot = self.commands.work_slot(&record.record_id, &self.config)?;
        let row = Reservation {
            principal: record.principal.clone(),
            record_id: record.record_id.clone(),
            request_id: request_id.to_owned(),
            request_json: binding.request_json,
            digest: binding.digest,
            receipt_id: self.commands.receipt_id()?,
            requested_at: request.requested_at as i64,
            state: Phase::Reserved,
            code: None,
            at,
            held_at: None,
            pending_hold,
        };
        {
            let tx = state.conn.transaction().map_err(store_error)?;
            if !store::insert_reservation(&tx, &row).map_err(store_error)?
                || !store::consume_intent(&tx, &hash).map_err(store_error)?
            {
                return Err(Refusal::UNAVAILABLE);
            }
            tx.commit().map_err(store_error)?;
        }

        #[cfg(test)]
        {
            self.commands.record_phase(Phase::Reserved);
            if let Some(fixture) = &self.commands.fixture {
                use std::sync::atomic::Ordering;
                fixture.permits.fetch_add(1, Ordering::SeqCst);
                if fixture.abandon.load(Ordering::SeqCst) {
                    return Ok(stored(id, &row, false, request));
                }
            }
        }
        drop(state);
        #[cfg(test)]
        if let Some((entered, release)) = self
            .commands
            .fixture
            .as_ref()
            .and_then(|fixture| fixture.before_submit.lock().unwrap().take())
        {
            entered.wait();
            release.wait();
        }
        let state = self.authority.locked()?;
        let checked = self
            .command_entitled(&state, &record.record_id, &request)
            .map_err(|_| "denied")
            .and_then(|_| self.commands.binding(&request.target));
        let (to, code) = match checked {
            Err(code) => (Phase::Refused, Some(code)),
            Ok(()) if pending_hold => (Phase::Held, None),
            #[cfg(test)]
            Ok(()) if self.commands.double.is_some() => (Phase::Submitting, None),
            Ok(()) => (Phase::Refused, Some(self.commands.local.refusal())),
        };
        Self::move_reserved(&state, &row, to, code, at)?;
        #[cfg(test)]
        self.commands.record_phase(to);
        let row = store::reservation(&state.conn, &record.principal, request_id)
            .map_err(store_error)?
            .ok_or(Refusal::UNAVAILABLE)?;
        #[cfg(test)]
        if to == Phase::Submitting {
            self.spawn_command_double(row.clone(), request.clone(), slot);
            return Ok(stored(id, &row, false, request));
        }
        drop(slot);
        Ok(stored(id, &row, false, request))
    }

    fn move_reserved(
        state: &State,
        row: &Reservation,
        to: Phase,
        code: Option<&str>,
        at: i64,
    ) -> Result<(), Refusal> {
        if !store::transition(
            &state.conn,
            &row.principal,
            &row.request_id,
            store::Transition {
                from: Phase::Reserved,
                to,
                code,
                now: at,
                held_at: (to == Phase::Held).then_some(at),
            },
        )
        .map_err(store_error)?
        {
            return Err(Refusal::UNAVAILABLE);
        }
        Ok(())
    }

    pub(super) fn sweep_command_holds(
        self: &Arc<Self>,
        cursor: &mut i64,
        at: i64,
    ) -> Result<(), Refusal> {
        let candidates = {
            let state = self.authority.locked()?;
            store::held_candidates(&state.conn, *cursor).map_err(store_error)?
        };
        *cursor = if candidates.len() < 256 {
            0
        } else {
            candidates.last().unwrap().0
        };
        for (_, row) in candidates {
            self.expire_hold(&row, at)?;
        }
        Ok(())
    }

    fn expire_hold(&self, candidate: &Reservation, at: i64) -> Result<(), Refusal> {
        let state = self.authority.locked()?;
        let deadline = candidate
            .held_at
            .ok_or(Refusal::UNAVAILABLE)?
            .saturating_add(self.config.confirm_ttl_secs as i64 * 1_000);
        if at < deadline {
            return Ok(());
        }
        let changed = store::transition(
            &state.conn,
            &candidate.principal,
            &candidate.request_id,
            store::Transition {
                from: Phase::Held,
                to: Phase::Refused,
                code: Some("confirmation_expired"),
                now: at,
                held_at: None,
            },
        )
        .map_err(store_error)?;
        #[cfg(test)]
        if changed {
            self.commands.record_phase(Phase::Refused);
            let request = decode(&candidate.request_json)?;
            if let Some(row) =
                store::reservation(&state.conn, &candidate.principal, &candidate.request_id)
                    .map_err(store_error)?
            {
                state.publish_command(&row.record_id, stored(None, &row, false, request));
            }
        }
        #[cfg(not(test))]
        let _ = changed;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn decide_command_for_test(
        self: &Arc<Self>,
        principal: &str,
        request_id: &str,
        confirm: bool,
    ) -> Result<(), Refusal> {
        self.settle_hold(
            principal,
            request_id,
            if confirm {
                HeldDecision::Confirm
            } else {
                HeldDecision::Decline
            },
        )
    }

    #[allow(dead_code, reason = "internal owner decision awaits management panel")]
    fn settle_hold(
        self: &Arc<Self>,
        principal: &str,
        request_id: &str,
        decision: HeldDecision,
    ) -> Result<(), Refusal> {
        let state = self.authority.locked()?;
        let at = self.commands.now();
        let Some(row) = store::reservation(&state.conn, principal, request_id)
            .map_err(store_error)?
            .filter(|row| row.state == Phase::Held)
        else {
            return Ok(());
        };
        let deadline = row
            .held_at
            .ok_or(Refusal::UNAVAILABLE)?
            .saturating_add(self.config.confirm_ttl_secs as i64 * 1_000);
        let request = decode(&row.request_json)?;
        let mut slot = None;
        let (to, code) = if at >= deadline {
            (Phase::Refused, Some("confirmation_expired"))
        } else {
            let checked = self
                .command_entitled(&state, &row.record_id, &request)
                .map_err(|_| "denied")
                .and_then(|_| self.commands.binding(&request.target));
            match checked {
                Err(code) => (Phase::Refused, Some(code)),
                Ok(()) if decision == HeldDecision::Decline => (Phase::Refused, Some("declined")),
                Ok(()) => {
                    slot = Some(self.commands.work_slot(&row.record_id, &self.config)?);
                    #[cfg(test)]
                    if self.commands.double.is_some() {
                        (Phase::Submitting, None)
                    } else {
                        (Phase::Refused, Some(self.commands.local.refusal()))
                    }
                    #[cfg(not(test))]
                    (Phase::Refused, Some(self.commands.local.refusal()))
                }
            }
        };
        if store::transition(
            &state.conn,
            principal,
            request_id,
            store::Transition {
                from: Phase::Held,
                to,
                code,
                now: at,
                held_at: None,
            },
        )
        .map_err(store_error)?
        {
            #[cfg(test)]
            {
                self.commands.record_phase(to);
                if let Some(settled) =
                    store::reservation(&state.conn, principal, request_id).map_err(store_error)?
                {
                    if to == Phase::Submitting {
                        self.spawn_command_double(
                            settled,
                            request,
                            slot.take().expect("submit owns a slot"),
                        );
                    } else {
                        state.publish_command(
                            &row.record_id,
                            stored(None, &settled, false, request),
                        );
                    }
                }
            }
        }
        drop(slot);
        Ok(())
    }

    #[cfg(test)]
    fn spawn_command_double(
        self: &Arc<Self>,
        row: Reservation,
        request: PreparedRequest,
        slot: WorkSlot,
    ) {
        let double = self
            .commands
            .double
            .as_ref()
            .expect("submitting requires a test double")
            .clone();
        let issuer = Arc::downgrade(self);
        let mut tasks = self.commands.tasks.lock().unwrap();
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let _slot = slot;
            double.requests.lock().unwrap().push(request.clone());
            double.submitted.add_permits(1);
            let outcome = loop {
                let wake = double.release.notified();
                if let Some(outcome) = *double.outcome.lock().unwrap() {
                    break outcome;
                }
                wake.await;
            };
            let (to, code) = match outcome {
                DoubleOutcome::Admitted => (Phase::Admitted, None),
                DoubleOutcome::Unattested => (Phase::Refused, Some("unattested")),
                DoubleOutcome::Lost => (Phase::EffectUnknown, None),
                DoubleOutcome::Unreachable => (Phase::Refused, Some("executor_unreachable")),
            };
            let Some(issuer) = issuer.upgrade() else {
                return;
            };
            let Ok(state) = issuer.authority.locked() else {
                return;
            };
            let result = store::transition(
                &state.conn,
                &row.principal,
                &row.request_id,
                store::Transition {
                    from: Phase::Submitting,
                    to,
                    code,
                    now: issuer.commands.now(),
                    held_at: None,
                },
            );
            if matches!(result, Ok(true)) {
                issuer.commands.record_phase(to);
                if let Ok(Some(settled)) =
                    store::reservation(&state.conn, &row.principal, &row.request_id)
                {
                    state.publish_command(&row.record_id, stored(None, &settled, false, request));
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll_oidc::signed_fixture::Fixture;
    use std::sync::atomic::Ordering;

    fn target() -> Value {
        json!({
            "node":"fixture.node","endpoint":"claude-1@fixture.node",
            "state_epoch":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","incarnation":3,
            "selector":{"kind":"execution","session_id":"exec-alpha","generation":7}
        })
    }

    fn request(id: u128, at: i64, text: &str) -> PreparedRequest {
        serde_json::from_value(json!({
            "request_id":format!("{id:032x}"),"requested_at":at,
            "verb":"send","target":target(),"params":{"text":text}
        }))
        .unwrap()
    }

    fn prepare(
        issuer: &Arc<Issuer>,
        record: &Record,
        carrier: &str,
        request: PreparedRequest,
    ) -> Result<Reply, Refusal> {
        issuer.command(
            record,
            carrier,
            CommandRequest::Prepare { id: None, request },
        )
    }

    fn commit(
        issuer: &Arc<Issuer>,
        record: &Record,
        carrier: &str,
        prepared: &Reply,
    ) -> Result<Reply, Refusal> {
        issuer.command(
            record,
            carrier,
            CommandRequest::Commit {
                id: None,
                request_id: prepared.body["request_id"].as_str().unwrap().into(),
                intent: prepared.body["intent"].as_str().unwrap().into(),
                digest: prepared.body["digest"].as_str().unwrap().into(),
            },
        )
    }

    fn lookup(
        issuer: &Arc<Issuer>,
        record: &Record,
        carrier: &str,
        id: &str,
    ) -> Result<Reply, Refusal> {
        issuer.command(
            record,
            carrier,
            CommandRequest::Lookup {
                id: None,
                request_id: id.into(),
            },
        )
    }

    #[tokio::test]
    async fn sc2_sc4_one_submit_owner_for_same_and_independent_intents() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        let dir = tempfile::tempdir().unwrap();
        let (issuer, fixture, double) =
            super::super::tests::command_double_transport_fixture(&oidc, &dir).await;
        let (_, native, _) = super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
        fixture.grant(&native.record.principal, target());
        let at = now_ms();
        fixture.freeze_clock(at);
        for (case, separate, differs) in [(1, false, false), (2, true, false), (3, true, true)] {
            let a = prepare(&issuer, &native.record, "ws", request(case, at, "first")).unwrap();
            let b = if separate {
                prepare(
                    &issuer,
                    &native.record,
                    "ws",
                    request(case, at, if differs { "second" } else { "first" }),
                )
                .unwrap()
            } else {
                a.clone()
            };
            let gate = Arc::new(std::sync::Barrier::new(2));
            let race = |prepared| {
                let gate = gate.clone();
                let issuer = issuer.clone();
                let record = native.record.clone();
                tokio::task::spawn_blocking(move || {
                    let _ = tokio::runtime::Handle::current();
                    gate.wait();
                    commit(&issuer, &record, "ws", &prepared).unwrap()
                })
            };
            let first = race(a.clone());
            let second = race(b);
            let (first, second) = tokio::join!(first, second);
            let replies = [first.unwrap(), second.unwrap()];
            let winner = replies
                .iter()
                .find(|reply| reply.body["lookup"].is_null() && reply.body["code"].is_null())
                .unwrap();
            assert_eq!(winner.body["outcome"], "effect_unknown");
            if differs {
                assert!(replies.iter().any(|reply| reply.body["code"] == "conflict"));
            } else {
                let loser = replies
                    .iter()
                    .find(|reply| reply.body["lookup"] == true)
                    .expect("matching race loser did not receive the incumbent receipt");
                assert_eq!(loser.body["receipt_id"], winner.body["receipt_id"]);
            }
            double.submitted.acquire().await.unwrap().forget();
            assert_eq!(double.submitted.available_permits(), 0);
            assert_eq!(fixture.permits.load(Ordering::SeqCst), case as usize);
            if !differs {
                fixture.freeze_clock(at + issuer.config.intent_ttl_ms as i64 + 1);
                let writes = fixture.writes.lock().unwrap().len();
                let replay = commit(&issuer, &native.record, "ws", &a).unwrap();
                assert_eq!(replay.body["receipt_id"], winner.body["receipt_id"]);
                assert_eq!(replay.body["lookup"], true);
                assert_eq!(fixture.writes.lock().unwrap().len(), writes);
                fixture.freeze_clock(at);
            }
        }
        assert_eq!(fixture.permits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn sc12_held_confirm_and_decline_each_settle_once() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        let dir = tempfile::tempdir().unwrap();
        let (issuer, fixture, double) =
            super::super::tests::command_double_transport_fixture(&oidc, &dir).await;
        let (_, _, delegated) =
            super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
        issuer.authority.allow_synthetic_for_test(&delegated.handle);
        issuer
            .authority
            .edit_fixture_record(&delegated.record.record_id, |record| {
                if let Grants::Delegated { grant } = &mut record.grants {
                    grant.rate = 60;
                    grant.verbs = vec!["send".to_owned()];
                    grant.confirm_verbs = vec!["send".to_owned()];
                    grant.targets = vec![super::super::authority::Target {
                        node: "fixture.node".to_owned(),
                        endpoint: "claude-1@fixture.node".to_owned(),
                    }];
                }
            });
        fixture.grant(&delegated.record.principal, target());
        let at = now_ms();
        fixture.freeze_clock(at);
        for (case, confirm) in [(10, false), (11, true)] {
            let frozen = request(case, at, "hold");
            let id = frozen.request_id.clone();
            let prepared = prepare(&issuer, &delegated.record, "http", frozen).unwrap();
            let held = commit(&issuer, &delegated.record, "http", &prepared).unwrap();
            assert_eq!(held.body["outcome"], "held");
            assert_eq!(double.submitted.available_permits(), 0);
            issuer
                .decide_command_for_test(&delegated.record.principal, &id, confirm)
                .unwrap();
            issuer
                .decide_command_for_test(&delegated.record.principal, &id, !confirm)
                .unwrap();
            if confirm {
                double.submitted.acquire().await.unwrap().forget();
                assert_eq!(
                    lookup(&issuer, &delegated.record, "http", &id)
                        .unwrap()
                        .body["outcome"],
                    "effect_unknown"
                );
            } else {
                assert_eq!(
                    lookup(&issuer, &delegated.record, "http", &id)
                        .unwrap()
                        .body["code"],
                    "declined"
                );
            }
        }

        let next = |case, label| {
            let frozen = request(case, at, label);
            let id = frozen.request_id.clone();
            let prepared = prepare(&issuer, &delegated.record, "http", frozen).unwrap();
            assert_eq!(
                commit(&issuer, &delegated.record, "http", &prepared)
                    .unwrap()
                    .body["outcome"],
                "held"
            );
            id
        };
        let unswept = next(12, "unswept");
        let sweeping = next(13, "sweep-race");
        let stale = {
            let state = issuer.authority.locked().unwrap();
            store::held_candidates(&state.conn, 0)
                .unwrap()
                .into_iter()
                .find(|(_, row)| row.request_id == sweeping)
                .unwrap()
                .1
        };
        issuer
            .decide_command_for_test(&delegated.record.principal, &sweeping, true)
            .unwrap();
        double.submitted.acquire().await.unwrap().forget();

        let after = at + issuer.config.confirm_ttl_secs as i64 * 1_000;
        fixture.freeze_clock(after);
        issuer.expire_hold(&stale, after).unwrap();
        assert_eq!(
            lookup(&issuer, &delegated.record, "http", &sweeping)
                .unwrap()
                .body["outcome"],
            "effect_unknown",
            "stale expiry sweep overwrote a submitting reservation"
        );
        issuer
            .decide_command_for_test(&delegated.record.principal, &unswept, true)
            .unwrap();
        assert_eq!(
            lookup(&issuer, &delegated.record, "http", &unswept)
                .unwrap()
                .body["code"],
            "confirmation_expired",
            "expired unswept reservation accepted confirmation"
        );
        assert_eq!(double.submitted.available_permits(), 0);

        fixture.freeze_clock(at);
        let changed = next(14, "changed");
        let mut changed_target = target();
        changed_target["incarnation"] = json!(4);
        fixture.clear_bindings();
        fixture.grant(&delegated.record.principal, changed_target);
        issuer
            .decide_command_for_test(&delegated.record.principal, &changed, true)
            .unwrap();
        assert_eq!(
            lookup(&issuer, &delegated.record, "http", &changed)
                .unwrap()
                .body["code"],
            "target_changed",
            "changed target lost the target_changed refusal"
        );
        assert_eq!(double.submitted.available_permits(), 0);

        let mut pending_request = request(15, at, "revocation-first");
        pending_request.target.incarnation = 4;
        let pending_id = pending_request.request_id.clone();
        let pending = prepare(&issuer, &delegated.record, "http", pending_request).unwrap();
        assert_eq!(
            commit(&issuer, &delegated.record, "http", &pending)
                .unwrap()
                .body["outcome"],
            "held"
        );
        issuer
            .authority
            .revoke(&delegated.record.record_id)
            .unwrap();
        issuer
            .decide_command_for_test(&delegated.record.principal, &pending_id, true)
            .unwrap();
        {
            let state = issuer.authority.locked().unwrap();
            let row = store::reservation(&state.conn, &delegated.record.principal, &pending_id)
                .unwrap()
                .unwrap();
            assert_eq!(row.code.as_deref(), Some("denied"));
        }
        assert_eq!(
            double.submitted.available_permits(),
            0,
            "revocation-first hold submitted"
        );
        *double.outcome.lock().unwrap() = Some(DoubleOutcome::Admitted);
        double.release.notify_waiters();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                {
                    let state = issuer.authority.locked().unwrap();
                    let row =
                        store::reservation(&state.conn, &delegated.record.principal, &sweeping)
                            .unwrap()
                            .unwrap();
                    if row.state != Phase::Submitting {
                        assert_eq!(
                            row.state,
                            Phase::Admitted,
                            "post-confirm revocation rewrote the executor disposition"
                        );
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sc14_abandoned_reservations_stay_charged_until_recovery() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        let dir = tempfile::tempdir().unwrap();
        let (issuer, fixture, double) =
            super::super::tests::command_double_transport_fixture(&oidc, &dir).await;
        let (_, native, _) = super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
        fixture.grant(&native.record.principal, target());
        fixture.abandon.store(true, Ordering::SeqCst);
        let at = now_ms();
        let maximum = issuer.config.command_reserved_max_per_record as u128;
        let mut earlier = Vec::new();
        for case in 1..=maximum {
            let frozen = request(case, at, "abandon");
            let id = frozen.request_id.clone();
            let prepared = prepare(&issuer, &native.record, "http", frozen).unwrap();
            let answer = commit(&issuer, &native.record, "http", &prepared).unwrap();
            assert_eq!(answer.body["outcome"], "effect_unknown");
            earlier.push((id, answer.body["receipt_id"].clone()));
        }
        let excess = prepare(
            &issuer,
            &native.record,
            "http",
            request(maximum + 1, at, "excess"),
        )
        .unwrap();
        assert_eq!(
            commit(&issuer, &native.record, "http", &excess).err(),
            Some(Refusal::UNAVAILABLE)
        );
        assert_eq!(fixture.permits.load(Ordering::SeqCst), maximum as usize);
        for (id, receipt) in &earlier {
            let answer = lookup(&issuer, &native.record, "http", id).unwrap();
            assert_eq!(&answer.body["receipt_id"], receipt);
            assert_eq!(answer.body["outcome"], "effect_unknown");
        }
        issuer.recover_commands().unwrap();
        issuer.recover_commands().unwrap();
        assert_eq!(double.submitted.available_permits(), 0);
        for (id, receipt) in earlier {
            let answer = lookup(&issuer, &native.record, "http", &id).unwrap();
            assert_eq!(answer.body["receipt_id"], receipt);
            assert_eq!(answer.body["code"], "interrupted");
        }
        assert_eq!(
            commit(&issuer, &native.record, "http", &excess)
                .unwrap()
                .body["outcome"],
            "effect_unknown"
        );
    }

    #[tokio::test]
    async fn sc1_revocation_is_ordered_by_the_submit_cas() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        for revoke_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let (issuer, fixture, double) =
                super::super::tests::command_double_transport_fixture(&oidc, &dir).await;
            let (_, native, _) =
                super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
            fixture.grant(&native.record.principal, target());
            let frozen = request(1, now_ms(), "ordered");
            let id = frozen.request_id.clone();
            let prepared = prepare(&issuer, &native.record, "http", frozen).unwrap();
            if revoke_first {
                let entered = Arc::new(std::sync::Barrier::new(2));
                let release = Arc::new(std::sync::Barrier::new(2));
                *fixture.before_submit.lock().unwrap() = Some((entered.clone(), release.clone()));
                let owner = issuer.clone();
                let record = native.record.clone();
                let task =
                    tokio::task::spawn_blocking(move || commit(&owner, &record, "http", &prepared));
                let revoke = issuer.clone();
                let record_id = native.record.record_id.clone();
                tokio::task::spawn_blocking(move || {
                    entered.wait();
                    revoke.authority.revoke(&record_id).unwrap();
                    release.wait();
                })
                .await
                .unwrap();
                assert_eq!(task.await.unwrap().unwrap().body["code"], "denied");
                assert_eq!(
                    double.submitted.available_permits(),
                    0,
                    "revoked before CAS reached executor"
                );
                assert_eq!(
                    *fixture.writes.lock().unwrap(),
                    [Phase::Reserved, Phase::Refused]
                );
            } else {
                commit(&issuer, &native.record, "http", &prepared).unwrap();
                double.submitted.acquire().await.unwrap().forget();
                issuer.authority.revoke(&native.record.record_id).unwrap();
                *double.outcome.lock().unwrap() = Some(DoubleOutcome::Admitted);
                double.release.notify_waiters();
                tokio::time::timeout(std::time::Duration::from_secs(3), async {
                    loop {
                        if fixture.writes.lock().unwrap().last() == Some(&Phase::Admitted) {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("post-CAS revocation rewrote the outcome");
            }
            assert_eq!(
                lookup(&issuer, &native.record, "http", &id).err(),
                Some(Refusal::UNAUTHENTICATED),
            );
        }
    }

    #[tokio::test]
    async fn sc15_unchanged_retry_uses_reservation_before_age_and_expires_after_compaction() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        let dir = tempfile::tempdir().unwrap();
        let (issuer, fixture) =
            super::super::tests::exact_command_transport_fixture(&oidc, &dir).await;
        let (_, native, _) = super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
        fixture.grant(&native.record.principal, target());
        let at = now_ms();
        fixture.freeze_clock(at);
        let command = request(2, at, "historical");
        let prepared = prepare(&issuer, &native.record, "http", command.clone()).unwrap();
        let receipt = commit(&issuer, &native.record, "http", &prepared).unwrap();
        for advance in [121_000, 172_800_000] {
            fixture.freeze_clock(at + advance);
            {
                let state = issuer.authority.locked().unwrap();
                let cutoff = (at + advance)
                    .saturating_sub(issuer.config.receipt_retention_secs as i64 * 1_000);
                store::compact(&state.conn, cutoff, at + advance).unwrap();
            }
            let restored = prepare(&issuer, &native.record, "http", command.clone()).unwrap();
            assert_eq!(
                restored.body["receipt_id"], receipt.body["receipt_id"],
                "reservation was not checked before request age"
            );
            assert_eq!(restored.body["lookup"], true);
            assert_eq!(
                commit(&issuer, &native.record, "http", &prepared)
                    .unwrap()
                    .body["receipt_id"],
                receipt.body["receipt_id"],
                "consumed binding disappeared during receipt retention"
            );
        }
        let after = at + issuer.config.receipt_retention_secs as i64 * 1000 + 1;
        fixture.freeze_clock(after);
        {
            let state = issuer.authority.locked().unwrap();
            store::compact(&state.conn, at + 1, after).unwrap();
        }
        assert_eq!(
            prepare(&issuer, &native.record, "http", command)
                .unwrap()
                .body["code"],
            "expired_request"
        );
        assert_eq!(
            commit(&issuer, &native.record, "http", &prepared)
                .unwrap()
                .body["code"],
            "intent_invalid"
        );
        let fresh = prepare(
            &issuer,
            &native.record,
            "http",
            request(2, after, "historical"),
        )
        .unwrap();
        assert_eq!(fresh.body["type"], "prepared");
        assert_ne!(
            commit(&issuer, &native.record, "http", &fresh)
                .unwrap()
                .body["receipt_id"],
            receipt.body["receipt_id"]
        );
    }

    #[tokio::test]
    async fn sc2_in_flight_owner_recovers_after_intent_deadline() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        let dir = tempfile::tempdir().unwrap();
        let (issuer, fixture, double) =
            super::super::tests::command_double_transport_fixture(&oidc, &dir).await;
        let (_, native, _) = super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
        fixture.grant(&native.record.principal, target());
        let at = now_ms();
        fixture.freeze_clock(at);
        let prepared =
            prepare(&issuer, &native.record, "http", request(1, at, "in flight")).unwrap();
        let initial = commit(&issuer, &native.record, "http", &prepared).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            double.submitted.acquire(),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        fixture.freeze_clock(at + issuer.config.intent_ttl_ms as i64 + 1);
        let replay = commit(&issuer, &native.record, "http", &prepared).unwrap();
        assert_eq!(
            replay.body["receipt_id"], initial.body["receipt_id"],
            "in-flight owner lost receipt after intent TTL"
        );
        assert_eq!(replay.body["lookup"], true);
        assert_eq!(replay.body["outcome"], "effect_unknown");
        assert_eq!(fixture.permits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sc3_each_generation_component_fences_a_prepared_intent() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        for transport in ["http", "ws-fixture"] {
            let dir = tempfile::tempdir().unwrap();
            let (issuer, fixture) =
                super::super::tests::exact_command_transport_fixture(&oidc, &dir).await;
            let (_, native, _) =
                super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
            for change in 0..3 {
                fixture.clear_bindings();
                fixture.grant(&native.record.principal, target());
                let frozen = request(50 + change, now_ms(), "generation");
                let prepared = prepare(&issuer, &native.record, transport, frozen).unwrap();
                let mut updated = target();
                match change {
                    0 => updated["incarnation"] = json!(4),
                    1 => updated["state_epoch"] = json!("1a1b2c3d4e5f60718293a4b5c6d7e8f9"),
                    _ => updated["selector"]["generation"] = json!(8),
                }
                fixture.clear_bindings();
                fixture.grant(&native.record.principal, updated);
                let answer = commit(&issuer, &native.record, transport, &prepared).unwrap();
                assert_eq!(
                    answer.body["code"], "target_changed",
                    "generation check was lost before submit"
                );
                assert_eq!(fixture.writes.lock().unwrap().last(), Some(&Phase::Refused));
            }
        }
    }

    #[tokio::test]
    async fn sc4_changed_prepare_conflicts_with_an_existing_reservation() {
        let oidc = Fixture::new_at(crate::storage::now_epoch_secs()).await;
        let dir = tempfile::tempdir().unwrap();
        let (issuer, fixture) =
            super::super::tests::exact_command_transport_fixture(&oidc, &dir).await;
        let (_, native, delegated) =
            super::super::tests::transport_owner_records(&issuer, &oidc.issuer());
        fixture.grant(&native.record.principal, target());
        let at = now_ms();
        for (id, carrier) in [(1, "http"), (2, "ws-fixture")] {
            let original = request(id, at, "original");
            let prepared = prepare(&issuer, &native.record, carrier, original.clone()).unwrap();
            let initial = commit(&issuer, &native.record, carrier, &prepared).unwrap();
            let conflict =
                prepare(&issuer, &native.record, carrier, request(id, at, "changed")).unwrap();
            assert_eq!(
                conflict.body["code"], "conflict",
                "changed prepare disclosed the incumbent receipt"
            );
            assert!(conflict.body.get("intent").is_none());
            assert_ne!(conflict.body["receipt_id"], initial.body["receipt_id"]);
            let recovered = prepare(&issuer, &native.record, carrier, original).unwrap();
            assert_eq!(recovered.body["receipt_id"], initial.body["receipt_id"]);
        }
        issuer.authority.allow_synthetic_for_test(&delegated.handle);
        issuer
            .authority
            .edit_fixture_record(&delegated.record.record_id, |record| {
                if let Grants::Delegated { grant } = &mut record.grants {
                    grant.targets = vec![super::super::authority::Target {
                        node: "fixture.node".to_owned(),
                        endpoint: "claude-1@fixture.node".to_owned(),
                    }];
                }
            });
        fixture.grants.lock().unwrap().push((
            delegated.record.principal.clone(),
            "fixture.node".to_owned(),
            "claude-1@fixture.node".to_owned(),
        ));
        let other = prepare(
            &issuer,
            &delegated.record,
            "http",
            request(1, at, "original"),
        )
        .unwrap();
        let own = lookup(&issuer, &native.record, "http", &format!("{:032x}", 1)).unwrap();
        let other = commit(&issuer, &delegated.record, "http", &other)
            .unwrap_or_else(|_| panic!("request ID collision incorrectly crossed principals"));
        assert_ne!(
            own.body["receipt_id"], other.body["receipt_id"],
            "request ID collision incorrectly crossed principals"
        );
        assert_eq!(fixture.permits.load(Ordering::SeqCst), 3);
    }
}
