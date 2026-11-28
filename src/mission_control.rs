pub mod admin;
#[allow(dead_code, reason = "Mission Control transport integration")]
mod admission;
mod assets;
#[allow(
    dead_code,
    reason = "Mission Control read-only hub staged before transport integration"
)]
mod attention;
pub mod authority;
mod budgets;
pub(crate) mod command;
pub(crate) mod command_http;
mod command_store;
#[cfg(test)]
mod command_transport_tests;
#[cfg(test)]
mod command_crash_tests;
#[cfg(test)]
mod command_priority_tests;
mod command_wire;
#[allow(
    dead_code,
    reason = "Mission Control read-only hub staged before transport integration"
)]
mod cursor;
mod device;
#[allow(
    dead_code,
    reason = "Mission Control read-only hub staged before transport integration"
)]
mod hub;
pub(crate) mod limits;
#[allow(
    dead_code,
    reason = "Mission Control read-only hub staged before transport integration"
)]
mod protocol;
#[allow(dead_code, reason = "Mission Control transport integration")]
mod request;
pub(crate) mod stream;
pub(crate) mod transport;
#[allow(
    dead_code,
    reason = "Mission Control read-only hub staged before transport integration"
)]
pub(crate) mod upstream;
mod web_shell;
pub(crate) mod websocket;
#[allow(dead_code, reason = "Mission Control transport integration")]
mod writer;

use crate::enroll_oidc::web::{self, Provider};
use crate::storage::now_epoch_secs;
use authority::{Authority, AuthorityConfig, Carrier, Class, Record};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{header, Method, Request, Response, StatusCode};
use openidconnect::url;
use ring::aead::{self, LessSafeKey, Nonce, UnboundKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

const FLOW_COOKIE: &str = "__Host-mc_flow";
const SESSION_COOKIE: &str = "__Host-mc_session";
const MAX_FORM: usize = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub public_origin: String,
    #[serde(default = "header_limit")]
    pub max_handshake_header_bytes: usize,
    #[serde(default = "handshakes")]
    pub pending_handshakes_global: usize,
    #[serde(default = "handshake_timeout")]
    pub handshake_timeout_ms: u64,
    pub issuer: String,
    #[serde(default)]
    pub accepted_iss: Vec<String>,
    pub client_id: String,
    pub client_secret_file: Option<PathBuf>,
    pub redirect_uri: String,
    #[serde(default = "yes")]
    pub request_offline_access: bool,
    #[serde(default)]
    pub provider_auth_params: BTreeMap<String, String>,
    #[serde(default = "web::default_signing_algorithms")]
    pub signing_algorithms: Vec<openidconnect::core::CoreJwsSigningAlgorithm>,
    pub allowlist: Vec<String>,
    pub native_client_id: String,
    pub upstream_token_key_file: Option<PathBuf>,
    #[serde(default = "day")]
    pub upstream_revalidate_secs: u64,
    #[serde(default = "hour")]
    pub jwks_refresh_secs: u64,
    #[serde(default = "minute")]
    pub clock_skew_secs: u64,
    #[serde(default = "ten_minutes")]
    pub login_flow_ttl_secs: u64,
    #[serde(default = "ten_minutes")]
    pub device_code_ttl_secs: u64,
    #[serde(default = "five")]
    pub device_poll_secs: u64,
    #[serde(default = "sixteen")]
    pub device_codes_live: usize,
    #[serde(default = "ten")]
    pub device_authorizations_per_min: usize,
    #[serde(default = "five_usize")]
    pub device_code_attempts_per_session: usize,
    #[serde(default = "week")]
    pub session_idle_secs: u64,
    #[serde(default = "month")]
    pub session_absolute_secs: u64,
    #[serde(default = "month")]
    pub native_idle_secs: u64,
    #[serde(default = "quarter")]
    pub native_absolute_secs: u64,
    #[serde(default = "quarter")]
    pub machine_token_default_secs: u64,
    #[serde(default = "year")]
    pub machine_token_max_secs: u64,
    #[serde(default = "quarter")]
    pub delegated_grant_max_secs: u64,
    #[serde(default = "slo")]
    pub revocation_slo_ms: u64,
    #[serde(default = "watchdog")]
    pub authority_watchdog_ms: u64,
    #[serde(default)]
    pub(crate) session_limits: limits::ReadLimits,
    #[serde(default = "command_work_max_global")]
    pub(crate) command_work_max_global: usize,
    #[serde(default = "command_work_max_per_record")]
    pub(crate) command_work_max_per_record: usize,
    #[serde(default = "command_reserved_max_global")]
    pub(crate) command_reserved_max_global: usize,
    #[serde(default = "command_reserved_max_per_record")]
    pub(crate) command_reserved_max_per_record: usize,
    #[serde(default = "command_holds_max_global")]
    pub(crate) command_holds_max_global: usize,
    #[serde(default = "command_holds_max_per_record")]
    pub(crate) command_holds_max_per_record: usize,
    #[serde(default = "command_intents_max_global")]
    pub(crate) command_intents_max_global: usize,
    #[serde(default = "command_intents_max_per_record")]
    pub(crate) command_intents_max_per_record: usize,
    #[serde(default = "receipt_lane_max")]
    pub(crate) receipt_lane_max: usize,
    #[serde(default = "intent_ttl_ms")]
    pub(crate) intent_ttl_ms: u64,
    #[serde(default = "request_max_age_secs")]
    pub(crate) request_max_age_secs: u64,
    #[serde(default = "receipt_retention_secs")]
    pub(crate) receipt_retention_secs: u64,
    #[serde(default = "confirm_ttl_secs")]
    pub(crate) confirm_ttl_secs: u64,
}

fn command_work_max_global() -> usize {
    64
}
fn command_work_max_per_record() -> usize {
    8
}
fn command_reserved_max_global() -> usize {
    64
}
fn command_reserved_max_per_record() -> usize {
    8
}
fn command_holds_max_global() -> usize {
    256
}
fn command_holds_max_per_record() -> usize {
    16
}
fn command_intents_max_global() -> usize {
    1_024
}
fn command_intents_max_per_record() -> usize {
    32
}
fn receipt_lane_max() -> usize {
    32
}
fn intent_ttl_ms() -> u64 {
    60_000
}
fn request_max_age_secs() -> u64 {
    86_400
}
fn receipt_retention_secs() -> u64 {
    2_592_000
}
fn confirm_ttl_secs() -> u64 {
    3_600
}

fn yes() -> bool {
    true
}
fn header_limit() -> usize {
    16_384
}
fn handshakes() -> usize {
    64
}
fn handshake_timeout() -> u64 {
    5_000
}
fn day() -> u64 {
    86_400
}
fn hour() -> u64 {
    3_600
}
fn minute() -> u64 {
    60
}
fn ten_minutes() -> u64 {
    600
}
fn five() -> u64 {
    5
}
fn five_usize() -> usize {
    5
}
fn sixteen() -> usize {
    16
}
fn ten() -> usize {
    10
}
fn week() -> u64 {
    7 * day()
}
fn month() -> u64 {
    30 * day()
}
fn quarter() -> u64 {
    90 * day()
}
fn year() -> u64 {
    365 * day()
}
fn slo() -> u64 {
    1_000
}
fn watchdog() -> u64 {
    250
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Mission Control configuration")]
    Configuration,
    #[error("Mission Control issuer unavailable")]
    Unavailable,
}

impl Config {
    pub fn resolve_files(&mut self, base: &Path) {
        for file in [
            &mut self.client_secret_file,
            &mut self.upstream_token_key_file,
        ]
        .into_iter()
        .flatten()
        {
            if file.is_relative() {
                *file = base.join(&*file);
            }
        }
    }

    pub(crate) fn authority_config(&self, nodes: Vec<String>) -> AuthorityConfig {
        AuthorityConfig {
            allowlist: self.allowlist.clone(),
            nodes,
            session_idle_secs: self.session_idle_secs,
            session_absolute_secs: self.session_absolute_secs,
            native_idle_secs: self.native_idle_secs,
            native_absolute_secs: self.native_absolute_secs,
            machine_token_default_secs: self.machine_token_default_secs,
            machine_token_max_secs: self.machine_token_max_secs,
            delegated_grant_max_secs: self.delegated_grant_max_secs,
            revocation_slo_ms: self.revocation_slo_ms,
            authority_watchdog_ms: self.authority_watchdog_ms,
        }
    }

    fn oidc(&self) -> web::Config {
        web::Config {
            issuer: self.issuer.clone(),
            accepted_iss: self.accepted_iss.clone(),
            client_id: self.client_id.clone(),
            client_secret_file: self.client_secret_file.clone(),
            redirect_uri: self.redirect_uri.clone(),
            request_offline_access: self.request_offline_access,
            provider_auth_params: self.provider_auth_params.clone(),
            signing_algorithms: self.signing_algorithms.clone(),
            clock_skew_secs: self.clock_skew_secs,
            jwks_refresh_secs: self.jwks_refresh_secs,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        let public = url::Url::parse(&self.public_origin).map_err(|_| Error::Configuration)?;
        if public.scheme() != "https"
            || public.origin().ascii_serialization() != self.public_origin
            || self.native_client_id.is_empty()
            || self.native_client_id.len() > 256
            || self.redirect_uri != format!("{}/login/callback", self.public_origin)
            || [
                self.login_flow_ttl_secs,
                self.device_code_ttl_secs,
                self.device_poll_secs,
                self.upstream_revalidate_secs,
                self.jwks_refresh_secs,
            ]
            .into_iter()
            .any(|value| value == 0 || value > i64::MAX as u64)
            || self.max_handshake_header_bytes == 0
            || self.pending_handshakes_global == 0
            || self.pending_handshakes_global > tokio::sync::Semaphore::MAX_PERMITS
            || self.handshake_timeout_ms == 0
            || self.device_codes_live == 0
            || self.device_authorizations_per_min == 0
            || self.device_code_attempts_per_session == 0
            || !self.session_limits.valid()
            || ![
                (
                    self.command_work_max_per_record,
                    self.command_work_max_global,
                ),
                (
                    self.command_reserved_max_per_record,
                    self.command_reserved_max_global,
                ),
                (
                    self.command_holds_max_per_record,
                    self.command_holds_max_global,
                ),
                (
                    self.command_intents_max_per_record,
                    self.command_intents_max_global,
                ),
                (self.receipt_lane_max, self.receipt_lane_max),
            ]
            .into_iter()
            .all(|(local, global)| {
                local > 0 && local <= global && global <= tokio::sync::Semaphore::MAX_PERMITS
            })
            || ![
                self.intent_ttl_ms,
                self.request_max_age_secs,
                self.receipt_retention_secs,
                self.confirm_ttl_secs,
            ]
            .into_iter()
            .all(|value| value > 0 && value <= i64::MAX as u64 / 1_000)
            || self.clock_skew_secs > i64::MAX as u64 / 1_000
            || self.receipt_retention_secs <= self.request_max_age_secs
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

struct Flow {
    expires: i64,
    cookie_hash: [u8; 32],
    pending: web::Pending,
}

pub(crate) struct Issuer {
    config: Config,
    provider: Provider,
    authority: Arc<Authority>,
    key: Option<LessSafeKey>,
    commands: command::Commands,
    flows: Mutex<HashMap<[u8; 32], Flow>>,
    devices: device::Devices,
    refreshing: Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
}

pub(crate) struct Prepared {
    config: Config,
    provider: Provider,
    key: Option<LessSafeKey>,
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
    Ok(bytes)
}

fn opaque() -> Result<String, Error> {
    Ok(hex::encode(random::<32>()?))
}

fn key_file(file: &Path) -> Result<LessSafeKey, Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(file)
        .map_err(|_| Error::Configuration)?;
    let metadata = input.metadata().map_err(|_| Error::Configuration)?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != crate::agent::current_uid()
    {
        return Err(Error::Configuration);
    }
    let mut bytes = Vec::new();
    input
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration)?;
    let key = UnboundKey::new(&aead::AES_256_GCM, &bytes).map_err(|_| Error::Configuration)?;
    Ok(LessSafeKey::new(key))
}

fn encrypt(key: &LessSafeKey, token: &str) -> Result<Vec<u8>, Error> {
    let nonce = random::<12>()?;
    let mut body = token.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut body,
    )
    .map_err(|_| Error::Unavailable)?;
    Ok([nonce.to_vec(), body].concat())
}

fn decrypt(key: &LessSafeKey, encrypted: &[u8]) -> Result<String, Error> {
    let (nonce, body) = encrypted.split_at_checked(12).ok_or(Error::Unavailable)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::Unavailable)?;
    let mut body = body.to_vec();
    let plaintext = key
        .open_in_place(nonce, aead::Aad::empty(), &mut body)
        .map_err(|_| Error::Unavailable)?;
    std::str::from_utf8(plaintext)
        .map(str::to_owned)
        .map_err(|_| Error::Unavailable)
}

fn cookie<'a>(headers: &'a header::HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for line in headers.get_all(header::COOKIE) {
        for pair in line.to_str().ok()?.split(';') {
            if let Some((key, value)) = pair.trim().split_once('=') {
                if key == name {
                    if found.is_some() || value.is_empty() {
                        return None;
                    }
                    found = Some(value);
                }
            }
        }
    }
    found
}

type WebResponse = Response<Full<Bytes>>;

fn response(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> WebResponse {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, content_type)
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("content-security-policy", web_shell::CANONICAL_CSP)
        .body(Full::new(body.into()))
        .unwrap()
}

fn denied() -> WebResponse {
    response(
        StatusCode::UNAUTHORIZED,
        "text/plain; charset=utf-8",
        "authentication refused\n",
    )
}

fn forbidden() -> WebResponse {
    response(
        StatusCode::FORBIDDEN,
        "text/plain; charset=utf-8",
        "request refused\n",
    )
}

fn unavailable() -> WebResponse {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        "text/plain; charset=utf-8",
        "issuer unavailable\n",
    )
}

fn redirect(destination: &str) -> WebResponse {
    let Ok(location) = destination.parse() else {
        return unavailable();
    };
    let mut response = response(StatusCode::SEE_OTHER, "text/plain; charset=utf-8", "");
    response.headers_mut().insert(header::LOCATION, location);
    response
}

fn set_cookie(response: &mut WebResponse, name: &str, value: &str, same_site: &str, ttl: u64) {
    if let Ok(cookie) =
        format!("{name}={value}; Secure; HttpOnly; Path=/; SameSite={same_site}; Max-Age={ttl}")
            .parse()
    {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
}

fn form_decode<T: serde::de::DeserializeOwned>(encoded: &[u8]) -> Option<T> {
    if encoded.len() > MAX_FORM {
        return None;
    }
    let mut values = serde_json::Map::new();
    for (name, value) in url::form_urlencoded::parse(encoded) {
        if values
            .insert(
                name.into_owned(),
                serde_json::Value::String(value.into_owned()),
            )
            .is_some()
        {
            return None;
        }
    }
    serde_json::from_value(serde_json::Value::Object(values)).ok()
}

async fn form<T: serde::de::DeserializeOwned>(request: Request<Incoming>) -> Option<T> {
    let content_type = request.headers().get(header::CONTENT_TYPE)?.to_str().ok()?;
    if content_type.split(';').next()?.trim() != "application/x-www-form-urlencoded" {
        return None;
    }
    let body = Limited::new(request.into_body(), MAX_FORM)
        .collect()
        .await
        .ok()?;
    form_decode(&body.to_bytes())
}

impl Issuer {
    pub async fn prepare(config: Config) -> Result<Prepared, Error> {
        config.validate()?;
        let key = config
            .upstream_token_key_file
            .as_deref()
            .map(key_file)
            .transpose()?;
        let provider = Provider::discover(config.oidc(), &config.public_origin, key.is_some())
            .await
            .map_err(|_| Error::Configuration)?;
        if key.is_none() {
            tracing::info!("Mission Control upstream revalidation disabled");
        }
        Ok(Prepared {
            config,
            provider,
            key,
        })
    }

    pub fn start(prepared: Prepared, authority: Arc<Authority>) -> Arc<Self> {
        Arc::new(Self {
            devices: device::Devices::default(),
            config: prepared.config,
            provider: prepared.provider,
            authority,
            key: prepared.key,
            commands: command::Commands::withheld(),
            flows: Mutex::new(HashMap::new()),
            refreshing: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn start_with_command_authority_for_test(
        prepared: Prepared,
        authority: Arc<Authority>,
        fixture: Arc<command::ExactCommandAuthorityFixture>,
    ) -> Arc<Self> {
        let mut issuer = Self::start(prepared, authority);
        Arc::get_mut(&mut issuer)
            .expect("new issuer is unique")
            .commands = command::Commands::exact(fixture);
        issuer
    }

    #[cfg(test)]
    pub(crate) fn start_with_command_double_for_test(
        prepared: Prepared,
        authority: Arc<Authority>,
        fixture: Arc<command::ExactCommandAuthorityFixture>,
        double: Arc<command::CommandDouble>,
    ) -> Arc<Self> {
        let mut issuer = Self::start(prepared, authority);
        Arc::get_mut(&mut issuer)
            .expect("new issuer is unique")
            .commands = command::Commands::with_double(fixture, double);
        issuer
    }

    pub(crate) fn recover_commands(&self) -> Result<(), Error> {
        let mut state = self.authority.locked().map_err(|_| Error::Unavailable)?;
        command_store::recover(&mut state.conn, command::now_ms())
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }

    pub(crate) async fn maintain_commands(self: Arc<Self>) -> Result<(), Error> {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut cursor = 0;
        loop {
            timer.tick().await;
            let at = command::now_ms();
            let cutoff = at.saturating_sub(self.config.receipt_retention_secs as i64 * 1_000);
            {
                let state = self.authority.locked().map_err(|_| Error::Unavailable)?;
                command_store::compact(&state.conn, cutoff, at).map_err(|_| Error::Unavailable)?;
            }
            self.sweep_command_holds(&mut cursor, at)
                .map_err(|_| Error::Unavailable)?;
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn set_node_masked(&self, node: &str, masked: bool) {
        let _ = self.authority.set_node_masked(node, masked);
    }

    fn begin(&self) -> Result<WebResponse, Error> {
        let pending = self.provider.begin().map_err(|_| Error::Unavailable)?;
        let mut response = redirect(&pending.authorization_url);
        let token = opaque()?;
        let now = now_epoch_secs();
        let mut flows = self.flows.lock().map_err(|_| Error::Unavailable)?;
        flows.retain(|_, flow| flow.expires > now);
        if flows.len() >= 64 {
            return Err(Error::Unavailable);
        }
        let state = digest(pending.state());
        if flows.contains_key(&state) {
            return Err(Error::Unavailable);
        }
        flows.insert(
            state,
            Flow {
                expires: now.saturating_add(self.config.login_flow_ttl_secs as i64),
                cookie_hash: digest(&token),
                pending,
            },
        );
        set_cookie(
            &mut response,
            FLOW_COOKIE,
            &token,
            "Lax",
            self.config.login_flow_ttl_secs,
        );
        Ok(response)
    }

    async fn callback(&self, query: Option<&str>, headers: &header::HeaderMap) -> WebResponse {
        #[derive(Deserialize)]
        struct Callback {
            state: String,
            code: Option<String>,
        }
        let cookie_hash = cookie(headers, FLOW_COOKIE).map(digest);
        let query: Option<Callback> = query.and_then(|query| form_decode(query.as_bytes()));
        let flow = self.flows.lock().ok().and_then(|mut flows| {
            let key = cookie_hash
                .and_then(|value| {
                    flows
                        .iter()
                        .find(|(_, flow)| bool::from(flow.cookie_hash.ct_eq(&value)))
                        .map(|(key, _)| *key)
                })
                .or_else(|| query.as_ref().map(|query| digest(&query.state)))?;
            flows.remove(&key)
        });
        let mut response = match (flow, query, cookie_hash) {
            (Some(flow), Some(query), Some(cookie_hash))
                if flow.expires > now_epoch_secs()
                    && bool::from(flow.cookie_hash.ct_eq(&cookie_hash)) =>
            {
                self.finish_login(flow, query.code.as_deref(), &query.state)
                    .await
            }
            _ => denied(),
        };
        set_cookie(&mut response, FLOW_COOKIE, "", "Lax", 0);
        response
    }

    async fn finish_login(&self, flow: Flow, code: Option<&str>, state: &str) -> WebResponse {
        let Some(code) = code else {
            return denied();
        };
        let Ok(login) = self
            .provider
            .exchange(flow.pending, code, state, now_epoch_secs())
            .await
        else {
            return denied();
        };
        let Some(email) = login
            .claims
            .email
            .as_deref()
            .filter(|_| login.claims.email_verified)
        else {
            return denied();
        };
        let refresh = match self
            .key
            .as_ref()
            .zip(login.refresh_token.as_deref())
            .map(|(key, token)| encrypt(key, token))
            .transpose()
        {
            Ok(refresh) => refresh,
            Err(_) => return unavailable(),
        };
        let Ok(issued) = self.authority.login(
            email,
            &login.claims.iss,
            &login.claims.sub,
            refresh.as_deref(),
        ) else {
            return denied();
        };
        let mut response = response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            web_shell::callback_bridge(),
        );
        set_cookie(
            &mut response,
            SESSION_COOKIE,
            &issued.handle,
            "Strict",
            self.config.session_absolute_secs,
        );
        response
    }

    async fn revalidate(&self, owner: &str, now: i64) -> Result<(), ()> {
        let Some(key) = &self.key else {
            return Ok(());
        };
        let flight = {
            let mut refreshing = self.refreshing.lock().map_err(|_| ())?;
            refreshing.retain(|_, lock| lock.strong_count() != 0);
            if let Some(lock) = refreshing.get(owner).and_then(std::sync::Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                refreshing.insert(owner.to_owned(), Arc::downgrade(&lock));
                lock
            }
        };
        let _guard = flight.lock().await;
        let Some(refresh) = self.authority.refresh(owner).map_err(|_| ())? else {
            return Ok(());
        };
        if now.saturating_sub(refresh.checked_at) < self.config.upstream_revalidate_secs as i64 {
            return Ok(());
        }
        let token = decrypt(key, &refresh.encrypted).map_err(|_| ())?;
        match self.provider.refresh(&token).await {
            Ok(rotated) => {
                let encrypted = rotated
                    .as_deref()
                    .map(|token| encrypt(key, token))
                    .transpose()
                    .map_err(|_| ())?;
                self.authority
                    .record_refresh(owner, &refresh, encrypted.as_deref())
                    .map_err(|_| ())
            }
            Err(web::RefreshError::InvalidGrant) => {
                self.authority
                    .invalidate_owner_refresh(owner, &refresh)
                    .map_err(|_| ())?;
                Err(())
            }
            Err(web::RefreshError::Unavailable) => Ok(()),
        }
    }

    pub async fn admit(&self, handle: &str, carrier: Carrier) -> Result<Record, ()> {
        self.admit_at(handle, carrier, now_epoch_secs()).await
    }

    async fn admit_at(&self, handle: &str, carrier: Carrier, now: i64) -> Result<Record, ()> {
        let record = self.authority.admit(handle, carrier).map_err(|_| ())?;
        if matches!(record.class, Class::Browser | Class::Native) {
            self.revalidate(&record.principal, now).await?;
            return self.authority.admit(handle, carrier).map_err(|_| ());
        }
        Ok(record)
    }

    async fn browser(&self, headers: &header::HeaderMap) -> Option<(String, Record)> {
        if headers.contains_key(header::AUTHORIZATION) {
            return None;
        }
        let handle = cookie(headers, SESSION_COOKIE)?;
        let record = self.admit(handle, Carrier::Cookie).await.ok()?;
        Some((handle.to_owned(), record))
    }

    fn synchronizer(&self, handle: &str, supplied: &str) -> bool {
        let expected = csrf(handle);
        bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
    }

    fn exact_origin(&self, headers: &header::HeaderMap) -> bool {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        origins.next().and_then(|value| value.to_str().ok())
            == Some(self.config.public_origin.as_str())
            && origins.next().is_none()
    }

    #[cfg(test)]
    pub async fn handle(&self, request: Request<Incoming>) -> WebResponse {
        self.handle_with_hub(request, None).await
    }

    pub(crate) async fn handle_with_hub(
        &self,
        request: Request<Incoming>,
        hub: Option<&upstream::ReadHub>,
    ) -> WebResponse {
        let method = request.method().clone();
        let route = request.uri().path();
        if route == assets::JS_PATH && method == Method::GET {
            return response(
                StatusCode::OK,
                "application/javascript; charset=utf-8",
                assets::JS_BYTES,
            );
        }
        if route == assets::CSS_PATH && method == Method::GET {
            return response(StatusCode::OK, "text/css; charset=utf-8", assets::CSS_BYTES);
        }
        if route == "/favicon.ico" && method == Method::GET {
            return response(StatusCode::NO_CONTENT, "image/x-icon", "");
        }
        if !matches!(
            route,
            "/" | "/login"
                | "/login/callback"
                | "/logout"
                | "/device"
                | "/oauth/device_authorization"
                | "/oauth/token"
        ) {
            return response(StatusCode::NOT_FOUND, "text/plain", "not found\n");
        }
        if route != "/login/callback" && request.uri().query().is_some() {
            return response(StatusCode::BAD_REQUEST, "text/plain", "unexpected query\n");
        }
        match (method, route) {
            (Method::GET, "/login") => self.begin().unwrap_or_else(|_| unavailable()),
            (Method::GET, "/login/callback") => {
                self.callback(request.uri().query(), request.headers()).await
            }
            (Method::POST, "/logout") => self.logout(request).await,
            (Method::GET, "/") => match self.browser(request.headers()).await {
                Some((handle, record)) => {
                    if matches!(
                        web_shell::sec_fetch_site(request.headers()),
                        Some("same-origin" | "none")
                    ) {
                        let snapshot = hub.and_then(|h| {
                            let grants = transport::grants(&record);
                            if grants.is_empty() {
                                return None;
                            }
                            let masked = self.authority.masked_nodes().ok()?;
                            let scope = authority::Scope::Fleet;
                            let projection = protocol::Projection {
                                scope: &scope,
                                grants,
                                masked: &|node| masked.contains(node),
                                activity: true,
                            };
                            h.snapshot(&projection).ok().flatten().map(|(s, _)| s)
                        });
                        response(
                            StatusCode::OK,
                            "text/html; charset=utf-8",
                            web_shell::authenticated_shell(&csrf(&handle), snapshot.as_ref()),
                        )
                    } else {
                        response(
                            StatusCode::OK,
                            "text/html; charset=utf-8",
                            web_shell::no_data_shell(),
                        )
                    }
                }
                None => response(
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    web_shell::signin_shell(),
                ),
            },
            (Method::GET, "/device") => self.device_page(request.headers()).await,
            (Method::POST, "/device") => self.device_approval(request).await,
            (Method::POST, "/oauth/device_authorization") => {
                self.device_authorization(request).await
            }
            (Method::POST, "/oauth/token") => self.device_token(request).await,
            _ => response(
                StatusCode::METHOD_NOT_ALLOWED,
                "text/plain",
                "method refused\n",
            ),
        }
    }

    async fn logout(&self, request: Request<Incoming>) -> WebResponse {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Logout {
            csrf: String,
        }
        if !self.exact_origin(request.headers()) {
            return forbidden();
        }
        let Some((handle, record)) = self.browser(request.headers()).await else {
            return denied();
        };
        let Some(payload): Option<Logout> = form(request).await else {
            return forbidden();
        };
        if !self.synchronizer(&handle, &payload.csrf) {
            return forbidden();
        }
        if self.authority.revoke(&record.record_id).is_err() {
            return unavailable();
        }
        let mut response = redirect("/");
        set_cookie(&mut response, SESSION_COOKIE, "", "Strict", 0);
        response
    }
}

fn csrf(handle: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"xmsg mission control synchronizer\0");
    hash.update(handle);
    hex::encode(hash.finalize())
}

#[cfg(test)]
pub(crate) mod tests;
