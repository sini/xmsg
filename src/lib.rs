#[cfg(feature = "daemon")]
pub mod activity;
#[cfg(feature = "daemon")]
pub mod adapter;
#[cfg(feature = "daemon")]
pub mod agent;
#[cfg(feature = "daemon")]
pub mod agy;
#[cfg(feature = "daemon")]
pub mod attachments;
#[cfg(feature = "daemon")]
pub mod caller_attribution;
#[cfg(feature = "daemon")]
pub mod claim;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "daemon")]
pub mod codex;
#[cfg(feature = "daemon")]
pub mod codex_relay;
#[cfg(feature = "daemon")]
pub mod discovery;
#[cfg(feature = "daemon")]
pub mod doctor_install;
#[cfg(feature = "daemon")]
mod doctor_peers;
#[cfg(feature = "daemon")]
pub mod e2e;
#[cfg(feature = "daemon")]
pub mod enroll_ca;
#[cfg(feature = "daemon")]
pub mod error;
#[cfg(feature = "daemon")]
pub mod fed;
#[cfg(feature = "daemon")]
pub mod federated_attachments;
#[cfg(feature = "daemon")]
pub mod handoff;
#[cfg(feature = "daemon")]
pub mod harnesses;
#[cfg(feature = "daemon")]
pub mod http;
#[cfg(feature = "daemon")]
pub mod inbox;
#[cfg(feature = "daemon")]
pub mod install_paths;
#[cfg(feature = "daemon")]
pub mod locator;
#[cfg(feature = "daemon")]
pub mod mcp;
#[cfg(feature = "daemon")]
pub mod mesh;
#[cfg(feature = "daemon")]
pub mod mission_control;
#[cfg(feature = "daemon")]
pub mod mission_control_client;
#[cfg(feature = "daemon")]
pub mod node;
#[cfg(feature = "daemon")]
pub mod observe;
#[cfg(feature = "daemon")]
pub mod observe_collector;
#[cfg(feature = "daemon")]
pub mod observe_collector_auth;
#[cfg(feature = "daemon")]
pub(crate) mod observe_collector_decode;
#[cfg(feature = "daemon")]
pub mod observe_collector_net;
#[cfg(feature = "daemon")]
pub mod observe_collector_store;
#[cfg(feature = "daemon")]
pub mod observe_collector_web;
#[cfg(feature = "daemon")]
pub mod observe_effects;
#[cfg(feature = "daemon")]
pub mod observe_export;
#[cfg(feature = "daemon")]
pub mod observe_fed;
#[cfg(feature = "daemon")]
pub mod observe_relay;
#[cfg(feature = "daemon")]
mod observe_snapshot;
#[cfg(all(feature = "daemon", feature = "test-hooks"))]
pub mod pairing;
#[cfg(all(feature = "daemon", not(feature = "test-hooks")))]
#[allow(dead_code)]
pub(crate) mod pairing;
#[cfg(feature = "daemon")]
pub mod pi;
#[cfg(feature = "daemon")]
pub mod plugin;
#[cfg(feature = "daemon")]
pub mod process;
#[cfg(feature = "daemon")]
mod recipient_snapshot;
#[cfg(feature = "daemon")]
pub mod registry;
#[cfg(feature = "daemon")]
pub mod runtime_lock;
#[cfg(feature = "daemon")]
pub mod schema_status;
#[cfg(feature = "client")]
pub mod session_context;
#[cfg(feature = "daemon")]
pub mod spawn;
#[cfg(feature = "daemon")]
pub mod storage;
#[cfg(feature = "daemon")]
pub mod surface;
#[cfg(feature = "daemon")]
pub mod svc;
#[cfg(feature = "daemon")]
pub mod systemd;

#[cfg(feature = "daemon")]
pub mod enroll_oidc;

#[cfg(feature = "daemon")]
pub mod enroll_client;

#[cfg(feature = "daemon")]
pub mod enroll;

#[cfg(feature = "daemon")]
pub mod enroll_cli;

#[cfg(all(test, feature = "daemon"))]
mod enroll_consumer_tests;

#[cfg(all(test, feature = "daemon"))]
mod enroll_device_consumer_tests;

#[cfg(all(test, feature = "daemon"))]
mod observe_export_gap_tests;
#[cfg(all(test, feature = "daemon"))]
mod observe_snapshot_tests;

#[cfg(all(test, feature = "daemon"))]
mod observe_collector_unknown_tests;

#[cfg(feature = "daemon")]
pub mod ca_health;
