#[cfg(feature = "daemon")]
pub mod adapter;
#[cfg(feature = "daemon")]
pub mod agent;
#[cfg(feature = "daemon")]
pub mod agy;
#[cfg(feature = "daemon")]
pub mod attachments;
#[cfg(feature = "daemon")]
pub mod claim;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "daemon")]
pub mod codex;
#[cfg(feature = "daemon")]
pub mod codex_relay;
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
pub mod http;
#[cfg(feature = "daemon")]
pub mod inbox;
#[cfg(feature = "daemon")]
pub mod mcp;
#[cfg(feature = "daemon")]
pub mod mesh;
#[cfg(feature = "daemon")]
pub mod node;
#[cfg(feature = "daemon")]
pub mod observe;
#[cfg(feature = "daemon")]
pub mod observe_effects;
#[cfg(feature = "daemon")]
pub mod pi;
#[cfg(feature = "daemon")]
pub mod plugin;
#[cfg(feature = "daemon")]
pub mod process;
#[cfg(feature = "daemon")]
pub mod registry;
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
