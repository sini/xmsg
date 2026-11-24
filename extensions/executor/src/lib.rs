//! Staged executor runtime; caller and adapter qualification remain default-denied.

pub mod acp;
pub mod approval;
#[allow(dead_code)]
mod caller_admission;
#[allow(dead_code)]
mod caller_policy;
pub mod capability;
#[allow(dead_code)]
mod content_delivery;
#[allow(dead_code)]
mod eligibility;
pub mod framing;
mod human_operator;
pub mod launch_environment;
#[allow(dead_code)]
mod lifecycle;
mod lifecycle_client;
pub mod operator;
pub mod protocol;
pub mod runtime_config;
#[allow(dead_code)]
mod runtime_policy;
#[allow(dead_code)]
mod runtime_process;

pub mod auth;
#[allow(dead_code)]
pub mod content;
#[allow(dead_code)]
mod content_admission;
pub mod control;
mod journal;
pub mod unix;
pub mod workspace;
// Host effects stay disabled until caller and adapter qualification is verified.
#[allow(dead_code)]
mod execution;
#[allow(dead_code)]
mod membership;
#[allow(dead_code)]
mod supervisor;
