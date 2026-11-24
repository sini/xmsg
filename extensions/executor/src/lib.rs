//! Executor contracts and a fail-closed control journal; no runtime launcher or host bridge.

pub mod acp;
pub mod approval;
pub mod capability;
#[allow(dead_code)]
mod eligibility;
pub mod framing;
pub mod launch_environment;
#[allow(dead_code)]
mod lifecycle;
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
pub mod control;
mod journal;
pub mod unix;
pub mod workspace;
// Host effects remain staged until the separately commissioned attribution bridge exists.
#[allow(dead_code)]
mod execution;
#[allow(dead_code)]
mod membership;
#[allow(dead_code)]
mod supervisor;
