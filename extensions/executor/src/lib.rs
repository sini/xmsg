//! Executor contracts and a fail-closed control journal; no runtime launcher or host bridge.

pub mod acp;
pub mod capability;
#[allow(dead_code)]
mod eligibility;
pub mod framing;
pub mod protocol;
pub mod runtime_config;

pub mod auth;
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
