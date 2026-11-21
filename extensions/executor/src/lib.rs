//! Executor contracts and a fail-closed control journal; no runtime launcher or host bridge.

pub mod capability;
pub mod framing;
pub mod protocol;

pub mod auth;
pub mod control;
mod journal;
pub mod unix;
