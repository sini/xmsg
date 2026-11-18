//! Default `ANTIGRAVITY_*` environment scrub for test harnesses that spawn `xmsg` daemons,
//! preventing an outer Antigravity session's live credentials from leaking into test children.
#![allow(dead_code)]

pub const AGY_ENV_VARS: [&str; 3] = [
    "ANTIGRAVITY_CONVERSATION_ID",
    "ANTIGRAVITY_LS_ADDRESS",
    "ANTIGRAVITY_CSRF_TOKEN",
];

pub fn scrub_std(cmd: &mut std::process::Command) -> &mut std::process::Command {
    for k in AGY_ENV_VARS {
        cmd.env_remove(k);
    }
    cmd
}

pub fn scrub_tokio(cmd: &mut tokio::process::Command) -> &mut tokio::process::Command {
    for k in AGY_ENV_VARS {
        cmd.env_remove(k);
    }
    cmd
}

pub trait ScrubAgyEnv {
    fn scrub_agy_env(&mut self) -> &mut Self;
}

impl ScrubAgyEnv for std::process::Command {
    fn scrub_agy_env(&mut self) -> &mut Self {
        scrub_std(self)
    }
}

impl ScrubAgyEnv for tokio::process::Command {
    fn scrub_agy_env(&mut self) -> &mut Self {
        scrub_tokio(self)
    }
}
