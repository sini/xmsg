use serde::{Deserialize, Serialize};

pub const ACTIVITY_STALE_WORKING_SECS: u64 = 30 * 60;
pub const ACTIVITY_STALE_BLOCKED_SECS: u64 = 24 * 60 * 60;
pub const ACTIVITY_FRESH_PERSIST_INTERVAL_SECS: i64 = 10;
pub const ACTIVITY_MAX_ENDPOINTS: usize = 1024;
pub const ACTIVITY_ENDED_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
pub const ACTIVITY_INGEST_QUEUE_CAP: usize = 256;
pub const ACTIVITY_MAX_CORRELATIONS: usize = 8;
pub const ACTIVITY_HOOK_DEADLINE_MS: u64 = 100;
pub const ACTIVITY_HOOK_MAX_STDIN_BYTES: usize = 1024 * 1024;
pub const ACTIVITY_HOOK_MAX_JSON_DEPTH: usize = 32;
pub const ACTIVITY_HOOK_MAX_FRAME_BYTES: usize = 1024;
pub const ACTIVITY_JOURNAL_MAX_ROWS: i64 = 2000;
pub const ACTIVITY_JOURNAL_MAX_BYTES: i64 = 2 * 1024 * 1024;
pub const ACTIVITY_PUBLISH_QUEUE_CAP: usize = 64;
pub const ACTIVITY_RATE_LIMIT_PER_SEC: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityState {
    Idle,
    Working,
    Blocked,
    Unknown,
}

impl ActivityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Working => "working",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "idle" => Some(Self::Idle),
            "working" => Some(Self::Working),
            "blocked" => Some(Self::Blocked),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockKind {
    Input,
    Permission,
}

impl BlockKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Permission => "permission",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "input" => Some(Self::Input),
            "permission" => Some(Self::Permission),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityReason {
    Background,
    ScheduledWake,
    Aged,
    Restarted,
    Contradictory,
    Unverified,
    EvidenceLost,
    RegistryUnavailable,
    Unreported,
    IncarnationEnded,
}

impl ActivityReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::ScheduledWake => "scheduled_wake",
            Self::Aged => "aged",
            Self::Restarted => "restarted",
            Self::Contradictory => "contradictory",
            Self::Unverified => "unverified",
            Self::EvidenceLost => "evidence_lost",
            Self::RegistryUnavailable => "registry_unavailable",
            Self::Unreported => "unreported",
            Self::IncarnationEnded => "incarnation_ended",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "background" => Some(Self::Background),
            "scheduled_wake" => Some(Self::ScheduledWake),
            "aged" => Some(Self::Aged),
            "restarted" => Some(Self::Restarted),
            "contradictory" => Some(Self::Contradictory),
            "unverified" => Some(Self::Unverified),
            "evidence_lost" => Some(Self::EvidenceLost),
            "registry_unavailable" => Some(Self::RegistryUnavailable),
            "unreported" => Some(Self::Unreported),
            "incarnation_ended" => Some(Self::IncarnationEnded),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityDescriptor {
    pub state: ActivityState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<BlockKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<ActivityReason>,
    pub state_epoch: String,
    pub incarnation: u64,
    pub revision: u64,
    pub changed_at: i64,
    pub fresh_at: i64,
}

impl ActivityDescriptor {
    pub fn is_valid(&self) -> bool {
        let block_ok = (self.state == ActivityState::Blocked) == self.block.is_some();
        let epoch_ok = self.state_epoch.len() == 32
            && self
                .state_epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        block_ok && epoch_ok && self.changed_at >= 0 && self.fresh_at >= 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityStatus {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotActivity {
    pub status: ActivityStatus,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundPresence {
    Absent,
    None,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakePresence {
    Absent,
    None,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerProof {
    pub pid: u32,
    pub started_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityHarness {
    Claude,
    Codex,
    Agy,
    Opencode,
    Pi,
    Hermes,
}

impl ActivityHarness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Agy => "agy",
            Self::Opencode => "opencode",
            Self::Pi => "pi",
            Self::Hermes => "hermes",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "claude" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "agy" => Some(Self::Agy),
            "opencode" => Some(Self::Opencode),
            "pi" => Some(Self::Pi),
            "hermes" => Some(Self::Hermes),
            _ => None,
        }
    }

    pub fn is_in_process(self) -> bool {
        matches!(self, Self::Opencode | Self::Pi | Self::Hermes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityFrame {
    pub action: String,
    pub schema_version: u8,
    pub harness: ActivityHarness,
    pub event: String,
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<OwnerProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<BlockKind>,
    pub background: BackgroundPresence,
    pub wake: WakePresence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<bool>,
}
