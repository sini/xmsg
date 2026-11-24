use serde_json::{json, Value};

pub(super) const ADAPTER_VERSION: &str = "0.108.0";
pub(super) const RUNTIME_VERSION: &str = "2.1.327";
pub(super) const REVISION: &str = "a6ba98ff3cf065d681abfe21042a8ce7ee292a09";

pub(super) fn session_meta() -> Value {
    json!({"claudeCode":{"options":{"allowDangerouslySkipPermissions":false}}})
}

pub(super) fn human_mode(mode: &str) -> bool {
    mode == "default"
}
