pub(super) const ADAPTER_VERSION: &str = "2.7.0";
pub(super) const RUNTIME_VERSION: &str = "0.169.1";
pub(super) const REVISION: &str = "7c98a1608022cbb2b7e425ae7a1df5fde86c6ff2";

pub(super) fn human_mode(mode: &str) -> bool {
    matches!(mode, "read-only" | "workspace-write")
}
