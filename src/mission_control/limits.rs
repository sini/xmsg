use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ReadLimits {
    pub hello_timeout_ms: u64,
    pub max_client_frame_bytes: usize,
    pub max_client_message_bytes: usize,
    pub max_server_frame_bytes: usize,
    pub max_server_message_bytes: usize,
    pub max_json_depth: usize,
    pub max_string_bytes: usize,
    pub subscriptions_per_connection: usize,
    pub client_messages_per_sec: u32,
    pub client_message_burst: u32,
    pub connections_per_principal: usize,
    pub connections_global: usize,
    pub upgrades_per_principal_per_min: usize,
    pub streams_per_token: usize,
    pub http_requests_per_token_per_min: usize,
    pub snapshot_max_bytes: usize,
    pub queue_max_bytes: usize,
    pub queue_max_messages: usize,
    pub slow_consumer_close_ms: u64,
    pub ping_interval_ms: u64,
    pub pong_timeout_ms: u64,
    pub tick_interval_ms: u64,
    pub idle_close_ms: u64,
    pub lease_max_secs: u64,
    pub replay_window_secs: u64,
    pub replay_events: usize,
    pub replay_bytes: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            hello_timeout_ms: 5000,
            max_client_frame_bytes: 16 * 1024,
            max_client_message_bytes: 16 * 1024,
            max_server_frame_bytes: 64 * 1024,
            max_server_message_bytes: 256 * 1024,
            max_json_depth: 16,
            max_string_bytes: 4096,
            subscriptions_per_connection: 16,
            client_messages_per_sec: 20,
            client_message_burst: 40,
            connections_per_principal: 8,
            connections_global: 64,
            upgrades_per_principal_per_min: 30,
            streams_per_token: 2,
            http_requests_per_token_per_min: 60,
            snapshot_max_bytes: 4 * 1024 * 1024,
            queue_max_bytes: 1024 * 1024,
            queue_max_messages: 1024,
            slow_consumer_close_ms: 30_000,
            ping_interval_ms: 20_000,
            pong_timeout_ms: 10_000,
            tick_interval_ms: 15_000,
            idle_close_ms: 120_000,
            lease_max_secs: 900,
            replay_window_secs: 120,
            replay_events: 4096,
            replay_bytes: 8 * 1024 * 1024,
        }
    }
}

impl ReadLimits {
    pub(super) fn valid(&self) -> bool {
        let sizes = [
            self.max_client_frame_bytes,
            self.max_client_message_bytes,
            self.max_server_frame_bytes,
            self.max_server_message_bytes,
            self.max_json_depth,
            self.max_string_bytes,
            self.subscriptions_per_connection,
            self.connections_per_principal,
            self.connections_global,
            self.upgrades_per_principal_per_min,
            self.streams_per_token,
            self.http_requests_per_token_per_min,
            self.snapshot_max_bytes,
            self.queue_max_bytes,
            self.queue_max_messages,
            self.replay_events,
            self.replay_bytes,
        ];
        let times = [
            self.hello_timeout_ms,
            self.slow_consumer_close_ms,
            self.ping_interval_ms,
            self.pong_timeout_ms,
            self.tick_interval_ms,
            self.idle_close_ms,
            self.lease_max_secs,
            self.replay_window_secs,
        ];
        sizes.iter().all(|&n| n > 0 && n <= 64 * 1024 * 1024)
            && times.iter().all(|&n| (1..=86_400_000).contains(&n))
            && self.max_json_depth <= 128
            && self.connections_global <= tokio::sync::Semaphore::MAX_PERMITS
            && self.max_client_frame_bytes <= self.max_client_message_bytes
            && self.max_server_frame_bytes <= self.max_server_message_bytes
            && self.client_messages_per_sec > 0
            && self.client_message_burst > 0
    }
}
