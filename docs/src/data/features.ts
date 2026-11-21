export interface EvidenceAnchor {
	path: string;
	anchor: string;
}

export interface FeatureEntry {
	id: string;
	title: string;
	owner: string;
	evidence: EvidenceAnchor[];
	note?: string;
	/** ISO date (YYYY-MM-DD) when a planned-only entry was added; warns after 60 days. */
	plannedSince?: string;
}

export interface SiblingAllowlistEntry {
	id: string;
	repo: string;
	owner: string;
	/** ISO date (YYYY-MM-DD) after which the allowlist entry expires and fails lint. */
	expiry: string;
	reason: string;
}

export const FEATURES: Record<string, FeatureEntry> = {
	'mission-control.session': {
		id: 'mission-control.session',
		title: 'Mission Control session issuer',
		owner: 'sini',
		evidence: [{ path: 'src/mission_control.rs', anchor: 'pub struct Config' }],
		plannedSince: '2026-11-21',
	},
	'mission-control.http': {
		id: 'mission-control.http',
		title: 'Mission Control snapshot and stream transports',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-21',
	},
	'mission-control.machine-tokens': {
		id: 'mission-control.machine-tokens',
		title: 'Mission Control read-only machine tokens',
		owner: 'sini',
		evidence: [{ path: 'src/mission_control/authority.rs', anchor: 'fn mint_machine(' }],
		plannedSince: '2026-11-21',
	},
	'mission-control.delegated-grants': {
		id: 'mission-control.delegated-grants',
		title: 'Mission Control delegated grants',
		owner: 'sini',
		evidence: [{ path: 'src/mission_control/authority.rs', anchor: 'struct DelegatedGrant' }],
		plannedSince: '2026-11-21',
	},
	'session-context.tags': {
		id: 'session-context.tags',
		title: 'Self-reported session context tags',
		owner: 'sini',
		evidence: [{ path: 'src/session_context.rs', anchor: 'pub struct SessionContext' }],
		plannedSince: '2026-11-20',
		note: 'Optional session metadata with publication masks on the source node.',
	},
	'teams.executor-contracts': {
		id: 'teams.executor-contracts',
		title: 'Executor contracts and fake ACP test harness',
		owner: 'sini',
		evidence: [{ path: 'extensions/executor/src/protocol.rs', anchor: 'pub struct ControlRequest' }],
		plannedSince: '2026-11-20',
		note: 'Internal library only; no launcher, endpoint or real harness qualification.',
	},
	'teams.local-parity': {
		id: 'teams.local-parity',
		title: 'Optional local mixed-harness teams runtime',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-20',
		note: 'Planned runtime; contracts and fake fixtures do not launch or qualify a harness.',
	},
	'session-locator.cli': {
		id: 'session-locator.cli',
		title: 'Read-only session locator CLI and Unix HTTP endpoint',
		owner: 'sini',
		evidence: [{ path: 'src/locator.rs', anchor: 'pub struct Locator' }],
		plannedSince: '2026-11-20',
		note: 'Registration-native identifiers and local display hints; resume recipes remain unproven.',
	},
	'fleet-observer.collector': {
		id: 'fleet-observer.collector',
		title: 'Fleet observer collector and browser view',
		owner: 'sini',
		evidence: [
			{ path: 'src/observe_collector.rs', anchor: 'pub struct Args' },
			{ path: 'src/observe_collector_web.rs', anchor: 'pub fn render_with_health' },
		],
		note: 'Owner collector cache, 15 s freshness window, coverage summary, and read-only browser view.',
	},
	'fleet-observer.reverse-relay': {
		id: 'fleet-observer.reverse-relay',
		title: 'Reverse observation through an owner-administered hub',
		owner: 'sini',
		evidence: [
			{ path: 'src/observe_relay.rs', anchor: 'pub struct Config' },
			{ path: 'src/observe_relay.rs', anchor: 'pub struct Route' },
		],
		note: 'Outbound-only leaf observation relayed through an owner hub over control polls.',
	},
	'fleet-observer.unknown-event-kind': {
		id: 'fleet-observer.unknown-event-kind',
		title: 'Collector unknown event kind fallback',
		owner: 'sini',
		evidence: [{ path: 'src/observe_collector_decode.rs', anchor: 'fn decode_page' }],
		note: 'Preserves forward compatibility when reading metadata from a newer node.',
	},
	'fleet-observer.body-transcript-views': {
		id: 'fleet-observer.body-transcript-views',
		title: 'Body detail and transcript views',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-20',
		note: 'Metadata-only collector; body detail and transcript views are not implemented.',
	},
	'xmsg.watch': {
		id: 'xmsg.watch',
		title: 'xmsg watch terminal timeline',
		owner: 'sini',
		evidence: [{ path: 'src/watch.rs', anchor: 'pub struct WatchArgs' }],
	},
	'xmsg.doctor': {
		id: 'xmsg.doctor',
		title: 'xmsg doctor diagnostics',
		owner: 'sini',
		evidence: [
			{ path: 'src/doctor.rs', anchor: 'pub struct DoctorArgs' },
			{ path: 'src/doctor.rs', anchor: 'pub fn run' },
		],
	},
	'xmsg.doctor-peers': {
		id: 'xmsg.doctor-peers',
		title: 'Daemon-only federation peer diagnostics',
		owner: 'sini',
		evidence: [{ path: 'src/doctor_peers.rs', anchor: 'pub(crate) struct Report' }],
	},
	'xmsg.recipient-snapshot': {
		id: 'xmsg.recipient-snapshot',
		title: 'Read-only local recipient snapshot and process liveness',
		owner: 'sini',
		evidence: [{ path: 'src/recipient_snapshot.rs', anchor: 'pub(crate) fn collect' }],
	},
	'xmsg.discovery': {
		id: 'xmsg.discovery',
		title: 'Candidate and verified peer discovery',
		owner: 'sini',
		evidence: [{ path: 'src/discovery/mod.rs', anchor: 'pub struct CandidateTable' }],
	},
	'xmsg.peer-mailbox': {
		id: 'xmsg.peer-mailbox',
		title: 'Bounded per-leaf stored peer_mailbox',
		owner: 'sini',
		evidence: [{ path: 'src/storage.rs', anchor: 'pub fn insert_peer_mailbox_with_limits' }],
	},
	'xmsg.codex-restart-custody': {
		id: 'xmsg.codex-restart-custody',
		title: 'Codex restart custody and durable handoff',
		owner: 'sini',
		evidence: [
			{ path: 'src/storage.rs', anchor: 'fn rebind_pending_codex_handoffs' },
			{ path: 'src/storage.rs', anchor: 'pub fn release_codex_handoff_to_pending' },
		],
	},
	'xmsg.attachments-inline-text': {
		id: 'xmsg.attachments-inline-text',
		title: 'Inline text attachment media_type default',
		owner: 'sini',
		evidence: [
			{
				path: 'src/mcp.rs',
				anchor: 'fn inline_text_defaults_to_utf8_plain_while_paths_keep_binary_default',
			},
		],
	},
	'xmsg.enroll-ca': {
		id: 'xmsg.enroll-ca',
		title: 'Device and OIDC enrollment CA',
		owner: 'sini',
		evidence: [
			{ path: 'src/enroll_ca.rs', anchor: 'pub struct EnrollCa' },
			{ path: 'src/enroll_client.rs', anchor: 'pub struct SavedState' },
		],
	},
	'xmsg.a2a-edge': {
		id: 'xmsg.a2a-edge',
		title: 'Optional A2A edge gateway',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-20',
		note: 'Planned / under evaluation: optional gateway node translating external A2A tasks to and from xmsg.',
	},
	'xmsg.slim-bridge': {
		id: 'xmsg.slim-bridge',
		title: 'Optional SLIM bridge',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-20',
		note: 'Backlog: optional bridge node for interoperating with an external SLIM fabric.',
	},
	'xmsg.teams-control': {
		id: 'xmsg.teams-control',
		title: 'Optional teams & environment extensions',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-20',
		note: 'Design intent: optional per-environment terminal/runtime adapters, hook-derived attention, typed-receipt lifecycle, and two-phase worktrees.',
	},
	'xmsg.ca-health': {
		id: 'xmsg.ca-health',
		title: 'CA application health checks',
		owner: 'sini',
		evidence: [{ path: 'src/ca_health.rs', anchor: 'pub fn installed' }],
	},
	'xmsg.schema-status': {
		id: 'xmsg.schema-status',
		title: 'Primary SQLite schema status inspection',
		owner: 'sini',
		evidence: [{ path: 'src/schema_status.rs', anchor: 'pub fn inspect' }],
	},
	'xmsg.harness-descriptors': {
		id: 'xmsg.harness-descriptors',
		title: 'Declared plugin harness descriptors (--harnesses-file)',
		owner: 'sini',
		evidence: [{ path: 'src/harnesses.rs', anchor: 'pub struct HarnessRegistry' }],
		plannedSince: '2026-11-20',
		note: 'Optional JSON descriptor registry for poll-only plugin harnesses, atomic reload/drain, immediate security revocation, and typed inert locator resume_argv.',
	},
	'agy.macos-locks': {
		id: 'agy.macos-locks',
		title: 'macOS Antigravity lock and process ancestry checks',
		owner: 'sini',
		evidence: [
			{ path: 'src/agy.rs', anchor: 'darwin_holder' },
			{ path: 'src/codex.rs', anchor: 'kqueue_vnode' },
		],
	},
	'gateway.oauth-as': {
		id: 'gateway.oauth-as',
		title: 'Gateway OAuth authorization server profile',
		owner: 'sini',
		evidence: [],
		note: 'Verified in sibling repo sini/xmsg-mcp-gateway (4804d250).',
	},
	'gateway.inline-attachments': {
		id: 'gateway.inline-attachments',
		title: 'Gateway inline attachment transport',
		owner: 'sini',
		evidence: [],
		note: 'Verified in sibling repo sini/xmsg-mcp-gateway (4804d250).',
	},
	'gateway.webhook-egress': {
		id: 'gateway.webhook-egress',
		title: 'Gateway webhook egress allowlist and callback verification',
		owner: 'sini',
		evidence: [],
		note: 'Verified in sibling repo sini/xmsg-mcp-gateway (4804d250).',
	},
	'genie.token-pools': {
		id: 'genie.token-pools',
		title: 'Genie token pools',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-20',
		note: 'Unimplemented in genie-agent 0117ea39 (src/dispatcher/index.ts:65 stub).',
	},
	'genie.reply-only-mcp': {
		id: 'genie.reply-only-mcp',
		title: 'Reply-only MCP in Genie expert sessions',
		owner: 'sini',
		evidence: [],
		plannedSince: '2026-11-20',
		note: 'Unimplemented in genie-agent 0117ea39 (nix/options.nix:639 registers plain xmsg mcp).',
	},
	'nixos.module-options': {
		id: 'nixos.module-options',
		title: 'NixOS and Home Manager module options',
		owner: 'sini',
		evidence: [{ path: 'nix/modules/home-manager.nix', anchor: 'stableExecutable = mkOption' }],
	},
	'fleet-observer.retention': {
		id: 'fleet-observer.retention',
		title: 'Configurable inactive-node retention window',
		owner: 'sini',
		evidence: [
			{
				path: 'src/observe_collector_net.rs',
				anchor: 'pub retention_after_inactive_secs: u64',
			},
		],
		note: 'Retains history for removed or unconfigured nodes for retention_after_inactive_secs (default 604800 = 7 days) after last accepted ingest.',
	},
};

export const SIBLING_ALLOWLIST: SiblingAllowlistEntry[] = [
	{
		id: 'gateway.oauth-as',
		repo: 'sini/xmsg-mcp-gateway',
		owner: 'sini',
		expiry: '2026-12-20',
		reason: 'Verified in sini/xmsg-mcp-gateway main (4804d250) at src/auth.rs:553 and src/authorization_server/mod.rs:183',
	},
	{
		id: 'gateway.inline-attachments',
		repo: 'sini/xmsg-mcp-gateway',
		owner: 'sini',
		expiry: '2026-12-20',
		reason: 'Verified in sini/xmsg-mcp-gateway main (4804d250) at src/attachments.rs:86 and src/attachments.rs:110',
	},
	{
		id: 'gateway.webhook-egress',
		repo: 'sini/xmsg-mcp-gateway',
		owner: 'sini',
		expiry: '2026-12-20',
		reason: 'Verified in sini/xmsg-mcp-gateway main (4804d250) at src/events.rs:104 and src/serving.rs:90',
	},
];
