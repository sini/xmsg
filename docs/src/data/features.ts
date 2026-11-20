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
};

export const SIBLING_ALLOWLIST: SiblingAllowlistEntry[] = [];
