import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
	collectLongPlannedWarnings,
	computeFeatureStatus,
	extractXmsgRevFromFlakeLock,
	lintDocsFile,
	resolveFleetPinRev,
	validateManifest,
} from './status-lib.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const statusAstroPath = path.resolve(__dirname, '../src/components/Status.astro');

const sampleFeature = {
	id: 'demo.feature',
	title: 'Demo feature',
	owner: 'sini',
	evidence: [{ path: 'src/demo.rs', anchor: 'pub fn demo' }],
};

function makeReader(treeByRef) {
	return (ref, filePath) => treeByRef[ref]?.[filePath] ?? null;
}

test('S1: feature removed from main drops onMain while keeping inFleetPin', () => {
	const refs = {
		main: { ref: 'main-sha' },
		fleetPin: { ref: 'pin-sha' },
		releaseTag: { ref: null, noReleaseTags: true },
	};
	const reader = makeReader({
		'main-sha': { 'src/demo.rs': '// removed' },
		'pin-sha': { 'src/demo.rs': 'pub fn demo() {}' },
	});
	const res = computeFeatureStatus(sampleFeature, refs, reader);
	assert.equal(res.errors.length, 0);
	assert.equal(res.status.onMain, false);
	assert.equal(res.status.inFleetPin, true);
	assert.equal(res.status.released, false);
});

test('S2: missing fleetPin renders unknown in non-strict and fails in strict', () => {
	const refs = {
		main: { ref: 'main-sha' },
		fleetPin: { ref: null },
		releaseTag: { ref: null, noReleaseTags: true },
	};
	const reader = makeReader({
		'main-sha': { 'src/demo.rs': 'pub fn demo() {}' },
	});

	const nonStrict = computeFeatureStatus(sampleFeature, refs, reader, { strict: false });
	assert.equal(nonStrict.errors.length, 0);
	assert.equal(nonStrict.status.onMain, true);
	assert.equal(nonStrict.status.inFleetPin, 'unknown');
	assert.equal(nonStrict.status.released, false);

	const strict = computeFeatureStatus(sampleFeature, refs, reader, { strict: true });
	assert.ok(strict.errors.length > 0);
	assert.match(strict.errors[0], /fleet pin/i);
});

test('S3: Status.astro reads precomputed .status.json and has zero git/child_process calls', () => {
	const src = fs.readFileSync(statusAstroPath, 'utf8');
	assert.match(src, /\.status\.json/);
	assert.doesNotMatch(src, /child_process|execFile|execSync|spawn|\bgit\b/);
});

test('S4: released does not imply inFleetPin or onMain (no ladder)', () => {
	const refs = {
		main: { ref: 'main-sha' },
		fleetPin: { ref: 'pin-sha' },
		releaseTag: { ref: 'v0.1.0' },
	};
	const reader = makeReader({
		'main-sha': {},
		'pin-sha': {},
		'v0.1.0': { 'src/demo.rs': 'pub fn demo() {}' },
	});
	const res = computeFeatureStatus(sampleFeature, refs, reader);
	assert.equal(res.status.onMain, false);
	assert.equal(res.status.inFleetPin, false);
	assert.equal(res.status.released, true);
});

test('S5: plannedSince older than 60 days warns without failing', () => {
	const features = {
		'old.planned': {
			id: 'old.planned',
			title: 'Old planned',
			owner: 'sini',
			evidence: [],
			plannedSince: '2026-08-01',
		},
	};
	const statuses = {
		'old.planned': {
			id: 'old.planned',
			title: 'Old planned',
			owner: 'sini',
			note: null,
			onMain: false,
			inFleetPin: false,
			released: false,
		},
	};
	assert.equal(validateManifest(features, [], '2026-11-20').length, 0);
	const warnings = collectLongPlannedWarnings(features, statuses, '2026-11-20', 60);
	assert.equal(warnings.length, 1);
	assert.match(warnings[0], /old\.planned/);
});

test('S6: lint rejects free-text status markers and allows prose "planned"', () => {
	const features = { 'demo.feature': sampleFeature };

	const proseOk = lintDocsFile(
		'concepts/example.mdx',
		'A planned collector source selects one explicit route and is planned for later.',
		features,
	);
	assert.equal(proseOk.length, 0);

	const asideFail = lintDocsFile(
		'concepts/example.mdx',
		'<Aside type="note" title="Planned, not yet released">\nBody\n</Aside>',
		features,
	);
	assert.ok(asideFail.length > 0);

	const textFail = lintDocsFile(
		'concepts/example.mdx',
		'This feature is Planned, not yet released.',
		features,
	);
	assert.ok(textFail.length > 0);

	const parenFail = lintDocsFile('concepts/example.mdx', '## Feature (Planned)', features);
	assert.ok(parenFail.length > 0);
});

test('S7: regression removes onMain while preserving inFleetPin and released', () => {
	const refs = {
		main: { ref: 'main-sha' },
		fleetPin: { ref: 'pin-sha' },
		releaseTag: { ref: 'v0.1.0' },
	};
	const reader = makeReader({
		'main-sha': { 'src/demo.rs': '// reverted' },
		'pin-sha': { 'src/demo.rs': 'pub fn demo() {}' },
		'v0.1.0': { 'src/demo.rs': 'pub fn demo() {}' },
	});
	const res = computeFeatureStatus(sampleFeature, refs, reader);
	assert.equal(res.status.onMain, false);
	assert.equal(res.status.inFleetPin, true);
	assert.equal(res.status.released, true);
});

test('S8: tag presence alone does not mark feature released if evidence is absent at tag', () => {
	const refs = {
		main: { ref: 'main-sha' },
		fleetPin: { ref: 'pin-sha' },
		releaseTag: { ref: 'v0.1.0' },
	};
	const reader = makeReader({
		'main-sha': { 'src/demo.rs': 'pub fn demo() {}' },
		'pin-sha': { 'src/demo.rs': 'pub fn demo() {}' },
		'v0.1.0': { 'src/other.rs': 'fn other() {}' },
	});
	const res = computeFeatureStatus(sampleFeature, refs, reader);
	assert.equal(res.status.onMain, true);
	assert.equal(res.status.inFleetPin, true);
	assert.equal(res.status.released, false);
});

test('S9: expired sibling-repo allowlist entry fails manifest validation', () => {
	const errors = validateManifest(
		{ 'demo.feature': sampleFeature },
		[
			{
				id: 'gateway.oauth',
				repo: 'sini/xmsg-mcp-gateway',
				owner: 'sini',
				expiry: '2026-10-01',
				reason: 'Temporary sibling-repo status',
			},
		],
		'2026-11-20',
	);
	assert.ok(errors.length > 0);
	assert.match(errors[0], /Expired sibling allowlist entry/);
});

test('S10: <Status id> missing from manifest fails lint', () => {
	const errors = lintDocsFile(
		'concepts/example.mdx',
		'<Status id="nonexistent.feature" />',
		{ 'demo.feature': sampleFeature },
	);
	assert.equal(errors.length, 1);
	assert.match(errors[0], /unknown feature id 'nonexistent\.feature'/);
});

test('S11: fleet pin derives from nix-config flake.lock; stale or failed fetch yields unknown', () => {
	const liveSha = '16f20a15bda3688d5364afb0a2eb558ae643cb9b';
	const staleSha = 'fcd68211b2b6a1d74dd9a0310388e146851fa51f';

	const extracted = extractXmsgRevFromFlakeLock({
		nodes: {
			xmsg: {
				locked: { owner: 'sini', repo: 'xmsg', rev: liveSha },
			},
		},
	});
	assert.equal(extracted, liveSha);

	assert.throws(() =>
		extractXmsgRevFromFlakeLock({
			nodes: { xmsg: { locked: { owner: 'other', repo: 'xmsg', rev: liveSha } } },
		}),
	);

	// Stale fleet-pin.txt disagrees with fetched nix-config rev -> rev is null -> unknown
	const disagreed = resolveFleetPinRev({
		envOverride: '',
		fallbackRev: staleSha,
		fetchedRev: liveSha,
		fetchError: null,
	});
	assert.equal(disagreed.rev, null);
	assert.match(disagreed.error, /disagrees/);

	const statusDisagreed = computeFeatureStatus(
		sampleFeature,
		{
			main: { ref: 'main-sha' },
			fleetPin: { ref: disagreed.rev },
			releaseTag: { ref: null, noReleaseTags: true },
		},
		makeReader({ 'main-sha': { 'src/demo.rs': 'pub fn demo() {}' } }),
		{ strict: false },
	);
	assert.equal(statusDisagreed.status.inFleetPin, 'unknown');

	// Fetch failed with fallback file present -> rev is null -> unknown (strict fails)
	const failedFetch = resolveFleetPinRev({
		envOverride: '',
		fallbackRev: staleSha,
		fetchedRev: null,
		fetchError: 'HTTP 503',
	});
	assert.equal(failedFetch.rev, null);
	assert.match(failedFetch.error, /HTTP 503/);

	// Matching fallback & fetched -> resolves liveSha
	const matched = resolveFleetPinRev({
		envOverride: '',
		fallbackRev: liveSha,
		fetchedRev: liveSha,
		fetchError: null,
	});
	assert.equal(matched.rev, liveSha);
	assert.equal(matched.error, null);
});
