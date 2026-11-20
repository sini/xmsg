import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FEATURES, SIBLING_ALLOWLIST } from '../src/data/features.ts';
import {
	collectLongPlannedWarnings,
	computeFeatureStatus,
	extractXmsgRevFromFlakeLock,
	lintDocsTree,
	resolveFleetPinRev,
	todayIsoDate,
	validateManifest,
} from './status-lib.mjs';

const DEFAULT_NIX_CONFIG_FLAKE_LOCK_URL =
	'https://raw.githubusercontent.com/sini/nix-config/main/flake.lock';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const docsDir = path.resolve(__dirname, '..');
const repoRoot = path.resolve(docsDir, '..');
const docsContentDir = path.join(docsDir, 'src', 'content', 'docs');
const statusOutPath = path.join(docsDir, '.status.json');

function runGit(args) {
	return execFileSync('git', args, {
		cwd: repoRoot,
		encoding: 'utf8',
		stdio: ['ignore', 'pipe', 'pipe'],
	});
}

function resolveCommit(candidate) {
	if (!candidate) return null;
	try {
		return runGit(['rev-parse', '--verify', `${candidate}^{commit}`]).trim();
	} catch {
		return null;
	}
}

async function fetchFleetPinFromNixConfig() {
	const url =
		process.env.NIX_CONFIG_FLAKE_LOCK_URL?.trim() || DEFAULT_NIX_CONFIG_FLAKE_LOCK_URL;
	try {
		const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
		if (!res.ok) {
			return {
				fetchedRev: null,
				fetchError: `HTTP ${res.status} fetching ${url}`,
			};
		}
		const json = await res.json();
		return { fetchedRev: extractXmsgRevFromFlakeLock(json), fetchError: null };
	} catch (err) {
		return {
			fetchedRev: null,
			fetchError: `Failed to fetch ${url}: ${err instanceof Error ? err.message : String(err)}`,
		};
	}
}

async function resolveRefs() {
	const mainCandidate = process.env.MAIN_REF?.trim();
	const mainSha = mainCandidate
		? resolveCommit(mainCandidate)
		: (resolveCommit('origin/main') ?? resolveCommit('main'));

	const envOverride = process.env.FLEET_PIN_REV?.trim() || '';

	const fetched = envOverride
		? { fetchedRev: null, fetchError: null }
		: await fetchFleetPinFromNixConfig();
	const pinResolution = resolveFleetPinRev({
		envOverride,
		fetchedRev: fetched.fetchedRev,
		fetchError: fetched.fetchError,
	});
	const fleetPinSha = resolveCommit(pinResolution.rev);

	let releaseTagSha = null;
	let noReleaseTags = false;
	try {
		const tags = runGit(['tag', '--list', 'v*', '--sort=-v:refname'])
			.split('\n')
			.map((t) => t.trim())
			.filter(Boolean);
		if (tags.length === 0) {
			noReleaseTags = true;
		} else {
			releaseTagSha = resolveCommit(tags[0]);
		}
	} catch {
		// Leave releaseTagSha null -> unknown in non-strict, error in strict.
	}

	return {
		refs: {
			main: { ref: mainSha, label: mainCandidate || 'origin/main|main' },
			fleetPin: { ref: fleetPinSha, label: pinResolution.source },
			releaseTag: { ref: releaseTagSha, noReleaseTags, label: 'v*' },
		},
		pinError: pinResolution.error,
	};
}

function makeGitFileReader() {
	const cache = new Map();
	return (ref, filePath) => {
		const key = `${ref}:${filePath}`;
		if (cache.has(key)) return cache.get(key);
		let content = null;
		try {
			content = runGit(['cat-file', '-p', `${ref}:${filePath}`]);
		} catch {
			content = null;
		}
		cache.set(key, content);
		return content;
	};
}

async function main() {
	const strict =
		process.argv.includes('--strict') ||
		process.env.DOCS_STATUS_STRICT === '1' ||
		process.env.DOCS_STATUS_STRICT === 'true';
	const today = process.env.STATUS_TODAY?.trim() || todayIsoDate();

	const errors = validateManifest(FEATURES, SIBLING_ALLOWLIST, today);
	const { refs, pinError } = await resolveRefs();
	if (pinError) {
		if (strict) {
			errors.push(pinError);
		} else {
			console.warn(`[status-check] WARN: ${pinError}`);
		}
	}
	const readFileAtRef = makeGitFileReader();

	const allowlistById = new Map(SIBLING_ALLOWLIST.map((item) => [item.id, item]));
	const statuses = {};
	for (const entry of Object.values(FEATURES)) {
		const res = computeFeatureStatus(entry, refs, readFileAtRef, { strict, allowlistById });
		statuses[entry.id] = res.status;
		errors.push(...res.errors);
	}

	errors.push(...lintDocsTree(docsContentDir, FEATURES));

	const warnings = collectLongPlannedWarnings(FEATURES, statuses, today);
	for (const w of warnings) {
		console.warn(`[status-check] WARN: ${w}`);
	}

	if (errors.length > 0) {
		for (const err of errors) {
			console.error(`[status-check] ERROR: ${err}`);
		}
		process.exit(1);
	}

	const output = {
		generatedAt: new Date().toISOString(),
		strict,
		refs: {
			main: refs.main.ref,
			fleetPin: refs.fleetPin.ref,
			releaseTag: refs.releaseTag.ref,
		},
		features: statuses,
	};

	fs.writeFileSync(statusOutPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
	console.log(
		`[status-check] OK (${Object.keys(statuses).length} features, strict=${strict}) -> ${path.relative(repoRoot, statusOutPath)}`,
	);
}

main();
