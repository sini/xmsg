import fs from 'node:fs';
import path from 'node:path';

export const LONG_PLANNED_DAYS = 60;

export const UNCONVERTED_LEGACY_FILES = new Set([]);

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const SHA40_RE = /^[0-9a-f]{40}$/i;

export function extractXmsgRevFromFlakeLock(flakeLock) {
	const locked = flakeLock?.nodes?.xmsg?.locked;
	if (!locked || typeof locked !== 'object') {
		throw new Error('nix-config flake.lock is missing nodes.xmsg.locked');
	}
	if (locked.owner !== 'sini' || locked.repo !== 'xmsg') {
		throw new Error(
			`nix-config flake.lock nodes.xmsg.locked has unexpected owner/repo: ${locked.owner}/${locked.repo}`,
		);
	}
	if (typeof locked.rev !== 'string' || !SHA40_RE.test(locked.rev)) {
		throw new Error(`nix-config flake.lock nodes.xmsg.locked.rev is invalid: ${locked.rev}`);
	}
	return locked.rev;
}

export function resolveFleetPinRev({ envOverride, fetchedRev, fetchError }) {
	if (envOverride) {
		return { rev: envOverride, source: 'env', error: null };
	}
	if (fetchError || !fetchedRev) {
		return {
			rev: null,
			source: 'fetch-failed',
			error:
				fetchError ||
				'Failed to fetch xmsg locked.rev from nix-config flake.lock',
		};
	}
	return { rev: fetchedRev, source: 'nix-config', error: null };
}

export function todayIsoDate(now = new Date()) {
	return now.toISOString().slice(0, 10);
}

export function validateManifest(features, allowlist, today = todayIsoDate()) {
	const errors = [];

	if (!features || typeof features !== 'object') {
		errors.push('Manifest FEATURES must be a non-null object.');
		return errors;
	}

	for (const [key, entry] of Object.entries(features)) {
		if (!entry || typeof entry !== 'object') {
			errors.push(`Feature '${key}' must be an object.`);
			continue;
		}
		if (entry.id !== key) {
			errors.push(`Feature '${key}' has mismatched id '${entry.id}'.`);
		}
		if (typeof entry.id !== 'string' || !entry.id.trim()) {
			errors.push(`Feature '${key}' is missing a non-empty id.`);
		}
		if (typeof entry.title !== 'string' || !entry.title.trim()) {
			errors.push(`Feature '${key}' is missing a non-empty title.`);
		}
		if (typeof entry.owner !== 'string' || !entry.owner.trim()) {
			errors.push(`Feature '${key}' is missing a non-empty owner.`);
		}
		if (!Array.isArray(entry.evidence)) {
			errors.push(`Feature '${key}' evidence must be an array.`);
		} else {
			for (const [idx, item] of entry.evidence.entries()) {
				if (!item || typeof item.path !== 'string' || !item.path.trim()) {
					errors.push(`Feature '${key}' evidence[${idx}] is missing a non-empty path.`);
				}
				if (!item || typeof item.anchor !== 'string' || !item.anchor.trim()) {
					errors.push(`Feature '${key}' evidence[${idx}] is missing a non-empty anchor.`);
				}
			}
		}
		if (entry.plannedSince !== undefined) {
			if (typeof entry.plannedSince !== 'string' || !ISO_DATE_RE.test(entry.plannedSince)) {
				errors.push(`Feature '${key}' plannedSince must be YYYY-MM-DD.`);
			}
		}
	}

	if (!Array.isArray(allowlist)) {
		errors.push('Manifest SIBLING_ALLOWLIST must be an array.');
		return errors;
	}

	for (const [idx, item] of allowlist.entries()) {
		if (!item || typeof item !== 'object') {
			errors.push(`Allowlist[${idx}] must be an object.`);
			continue;
		}
		for (const field of ['id', 'repo', 'owner', 'expiry', 'reason']) {
			if (typeof item[field] !== 'string' || !item[field].trim()) {
				errors.push(`Allowlist[${idx}] is missing a non-empty '${field}'.`);
			}
		}
		if (typeof item.expiry === 'string' && ISO_DATE_RE.test(item.expiry)) {
			if (item.expiry < today) {
				errors.push(
					`Expired sibling allowlist entry '${item.id}' (${item.repo}, owner ${item.owner}, expired ${item.expiry} < ${today}).`,
				);
			}
		} else if (typeof item.expiry === 'string') {
			errors.push(`Allowlist '${item.id}' expiry '${item.expiry}' must be YYYY-MM-DD.`);
		}
	}

	return errors;
}

export function checkEvidenceAtRef(evidence, ref, readFileAtRef) {
	if (evidence.length === 0) {
		return false;
	}
	for (const item of evidence) {
		const content = readFileAtRef(ref, item.path);
		if (content === null || !content.includes(item.anchor)) {
			return false;
		}
	}
	return true;
}

export function computeFeatureStatus(entry, refs, readFileAtRef, { strict = false } = {}) {
	const errors = [];

	function evalFact(refState, label) {
		if (refState.noReleaseTags) {
			return false;
		}
		if (!refState.ref) {
			if (strict) {
				errors.push(`Cannot resolve ${label} ref in strict mode for feature '${entry.id}'.`);
			}
			return 'unknown';
		}
		return checkEvidenceAtRef(entry.evidence, refState.ref, readFileAtRef);
	}

	const onMain = evalFact(refs.main, 'main');
	const inFleetPin = evalFact(refs.fleetPin, 'fleet pin');
	const released = evalFact(refs.releaseTag, 'release tag');

	return {
		status: {
			id: entry.id,
			title: entry.title,
			owner: entry.owner,
			note: entry.note ?? null,
			onMain,
			inFleetPin,
			released,
		},
		errors,
	};
}

export function collectLongPlannedWarnings(
	features,
	statuses,
	today = todayIsoDate(),
	maxDays = LONG_PLANNED_DAYS,
) {
	const warnings = [];
	const todayMs = Date.parse(`${today}T00:00:00Z`);
	for (const [id, entry] of Object.entries(features)) {
		const st = statuses[id];
		if (!st) continue;
		if (st.onMain === false && st.inFleetPin === false && st.released === false && entry.plannedSince) {
			const sinceMs = Date.parse(`${entry.plannedSince}T00:00:00Z`);
			const ageDays = Math.floor((todayMs - sinceMs) / 86400000);
			if (ageDays > maxDays) {
				warnings.push(
					`Feature '${id}' (owner ${entry.owner}) has been plannedSince ${entry.plannedSince} (${ageDays} days > ${maxDays} days).`,
				);
			}
		}
	}
	return warnings;
}

function walkDocsFiles(dir, baseDir = dir, out = []) {
	if (!fs.existsSync(dir)) return out;
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			walkDocsFiles(full, baseDir, out);
		} else if (entry.isFile() && (entry.name.endsWith('.md') || entry.name.endsWith('.mdx'))) {
			out.push({
				fullPath: full,
				relPath: path.relative(baseDir, full).replaceAll(path.sep, '/'),
			});
		}
	}
	return out;
}

function stripCodeBlocks(content) {
	return content.replace(/```[\s\S]*?```/g, '').replace(/`[^`\n]*`/g, '');
}

const STATUS_TAG_RE = /<Status\b[^>]*\bid\s*=\s*(?:"([^"]+)"|'([^']+)')[^>]*\/?>/g;
const ASIDE_TITLE_RE = /<Aside\b[^>]*\btitle\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>/gi;
const MARKER_PATTERNS = [
	{ name: 'paren-planned', re: /\(\s*planned\s*\)/i },
	{ name: 'planned-not-yet-released', re: /planned,\s*not yet released/i },
	{ name: 'bold-planned', re: /\*\*planned:?\*\*/i },
];

export function lintDocsFile(relPath, content, features, { checkFreeText = true } = {}) {
	const errors = [];
	const stripped = stripCodeBlocks(content);

	for (const match of stripped.matchAll(STATUS_TAG_RE)) {
		const id = match[1] ?? match[2];
		if (!features[id]) {
			errors.push(`${relPath}: <Status id="${id}" /> references unknown feature id '${id}'.`);
		}
	}

	if (!checkFreeText) {
		return errors;
	}

	for (const match of stripped.matchAll(ASIDE_TITLE_RE)) {
		const title = match[1] ?? match[2] ?? '';
		if (/\bplanned\b|not yet released/i.test(title)) {
			errors.push(
				`${relPath}: <Aside title="${title}"> contains free-text status marker; use <Status id="..." /> instead.`,
			);
		}
	}

	const lines = stripped.split('\n');
	for (let i = 0; i < lines.length; i += 1) {
		const line = lines[i];
		for (const pattern of MARKER_PATTERNS) {
			if (pattern.re.test(line)) {
				errors.push(
					`${relPath}:${i + 1}: free-text status marker (${pattern.name}) found; use <Status id="..." /> instead.`,
				);
			}
		}
	}

	return errors;
}

export function lintDocsTree(docsContentDir, features, unconvertedAllowlist = UNCONVERTED_LEGACY_FILES) {
	const errors = [];
	const files = walkDocsFiles(docsContentDir);
	for (const { fullPath, relPath } of files) {
		const content = fs.readFileSync(fullPath, 'utf8');
		const checkFreeText = !unconvertedAllowlist.has(relPath);
		errors.push(...lintDocsFile(relPath, content, features, { checkFreeText }));
	}
	return errors;
}
