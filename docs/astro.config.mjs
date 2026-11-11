// @ts-check
import { fileURLToPath } from 'node:url';
import { defineConfig, fontProviders } from 'astro/config';
import starlight from '@astrojs/starlight';

import mermaid from 'astro-mermaid';
import starlightLinksValidator from 'starlight-links-validator';
import { unified } from '@astrojs/markdown-remark';
import { codeImport } from 'remark-code-import';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import { wholeTokenTextMarkers } from './src/ec-whole-token-markers.mjs';

// The repository root, one level above docs/. Code fences cite Rust and Nix
// sources relative to it, which live outside the Astro project.
const repoRoot = fileURLToPath(new URL('..', import.meta.url));

const codeImportPlugin = /** @type {import('@astrojs/markdown-remark').RemarkPlugin} */ (
	/** @type {unknown} */ (codeImport)
);

// https://astro.build/config
export default defineConfig({
	site: 'https://xmsg.json64.dev',
	markdown: {
		processor: unified({
			remarkPlugins: [
				[codeImportPlugin, { rootDir: repoRoot, allowImportingFromOutside: true, removeRedundantIndentations: true }],
				remarkMath,
			],
			rehypePlugins: [rehypeKatex],
		}),
	},
	fonts: [
		{
			provider: fontProviders.google(),
			name: "Victor Mono",
			cssVariable: "--font-victor-mono",
			weights: [400, 600, 700],
			styles: ["normal", "italic"],
		},
		{
			provider: fontProviders.google(),
			name: "JetBrains Mono",
			cssVariable: "--font-jetbrains-mono",
			weights: [400, 600],
			styles: ["normal", "italic"],
		},
	],
	integrations: [
		mermaid({
			theme: 'base',
			autoTheme: false,
			mermaidConfig: {
				themeCSS: [
					'.node rect, .node circle, .node ellipse, .node polygon, .node path {',
					'  fill: color-mix(in srgb, var(--sl-color-accent) 12%, var(--sl-color-bg)) !important;',
					'  stroke: color-mix(in srgb, var(--sl-color-accent) 55%, transparent) !important;',
					'}',
					'.node .label, .nodeLabel, .node text { color: var(--sl-color-white) !important; fill: var(--sl-color-white) !important; }',
					'.edgePath .path, .flowchart-link, .messageLine0, .messageLine1 { stroke: var(--sl-color-gray-3) !important; }',
					'.arrowheadPath, marker path, defs marker path { fill: var(--sl-color-gray-3) !important; stroke: none !important; }',
					'.edgeLabel, .edgeLabel p { background: var(--sl-color-bg) !important; color: var(--sl-color-gray-2) !important; fill: var(--sl-color-bg) !important; }',
					'.edgeLabel .label text, .edgeLabel text { fill: var(--sl-color-gray-2) !important; }',
					'.cluster rect { fill: color-mix(in srgb, var(--sl-color-accent) 5%, var(--sl-color-bg)) !important; stroke: var(--sl-color-hairline-light) !important; }',
					'.cluster text, .cluster .label { fill: var(--sl-color-gray-2) !important; color: var(--sl-color-gray-2) !important; }',
				].join('\n'),
			},
		}),
		starlight({
			title: 'xmsg',
			expressiveCode: {
				plugins: [wholeTokenTextMarkers()],
			},
			plugins: [
				starlightLinksValidator({
					errorOnRelativeLinks: false,
					errorOnLocalLinks: false,
				}),
			],
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/sini/xmsg' }
			],
			sidebar: [
				{
					label: 'xmsg',
					items: [
						{ label: 'Overview', slug: 'overview' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Addressing & Resolution', slug: 'concepts/addressing' },
						{ label: 'Sessions, Services & Subagents', slug: 'concepts/sessions-services-subagents' },
						{ label: 'Delivery, Queueing & Replies', slug: 'concepts/replies' },
						{ label: 'Federation', slug: 'concepts/federation' },
						{ label: 'Hubs, Leaves & Gateways', slug: 'concepts/hubs-and-leaves' },
						{ label: 'Security & Trust Model', slug: 'concepts/trust-model' },
					],
				},
				{
					label: 'Harness Integration',
					items: [
						{ label: 'Claude Code', slug: 'harnesses/claude-code' },
						{ label: 'Codex', slug: 'harnesses/codex' },
						{ label: 'Antigravity', slug: 'harnesses/antigravity' },
						{ label: 'opencode', slug: 'harnesses/opencode' },
						{ label: 'Hermes', slug: 'harnesses/hermes' },
						{ label: 'Pi', slug: 'harnesses/pi' },
					],
				},
				{
					label: 'CLI & API Reference',
					items: [
						{ label: 'CLI & MCP Server', slug: 'reference/cli-and-mcp' },
						{ label: 'HTTP API & Unix Sockets', slug: 'reference/http-and-sockets' },
						{ label: 'Daemon Protocol & Rust Client', slug: 'reference/service-client' },
					],
				},
				{
					label: 'Operations & Platforms',
					items: [
						{ label: 'NixOS & Home Manager', slug: 'operations/nixos-and-home-manager' },
						{ label: 'Runtime, Reloading & Systemd', slug: 'operations/runtime-and-systemd' },
						{ label: 'OCI & Docker', slug: 'operations/docker' },
						{ label: 'Kubernetes & Helm', slug: 'operations/helm-and-kubernetes' },
						{ label: 'macOS', slug: 'getting-started/macos' },
						{ label: 'Arch Linux', slug: 'getting-started/arch' },
						{ label: 'Ubuntu', slug: 'getting-started/ubuntu' },
						{ label: 'Fedora', slug: 'getting-started/fedora' },
					],
				},
			],
			components: {
				Head: './src/components/Head.astro',
				Footer: './src/components/Footer.astro',
				ThemeProvider: './src/components/ThemeProvider.astro',
				ThemeSelect: './src/components/ThemeSelect.astro',
			},
			editLink: {
				baseUrl: 'https://github.com/sini/xmsg/edit/main/docs/',
			},
			customCss: [
				'katex/dist/katex.min.css',
				'./src/styles/layout.css',
				'./src/styles/custom.css'
			],
		}),
	],
});
