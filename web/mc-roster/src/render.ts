import {
  activityGlyph,
  formatAgeMs,
  plainReason,
  RosterStore,
  sortEndpoints,
} from "./projection.ts";
import type { EndpointEntry, NodeView } from "./protocol.ts";

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export interface RenderCallbacks {
  onSelectNode: (nodeName: string | null) => void;
  onReconnect: () => void;
}

export class RosterRenderer {
  private readonly liveRoot: HTMLElement;
  private readonly ssrRoot: HTMLElement | null;
  private readonly liveRegion: HTMLElement;
  private announceTimer: number | null = null;

  constructor(liveRoot: HTMLElement, ssrRoot: HTMLElement | null) {
    this.liveRoot = liveRoot;
    this.ssrRoot = ssrRoot;
    this.liveRegion = el("div", "mc-sr-only");
    this.liveRegion.setAttribute("aria-live", "polite");
    this.liveRegion.setAttribute("aria-atomic", "true");
    this.liveRoot.parentElement?.appendChild(this.liveRegion);
  }

  render(store: RosterStore, nowClientMs: number, cb: RenderCallbacks): void {
    const fleetSub = store.subs.get("fleet");
    const hasSynced = Boolean(fleetSub?.synced);

    if (store.stoppedAuth) {
      // Terminal re-authenticate: clear both SSR fallback and JS state immediately.
      if (this.ssrRoot) this.ssrRoot.replaceChildren();
    } else if (hasSynced && this.ssrRoot) {
      // WebSocket snapshot final received: replace SSR fallback.
      this.ssrRoot.replaceChildren();
    }

    const frag = document.createDocumentFragment();
    const badge = store.connectionBadge(nowClientMs);
    const serverNow = store.nowServerMs(nowClientMs);

    // Connection banner
    const banner = el("div", "mc-banner");
    banner.setAttribute("data-connection-badge", badge);

    const statusPill = el("span", `mc-pill mc-pill-${badge.toLowerCase()}`, badge);
    banner.appendChild(statusPill);

    const ageText =
      store.lastRealEventAtMs > 0
        ? `last event ${formatAgeMs(nowClientMs - store.lastRealEventAtMs)} ago`
        : "no event yet";
    banner.appendChild(el("span", "mc-muted", ageText));

    if (store.stoppedIncompatible) {
      banner.appendChild(el("span", "mc-error", "client incompatible"));
    } else if (store.stoppedAuth) {
      banner.appendChild(el("span", "mc-error", "Session expired or revoked."));
      const reauth = el("a", "mc-btn", "Re-authenticate");
      reauth.setAttribute("href", "/login");
      banner.appendChild(reauth);
    } else if (store.defectMessage) {
      banner.appendChild(el("span", "mc-error", `client defect: ${store.defectMessage}`));
    } else if (badge === "Stale") {
      const retryBtn = el("button", "mc-btn", "Reconnect");
      retryBtn.setAttribute("type", "button");
      retryBtn.addEventListener("click", cb.onReconnect);
      banner.appendChild(retryBtn);
    }

    // Truthful coverage / empty-fleet badges
    const allNodes = store.nodeOrder.map((n) => store.nodes.get(n)).filter((n): n is NodeView => Boolean(n));
    const hasEligible = allNodes.some(
      (n) =>
        n.status !== "removed_retained" &&
        n.status !== "loading" &&
        n.status !== "denied" &&
        n.status !== "unsupported_outbound_only" &&
        n.status !== "unsupported_transport",
    );
    if (store.fleetTruncated) {
      banner.appendChild(el("span", "mc-warn", "coverage: truncated"));
    } else if (hasSynced && allNodes.length === 0) {
      banner.appendChild(el("span", "mc-muted", "empty fleet (0 nodes)"));
    } else if (hasSynced && !hasEligible) {
      banner.appendChild(el("span", "mc-warn", "coverage: empty (no eligible nodes)"));
    }
    frag.appendChild(banner);

    // Roster body (suppressed when stoppedAuth)
    if (!store.stoppedAuth && hasSynced) {
      if (allNodes.length === 0) {
        frag.appendChild(el("p", "mc-empty", "No nodes configured in scope."));
      } else {
        for (const nv of allNodes) {
          frag.appendChild(this.renderNodeSection(store, nv, serverNow, cb));
        }
      }

      if (store.selectedNode) {
        const detailNode = store.nodes.get(store.selectedNode);
        if (detailNode) {
          frag.appendChild(this.renderDetail(store, detailNode, serverNow, cb));
        }
      }
    }

    this.liveRoot.replaceChildren(frag);
    this.flushAnnouncements(store);
  }

  private renderNodeSection(
    store: RosterStore,
    nv: NodeView,
    serverNowMs: number,
    cb: RenderCallbacks,
  ): HTMLElement {
    const sec = el("section", "mc-node");
    sec.setAttribute("data-node", nv.node);

    const unreachable = store.isNodeUnreachable(nv.node);
    const displayStatus = unreachable ? "unreachable" : nv.status;
    const nodeStale = nv.status === "stale" || unreachable;

    const header = el("div", "mc-node-header");
    header.appendChild(el("h2", "mc-node-name", nv.node));
    header.appendChild(el("span", `mc-tag mc-status-${displayStatus}`, displayStatus));
    header.appendChild(el("span", `mc-tag mc-delivery-${nv.delivery}`, nv.delivery));
    if (nv.via_hub) header.appendChild(el("span", "mc-muted", `via ${nv.via_hub}`));
    if (nv.activity_authority) {
      header.appendChild(el("span", "mc-muted", `activity: ${nv.activity_authority}`));
    }
    if (nv.last_source_at !== undefined) {
      header.appendChild(el("span", "mc-muted", `source ${formatAgeMs(serverNowMs - nv.last_source_at)} ago`));
    }
    if (nv.endpoints_truncated) {
      header.appendChild(el("span", "mc-warn", "endpoints truncated"));
    }
    if (nv.source_gaps.length > 0) {
      const gapText = nv.source_gaps.map((g) => g.reason).join(", ");
      header.appendChild(el("span", "mc-warn", `gaps: ${gapText}`));
    }

    if (nv.status !== "removed_retained") {
      const detailBtn = el("button", "mc-btn mc-btn-small", store.selectedNode === nv.node ? "Close detail" : "Node detail");
      detailBtn.setAttribute("type", "button");
      detailBtn.addEventListener("click", () => cb.onSelectNode(store.selectedNode === nv.node ? null : nv.node));
      header.appendChild(detailBtn);
    }
    sec.appendChild(header);

    if (nv.status === "removed_retained") {
      const msg =
        nv.last_activity_at !== undefined
          ? `Removed (retained; last activity ${formatAgeMs(serverNowMs - nv.last_activity_at)} ago)`
          : "Removed (retained)";
      sec.appendChild(el("p", "mc-muted", msg));
      return sec;
    }

    if (nv.history_hidden) {
      sec.appendChild(el("p", "mc-muted", "History masked by node policy."));
      return sec;
    }

    if (nv.endpoints.length === 0) {
      sec.appendChild(el("p", "mc-muted", "No active endpoints."));
      return sec;
    }

    const sorted = sortEndpoints(nv.endpoints, nodeStale);
    const showEvidenceCol = sorted.some((ep) => {
      if (!ep.activity) return false;
      return Math.abs(ep.activity.fresh_at - ep.activity.changed_at) > 60;
    });

    const table = el("table", "mc-table");
    const thead = el("thead");
    const headRow = el("tr");
    const cols = ["Agent", "Harness", "Activity", "Changed"];
    if (showEvidenceCol) cols.push("Evidence");
    cols.push("Manage");
    for (const c of cols) {
      const th = el("th", undefined, c);
      th.setAttribute("scope", "col");
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = el("tbody");
    for (const ep of sorted) {
      tbody.appendChild(this.renderEndpointRow(ep, nodeStale, showEvidenceCol, serverNowMs));
    }
    table.appendChild(tbody);
    sec.appendChild(table);
    return sec;
  }

  private renderEndpointRow(
    ep: EndpointEntry,
    nodeStale: boolean,
    showEvidenceCol: boolean,
    serverNowMs: number,
  ): HTMLTableRowElement {
    const stale = nodeStale || ep.activity_stale === true;
    const tr = el("tr", stale ? "mc-row mc-row-stale" : "mc-row");
    tr.setAttribute("tabindex", "0");
    tr.setAttribute("data-endpoint", ep.descriptor.id);

    // Agent: descriptor.label + descriptor.id
    const agentTd = el("td");
    if (ep.descriptor.label) {
      agentTd.appendChild(el("span", "mc-agent-label", ep.descriptor.label));
      agentTd.appendChild(el("span", "mc-mono mc-muted", ` (${ep.descriptor.id})`));
    } else {
      agentTd.appendChild(el("span", "mc-mono", ep.descriptor.id));
    }
    if (ep.descriptor.context) {
      const ctx = ep.descriptor.context;
      const parts = [ctx.repo, ctx.branch, ctx.worktree, ctx.task, ctx.pr].filter(Boolean);
      if (parts.length > 0) {
        agentTd.appendChild(el("div", "mc-context mc-muted", parts.join(" · ")));
      }
    }
    tr.appendChild(agentTd);

    // Harness
    tr.appendChild(el("td", "mc-mono", ep.descriptor.harness));

    // Activity: glyph + state label + plain reason + stale tag
    const actTd = el("td");
    const g = activityGlyph(ep.activity, ep.descriptor.kind);
    actTd.appendChild(el("span", "mc-glyph", g.glyph));
    actTd.appendChild(el("span", "mc-act-label", ` ${g.label}`));
    if (ep.activity?.reason) {
      actTd.appendChild(el("span", "mc-muted", ` — ${plainReason(ep.activity.reason)}`));
    }
    if (stale) {
      actTd.appendChild(el("span", "mc-tag mc-tag-stale", "stale"));
    }
    tr.appendChild(actTd);

    // Changed (Unix seconds * 1000)
    const changedText = ep.activity ? formatAgeMs(serverNowMs - ep.activity.changed_at * 1000) : "—";
    tr.appendChild(el("td", "mc-mono", changedText));

    // Evidence (only when |fresh_at - changed_at| > 60s)
    if (showEvidenceCol) {
      const evText = ep.activity ? formatAgeMs(serverNowMs - ep.activity.fresh_at * 1000) : "—";
      tr.appendChild(el("td", "mc-mono", evText));
    }

    // Manage: one-line disabled reason in roster
    tr.appendChild(el("td", "mc-muted", "Disabled: inspect-only rollout"));
    return tr;
  }

  private renderDetail(
    store: RosterStore,
    nv: NodeView,
    serverNowMs: number,
    cb: RenderCallbacks,
  ): HTMLElement {
    const panel = el("aside", "mc-detail");
    panel.setAttribute("data-detail-node", nv.node);

    const head = el("div", "mc-detail-head");
    head.appendChild(el("h3", undefined, `Node detail: ${nv.node}`));
    const closeBtn = el("button", "mc-btn mc-btn-small", "Close");
    closeBtn.setAttribute("type", "button");
    closeBtn.addEventListener("click", () => cb.onSelectNode(null));
    head.appendChild(closeBtn);
    panel.appendChild(head);

    // Single disabled Manage control (inspect-only rollout)
    const manageBox = el("div", "mc-manage-box");
    const manageBtn = el("button", "mc-btn", "Manage");
    manageBtn.setAttribute("type", "button");
    manageBtn.disabled = true;
    manageBtn.setAttribute("aria-disabled", "true");
    manageBox.appendChild(manageBtn);
    manageBox.appendChild(el("span", "mc-muted", "Disabled: inspect-only rollout"));
    panel.appendChild(manageBox);

    if (nv.history_hidden) {
      panel.appendChild(el("p", "mc-muted", "History masked."));
      return panel;
    }

    const unreachable = store.isNodeUnreachable(nv.node);
    const sorted = sortEndpoints(nv.endpoints, nv.status === "stale" || unreachable);
    const table = el("table", "mc-table");
    const thead = el("thead");
    const hr = el("tr");
    for (const c of ["Agent", "Harness", "Activity", "Wire reason", "Changed", "Evidence"]) {
      const th = el("th", undefined, c);
      th.setAttribute("scope", "col");
      hr.appendChild(th);
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = el("tbody");
    for (const ep of sorted) {
      const tr = el("tr");
      tr.appendChild(el("td", "mc-mono", ep.descriptor.label ? `${ep.descriptor.label} (${ep.descriptor.id})` : ep.descriptor.id));
      tr.appendChild(el("td", "mc-mono", ep.descriptor.harness));
      const g = activityGlyph(ep.activity, ep.descriptor.kind);
      tr.appendChild(el("td", undefined, `${g.glyph} ${g.label}${ep.activity?.reason ? ` — ${plainReason(ep.activity.reason)}` : ""}`));
      tr.appendChild(el("td", "mc-mono", ep.activity?.reason ?? "—"));
      tr.appendChild(el("td", "mc-mono", ep.activity ? formatAgeMs(serverNowMs - ep.activity.changed_at * 1000) : "—"));
      tr.appendChild(el("td", "mc-mono", ep.activity ? formatAgeMs(serverNowMs - ep.activity.fresh_at * 1000) : "—"));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    panel.appendChild(table);

    if (nv.exchanges.length > 0) {
      panel.appendChild(el("h4", undefined, `Recent exchanges (${nv.exchanges.length})`));
      const ul = el("ul", "mc-exchanges");
      for (const ex of nv.exchanges.slice(-10)) {
        const line = `${ex.event.kind}: ${ex.event.from ?? "?"} -> ${ex.event.to ?? "?"} (${ex.event.available})`;
        ul.appendChild(el("li", "mc-mono", line));
      }
      panel.appendChild(ul);
    }
    return panel;
  }

  private flushAnnouncements(store: RosterStore): void {
    if (store.pendingAnnouncements.length === 0) return;
    if (this.announceTimer !== null) return;
    this.announceTimer = window.setTimeout(() => {
      this.announceTimer = null;
      const items = store.pendingAnnouncements.splice(0, store.pendingAnnouncements.length);
      if (items.length > 0) {
        this.liveRegion.textContent = items.join("; ");
      }
    }, 2000);
  }
}
