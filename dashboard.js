/* Dashboard composition for egresstop. The headline panel is EGRESS
 * ALERTS — destinations that didn't match the allowlist. Below it,
 * CALLERS shows which processes are responsible. ALLOWED summarizes
 * the expected traffic. CONNECTION FEED shows the raw event stream. */

import {
  fg, bold, ital, RESET, EOL,
  C_AXIS, C_DIM, C_ALERT, C_FLAGGED, C_ALLOWED, C_TX, C_RX,
  formatBytes, formatBps, compactNum,
  fmtEndpoint, mmss, fmtDuration,
  vlen, clipAnsi, fixw,
  sparkline,
} from "./render.js";

import {
  tot,
  liveRates, listFlagged, listAllowed, listCallers, recentEvents, counts,
  aName, aAddr, startTime,
} from "./state.js";

const MIN_COLS = 80;
const MIN_ROWS = 28;

/* ---- chrome helpers ----------------------------------------------- */
function topRule(C, title, alerts) {
  const accent = alerts > 0 ? C_ALERT : C_ALLOWED;
  const head = ` ▌ ${title} `;
  return bold + fg(accent) + head + RESET + fg(C_AXIS) +
    "─".repeat(Math.max(0, C - head.length)) + RESET + EOL;
}
function botRule(C) { return fg(C_AXIS) + "─".repeat(C) + RESET + EOL; }
function sectionBar(C, text, accent = 45) {
  const prefix = fg(accent) + "  " + text + " ";
  const tail = fg(C_AXIS) + "─".repeat(Math.max(0, C - vlen(prefix))) + RESET;
  return clipAnsi(prefix + tail, C) + EOL;
}

/* ---- header ------------------------------------------------------- */
function headerLine(C) {
  const r = liveRates();
  const c = counts();
  const live = bold + fg(46) + "●" + RESET + fg(252) + " LIVE " + RESET;
  const up = fg(C_DIM) + mmss(Date.now() - startTime) + RESET;
  const active = fg(252) + compactNum(r.active) + RESET + fg(C_DIM) + " conn" + RESET;
  const totalBw = fg(C_TX) + "▲" + RESET + fg(252) + formatBps(r.total_tx_bps) + RESET +
                  fg(C_DIM) + " " + RESET +
                  fg(C_RX) + "▼" + RESET + fg(252) + formatBps(r.total_rx_bps) + RESET;
  const totBw = r.total_tx_bps + r.total_rx_bps;
  const flagBw = r.flagged_tx_bps + r.flagged_rx_bps;
  const pct = totBw > 0 ? Math.round((flagBw / totBw) * 100) : 0;
  const flagColor = pct >= 5 ? C_ALERT : flagBw > 0 ? C_FLAGGED : C_ALLOWED;
  const flagStr = fg(flagColor) + "⚠ " + pct + "% flagged" + RESET;
  const alertCount = c.flagged_endpoints > 0
    ? bold + fg(C_ALERT) + "🚨 " + c.flagged_endpoints + " alert" + (c.flagged_endpoints === 1 ? "" : "s") + RESET
    : fg(C_ALLOWED) + "✓ no alerts" + RESET;

  const SEP = fg(C_DIM) + "   " + RESET;
  const parts = [live + up, active, totalBw, flagStr, alertCount];
  let line = parts.join(SEP);
  if (vlen(line) > C) line = parts.join(" ");
  return clipAnsi(line, C) + EOL;
}

/* ---- EGRESS ALERTS panel ------------------------------------------ */
/* Line layout (chrome ≠ ENDP_W ≠ sparkW):
 *   " "(1) + "⚠"(1) + " "(1) + ENDP_W + " "(1) + pid(9) + " "(1)
 * + comm(commW) + " "(1) + tx(10) + " "(1) + rx(10) + " "(1)
 * + dur(8) + " "(1, before spark) = 46 + ENDP_W + commW + sparkW */
function panelFlagged(C, H) {
  const list = listFlagged(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no egress alerts — every connection matched the allowlist." + RESET];
  }
  const ENDP_W = Math.min(28, Math.max(20, Math.floor(C * 0.26)));
  const commW  = Math.min(14, Math.max(8, Math.floor(C * 0.10)));
  const showSpark = C >= 100;
  const sparkW = showSpark ? Math.max(8, C - 46 - ENDP_W - commW) : 0;

  /* Build a caller-key → caller map ONCE per render (not per-row).
   * For each flagged endpoint we use this to find which caller is
   * most responsible (heuristic: caller with the most TOTAL flagged
   * bytes among those touching this endpoint). */
  const callerByKey = new Map();
  for (const { c } of listCallers(1024)) {
    callerByKey.set(c.pid + "\x00" + c.comm, c);
  }

  const out = [];
  for (const item of list) {
    if (out.length >= H) break;
    const e = item.e;
    const mark = bold + fg(C_ALERT) + "⚠" + RESET;
    const endpoint = aAddr(fmtEndpoint(e.family, e.addr, e.port));
    const epCell = fixw(bold + fg(C_ALERT) + endpoint + RESET, ENDP_W);

    let topCaller = null, topBytes = -1;
    for (const k of e.callers) {
      const c = callerByKey.get(k);
      if (!c) continue;
      const bts = c.flagged_bytes_tx + c.flagged_bytes_rx;
      if (bts > topBytes) { topBytes = bts; topCaller = c; }
    }
    const pidStr  = topCaller
      ? fg(C_DIM) + ("pid " + topCaller.pid).padEnd(9) + RESET
      : fg(C_DIM) + "pid —     " + RESET;
    const commCell = fixw(fg(C_FLAGGED) + (topCaller ? aName(topCaller.comm) : "?") + RESET, commW);

    const tx = fg(C_TX) + "▲" + RESET + fixw(formatBps(item.tx_bps), 9);
    const rx = fg(C_RX) + "▼" + RESET + fixw(formatBps(item.rx_bps), 9);
    const dur = fg(C_DIM) + fixw(fmtDuration(Date.now() - e.first_seen), 8) + RESET;

    let spark = "";
    if (showSpark && sparkW >= 4) {
      spark = " " + sparkline(e.tx_rate_hist, sparkW, C_ALERT);
    }
    const line = " " + mark + " " + epCell + " " + pidStr + " " +
                 commCell + " " + tx + " " + rx + " " + dur + spark;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- CALLERS panel ------------------------------------------------ */
/* Line: " "(1) + mark(1) + " "(1) + commW + " "(1) + pid(9) + " "(1)
 *     + flaggedRate(11) + " "(1) + allowedRate(11) + " "(1)
 *     + ratio bar(barW + 2 wrappers) + " "(1) + sparkW
 * chrome (everything except commW, barW, sparkW) = 1+1+1+1+9+1+11+1+11+1+2+1 = 41 */
function panelCallers(C, H) {
  const list = listCallers(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no callers yet." + RESET];
  }
  const commW  = Math.min(16, Math.max(10, Math.floor(C * 0.14)));
  const showSpark = C >= 100;
  const barW = 10;
  const sparkW = showSpark ? Math.max(8, C - 41 - commW - barW) : 0;

  const out = [];
  for (const item of list) {
    if (out.length >= H) break;
    const c = item.c;
    const isFlagged = item.flagged_bytes > 0;
    const mark = isFlagged
      ? bold + fg(C_ALERT) + "⚠" + RESET
      : fg(C_ALLOWED) + "·" + RESET;
    const commCell = fixw((isFlagged ? fg(C_FLAGGED) : fg(252)) + aName(c.comm) + RESET, commW);
    const pidStr   = fg(C_DIM) + ("pid " + c.pid).padEnd(9) + RESET;
    const fRate = fg(C_ALERT) + "⚠" + RESET + fixw(formatBps(item.flagged_bps), 10);
    const aRate = fg(C_ALLOWED) + "✓" + RESET + fixw(formatBps(item.allowed_bps), 10);

    /* Ratio bar: red filled for flagged share, green for allowed share */
    const totBps = item.flagged_bps + item.allowed_bps;
    const flagFrac = totBps > 0 ? item.flagged_bps / totBps : 0;
    const redChars = Math.round(flagFrac * barW);
    const grnChars = barW - redChars;
    const bar = "[" + fg(C_ALERT) + "█".repeat(redChars) + RESET
                    + fg(C_ALLOWED) + "█".repeat(grnChars) + RESET + "]";

    let spark = "";
    if (showSpark && sparkW >= 4) {
      const color = isFlagged ? C_ALERT : C_ALLOWED;
      const hist = isFlagged ? c.flagged_tx_hist : c.allowed_tx_hist;
      spark = " " + sparkline(hist, sparkW, color);
    }
    const line = " " + mark + " " + commCell + " " + pidStr + " " +
                 fRate + " " + aRate + " " + bar + spark;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- ALLOWED panel (quieter) -------------------------------------- */
/* Line: " "(1) + "✓"(1) + " "(1) + ENDP_W + " "(1) + commentW
 *     + " "(1) + tx(10) + " "(1) + rx(10) + " "(1, before spark)
 * chrome = 1+1+1+1+1+10+1+10+1 = 27 + ENDP_W + commentW + sparkW */
function panelAllowed(C, H) {
  const list = listAllowed(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no allowed outbound yet." + RESET];
  }
  const ENDP_W = Math.min(26, Math.max(18, Math.floor(C * 0.24)));
  const commentW = Math.min(22, Math.max(12, Math.floor(C * 0.16)));
  const showSpark = C >= 100;
  const sparkW = showSpark ? Math.max(8, C - 27 - ENDP_W - commentW) : 0;

  const out = [];
  for (const item of list) {
    if (out.length >= H) break;
    const e = item.e;
    const mark = fg(C_ALLOWED) + "✓" + RESET;
    const endpoint = aAddr(fmtEndpoint(e.family, e.addr, e.port));
    const epCell = fixw(fg(C_ALLOWED) + endpoint + RESET, ENDP_W);
    const commentCell = fixw(fg(C_DIM) + (e.rule_comment || "—") + RESET, commentW);
    const tx = fg(C_TX) + "▲" + RESET + fixw(formatBps(item.tx_bps), 9);
    const rx = fg(C_RX) + "▼" + RESET + fixw(formatBps(item.rx_bps), 9);
    let spark = "";
    if (showSpark && sparkW >= 4) {
      spark = " " + sparkline(e.tx_rate_hist, sparkW, C_ALLOWED);
    }
    const line = " " + mark + " " + epCell + " " + commentCell + " " +
                 tx + " " + rx + spark;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- CONNECTION FEED ---------------------------------------------- */
function panelFeed(C, H) {
  const list = recentEvents(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no events yet…" + RESET];
  }
  const epW = Math.max(20, Math.min(28, Math.floor((C - 50) / 2)));
  const out = [];
  for (let i = 0; i < Math.min(H, list.length); i++) {
    const e = list[i];
    const ts = fg(C_DIM) + mmss(Math.max(0, e.ts - startTime)) + RESET;
    const color = e.flagged ? C_ALERT : C_ALLOWED;
    const mark = (e.flagged ? bold : "") + fg(color) + (e.flagged ? "⚠" : "·") + RESET;
    const local  = aAddr(fmtEndpoint(e.family, e.saddr, e.sport));
    const remote = aAddr(fmtEndpoint(e.family, e.daddr, e.dport));
    let middle;
    if (e.kind === "open") {
      middle = fg(color) + (e.flagged ? bold : "") + fixw("● OPEN", 8) + RESET + " " +
               fg(252) + fixw(local, epW) + RESET +
               fg(C_DIM) + " → " + RESET +
               fg(color) + fixw(remote, epW) + RESET;
    } else {
      const bytes = fg(C_DIM) + fixw(
        formatBytes(e.bytes_tx) + "/" + formatBytes(e.bytes_rx), 16) + RESET;
      middle = fg(C_DIM) + fixw("✕ CLOSE", 8) + RESET + " " +
               fg(252) + fixw(local, epW) + RESET +
               fg(C_DIM) + " → " + RESET +
               fg(248) + fixw(remote, epW) + RESET +
               " " + bytes;
    }
    const proc = (e.pid > 0)
      ? fg(C_DIM) + "  pid " + e.pid + " " + RESET + fg(248) + aName(e.comm) + RESET
      : "";
    const line = " " + ts + "  " + mark + " " + middle + proc;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- composition --------------------------------------------------- */
export function renderDashboard(C, R) {
  if (C < MIN_COLS || R < MIN_ROWS) return smallTerm(C, R);

  const c = counts();
  const hasAlerts = c.flagged_endpoints > 0;

  const rows = [];
  rows.push(topRule(C, "EGRESSTOP · outbound TCP watchdog · allowlist mode",
                    c.flagged_endpoints));
  rows.push(headerLine(C));
  rows.push("");

  /* Chrome accounting:
   *   top + header + blank        = 3
   *   alerts-title                = 1
   *   blank + callers-title       = 2
   *   blank + allowed-title       = 2
   *   blank + feed-title          = 2
   *   bottom-rule                 = 1
   *                          total chrome = 11
   */
  const content = R - 11;
  /* Give the EGRESS ALERTS panel prominence when alerts exist. */
  const alertH   = hasAlerts ? Math.max(4, Math.round(content * 0.28)) : Math.max(2, Math.round(content * 0.16));
  const callersH = Math.max(3, Math.round(content * 0.22));
  const allowedH = Math.max(3, Math.round(content * 0.22));
  const feedH    = Math.max(3, content - alertH - callersH - allowedH);

  const alertTitle = hasAlerts
    ? bold + fg(C_ALERT) + "EGRESS ALERTS · destinations not in allowlist" + RESET
    : fg(C_ALLOWED) + "EGRESS ALERTS · all quiet, every connection matched a rule" + RESET;
  rows.push(sectionBar(C, alertTitle, hasAlerts ? C_ALERT : C_ALLOWED));
  const fl = panelFlagged(C, alertH);
  for (let i = 0; i < alertH; i++) rows.push(fl[i] ?? " ".repeat(C));

  rows.push("");
  rows.push(sectionBar(C, "CALLERS · processes producing outbound (⚠ flagged · ✓ allowed)"));
  const cx = panelCallers(C, callersH);
  for (let i = 0; i < callersH; i++) rows.push(cx[i] ?? " ".repeat(C));

  rows.push("");
  rows.push(sectionBar(C, "ALLOWED · destinations matching allowlist · "
                          + formatBytes(tot.bytes_tx_total - tot.bytes_tx_flagged) + "↑ "
                          + formatBytes(tot.bytes_rx_total - tot.bytes_rx_flagged) + "↓ allowed bytes total"));
  const al = panelAllowed(C, allowedH);
  for (let i = 0; i < allowedH; i++) rows.push(al[i] ?? " ".repeat(C));

  rows.push("");
  rows.push(sectionBar(C, "CONNECTION FEED · opens and closes, newest first"));
  const fd = panelFeed(C, feedH);
  for (let i = 0; i < feedH; i++) rows.push(fd[i] ?? " ".repeat(C));

  rows.push(botRule(C));

  const trimmed = rows.slice(0, R).map(
    (l) => (l && (l.endsWith(EOL) || l.includes("\x1b[K"))) ? l : l + EOL);
  return clearScreen() + trimmed.join("\n");
}

export function clearScreen() { return "\x1b[H\x1b[2J"; }

function smallTerm(C, R) {
  const lines = [
    `egresstop: terminal too small`,
    `need ≥ ${MIN_COLS}×${MIN_ROWS}`,
    `have ${C}×${R}`,
  ];
  return lines.map((l) => l.slice(0, Math.max(1, C))).join("\n") + "\n";
}
