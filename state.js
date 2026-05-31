/* Application state + event ingest for egresstop.
 *
 * BPF emits three event kinds on one ringbuf:
 *   kind 0  OPEN   new connection observed
 *   kind 1  BYTES  periodic byte delta on a tracked connection
 *   kind 2  CLOSE  connection terminating
 *
 * The model tracks every connection, classifies it via the allowlist
 * at OPEN time, and aggregates traffic separately into two buckets:
 *   - flagged  (destination matches no rule → potential exfil/C2)
 *   - allowed  (destination matches a rule  → expected outbound)
 *
 * The dashboard surfaces flagged endpoints prominently; the allowed
 * path is summarized but quiet. */

import { matchAllowlist } from "./allowlist.js";

export const TICK_MS    = 200;
export const HIST_LEN   = 240;
const   CLOSE_FADE_MS   = 5_000;
const   CALLER_STALE_MS = 60_000;
const   ENDPOINT_STALE_MS = 60_000;
const   FEED_KEEP       = 200;

/* ---- global counters + history ------------------------------------ */
export const startTime = Date.now();
export const tot = {
  events: 0,
  opens: 0,
  closes: 0,
  bytes_tx_flagged: 0,    /* bytes flowing to non-allowlisted destinations */
  bytes_rx_flagged: 0,
  bytes_tx_total: 0,      /* across all connections                       */
  bytes_rx_total: 0,
  alerts: 0,              /* count of distinct flagged endpoints seen     */
};

let tickFlaggedTx = 0, tickFlaggedRx = 0;
let tickTotalTx   = 0, tickTotalRx   = 0;
let tickOpens     = 0;
export const flaggedTxHist = [];
export const flaggedRxHist = [];
export const totalTxHist   = [];
export const totalRxHist   = [];
export const opensHist     = [];
export const activeHist    = [];
function pushHist(arr, v) { arr.push(v); if (arr.length > HIST_LEN) arr.shift(); }

/* ---- anonymize ---------------------------------------------------- */
const anon = !!globalThis.yeet?.args?.anonymize;
const aliasMaps = { name: new Map(), addr: new Map() };
function aliasGen(kind, key, prefix) {
  const m = aliasMaps[kind];
  let a = m.get(key);
  if (!a) { a = prefix + String(m.size + 1).padStart(2, "0"); m.set(key, a); }
  return a;
}
export function aName(s) { return anon && s ? aliasGen("name", s, "proc-") : s; }
export function aAddr(s) { return anon && s ? aliasGen("addr", s, "host-") : s; }

/* ---- connection table --------------------------------------------- */
const conns = new Map();   /* sk_hex → ConnInfo */

/* ---- aggregators -------------------------------------------------- */
/* CallerStat: a process that has produced outbound TCP traffic. Keyed
 * by "pid\0comm" (NUL-separated so a colon in comm can never collide).
 * Tracks flagged vs allowed bytes separately so we can surface which
 * processes are responsible for unexpected outbound. */
const callers = new Map();
function callerKey(pid, comm) { return pid + "\x00" + comm; }

function getCaller(pid, comm) {
  const key = callerKey(pid, comm);
  let c = callers.get(key);
  if (!c) {
    c = {
      pid, comm,
      flagged_bytes_tx: 0, flagged_bytes_rx: 0,
      allowed_bytes_tx: 0, allowed_bytes_rx: 0,
      flagged_tx_hist: [], allowed_tx_hist: [],
      flagged_endpoints: new Set(),
      allowed_endpoints: new Set(),
      first_seen: Date.now(),
      last_seen:  Date.now(),
    };
    callers.set(key, c);
  }
  return c;
}

/* FlaggedEndpoint: a destination (addr+port) that did NOT match the
 * allowlist. These are the headline alerts. */
const flagged = new Map();

/* AllowedEndpoint: matched a rule. Tracked too (quietly) so we can
 * show what's flowing on the "expected" path. */
const allowed = new Map();

function endpointKey(family, daddr, dport) {
  let k = String(family) + ":";
  for (let i = 0; i < 16; i++) k += daddr[i].toString(16).padStart(2, "0");
  k += ":" + dport;
  return k;
}

function getFlaggedEndpoint(family, daddr, dport) {
  const k = endpointKey(family, daddr, dport);
  let e = flagged.get(k);
  if (!e) {
    const addrCopy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) addrCopy[i] = daddr[i] | 0;
    e = {
      key: k, family, addr: addrCopy, port: dport,
      bytes_tx: 0, bytes_rx: 0,
      tx_rate_hist: [], rx_rate_hist: [],
      callers: new Set(),
      conn_count: 0,
      first_seen: Date.now(),
      last_seen:  Date.now(),
    };
    flagged.set(k, e);
    tot.alerts++;
  }
  return e;
}

function getAllowedEndpoint(family, daddr, dport, rule) {
  const k = endpointKey(family, daddr, dport);
  let e = allowed.get(k);
  if (!e) {
    const addrCopy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) addrCopy[i] = daddr[i] | 0;
    e = {
      key: k, family, addr: addrCopy, port: dport,
      rule_comment: rule?.comment || "",
      bytes_tx: 0, bytes_rx: 0,
      tx_rate_hist: [], rx_rate_hist: [],
      callers: new Set(),
      conn_count: 0,
      first_seen: Date.now(),
      last_seen:  Date.now(),
    };
    allowed.set(k, e);
  }
  return e;
}

/* ---- live event feed ---------------------------------------------- */
const feed = [];
function pushFeed(rec) { feed.push(rec); if (feed.length > FEED_KEEP) feed.shift(); }

/* ---- decoders ----------------------------------------------------- */
function num(v) { return typeof v === "bigint" ? Number(v) : v; }
function bigKey(v) { return typeof v === "bigint" ? v.toString(16) : String(v); }
function bytesAsArray(b) {
  const out = new Uint8Array(16);
  if (!b) return out;
  for (let i = 0; i < 16; i++) out[i] = b[i] | 0;
  return out;
}

/* ---- ingest ------------------------------------------------------- */
export function onEvent(e) {
  if (!e) return;
  tot.events++;
  const kind  = num(e.kind) | 0;
  const now   = Date.now();
  const sk    = bigKey(e.sk);
  const family = num(e.family) | 0;
  const sport  = num(e.sport) & 0xffff;
  const dport  = num(e.dport) & 0xffff;
  const pid    = num(e.pid) | 0;
  const comm   = String(e.comm || "?");
  const saddr  = bytesAsArray(e.saddr);
  const daddr  = bytesAsArray(e.daddr);
  const bytes_tx = num(e.bytes_tx) || 0;
  const bytes_rx = num(e.bytes_rx) || 0;
  const delta_tx = num(e.delta_tx) || 0;
  const delta_rx = num(e.delta_rx) || 0;

  if (kind === 0) {
    tot.opens++; tickOpens++;
    let c = conns.get(sk);
    if (!c) {
      const m = matchAllowlist(family, daddr, dport);
      c = {
        sk, family, saddr, sport, daddr, dport,
        pid, comm,
        bytes_tx: 0, bytes_rx: 0,
        first_seen: now, last_active: now, closed: 0,
        flagged: !m.matched,
        rule: m.rule || null,
      };
      conns.set(sk, c);
    } else {
      /* duplicate OPEN — accept new attribution but preserve byte counters
       * and the original allowlist verdict (same destination → same verdict). */
      c.pid = pid; c.comm = comm; c.last_active = now;
    }

    /* register this caller against the right bucket */
    const cr = getCaller(c.pid, c.comm);
    cr.last_seen = now;
    if (c.flagged) {
      const ep = getFlaggedEndpoint(c.family, c.daddr, c.dport);
      ep.conn_count++; ep.last_seen = now;
      ep.callers.add(callerKey(c.pid, c.comm));
      cr.flagged_endpoints.add(ep.key);
    } else {
      const ep = getAllowedEndpoint(c.family, c.daddr, c.dport, c.rule);
      ep.conn_count++; ep.last_seen = now;
      ep.callers.add(callerKey(c.pid, c.comm));
      cr.allowed_endpoints.add(ep.key);
    }

    pushFeed({
      ts: now, kind: "open", sk,
      family: c.family,
      saddr: c.saddr, sport: c.sport,
      daddr: c.daddr, dport: c.dport,
      pid: c.pid, comm: c.comm,
      flagged: c.flagged,
      rule_comment: c.rule?.comment || "",
    });
    return;
  }

  if (kind === 1) {
    let c = conns.get(sk);
    if (!c) {
      /* missed OPEN (e.g. existed before egresstop started) — classify now */
      const m = matchAllowlist(family, daddr, dport);
      c = {
        sk, family, saddr, sport, daddr, dport,
        pid, comm,
        bytes_tx: 0, bytes_rx: 0,
        first_seen: now, last_active: now, closed: 0,
        flagged: !m.matched,
        rule: m.rule || null,
      };
      conns.set(sk, c);

      const cr = getCaller(c.pid, c.comm);
      cr.last_seen = now;
      if (c.flagged) {
        const ep = getFlaggedEndpoint(c.family, c.daddr, c.dport);
        ep.conn_count++; ep.last_seen = now;
        ep.callers.add(callerKey(c.pid, c.comm));
        cr.flagged_endpoints.add(ep.key);
      } else {
        const ep = getAllowedEndpoint(c.family, c.daddr, c.dport, c.rule);
        ep.conn_count++; ep.last_seen = now;
        ep.callers.add(callerKey(c.pid, c.comm));
        cr.allowed_endpoints.add(ep.key);
      }
    }
    c.bytes_tx += delta_tx;
    c.bytes_rx += delta_rx;
    c.last_active = now;

    tickTotalTx += delta_tx; tickTotalRx += delta_rx;
    tot.bytes_tx_total += delta_tx; tot.bytes_rx_total += delta_rx;

    const cr = getCaller(c.pid, c.comm); cr.last_seen = now;
    if (c.flagged) {
      tickFlaggedTx += delta_tx; tickFlaggedRx += delta_rx;
      tot.bytes_tx_flagged += delta_tx; tot.bytes_rx_flagged += delta_rx;
      cr.flagged_bytes_tx += delta_tx; cr.flagged_bytes_rx += delta_rx;
      const ep = getFlaggedEndpoint(c.family, c.daddr, c.dport);
      ep.bytes_tx += delta_tx; ep.bytes_rx += delta_rx; ep.last_seen = now;
    } else {
      cr.allowed_bytes_tx += delta_tx; cr.allowed_bytes_rx += delta_rx;
      const ep = getAllowedEndpoint(c.family, c.daddr, c.dport, c.rule);
      ep.bytes_tx += delta_tx; ep.bytes_rx += delta_rx; ep.last_seen = now;
    }
    return;
  }

  if (kind === 2) {
    let c = conns.get(sk);
    if (c) {
      tot.closes++;
      /* reconcile any bytes the kernel reported but JS missed
       * (e.g. ringbuf overflow or a final delta below the emit threshold). */
      const extraTx = Math.max(0, bytes_tx - c.bytes_tx);
      const extraRx = Math.max(0, bytes_rx - c.bytes_rx);
      if (extraTx + extraRx > 0) {
        c.bytes_tx += extraTx; c.bytes_rx += extraRx;
        tickTotalTx += extraTx; tickTotalRx += extraRx;
        tot.bytes_tx_total += extraTx; tot.bytes_rx_total += extraRx;
        const cr = getCaller(c.pid, c.comm); cr.last_seen = now;
        if (c.flagged) {
          tickFlaggedTx += extraTx; tickFlaggedRx += extraRx;
          tot.bytes_tx_flagged += extraTx; tot.bytes_rx_flagged += extraRx;
          cr.flagged_bytes_tx += extraTx; cr.flagged_bytes_rx += extraRx;
          const ep = getFlaggedEndpoint(c.family, c.daddr, c.dport);
          ep.bytes_tx += extraTx; ep.bytes_rx += extraRx; ep.last_seen = now;
        } else {
          cr.allowed_bytes_tx += extraTx; cr.allowed_bytes_rx += extraRx;
          const ep = getAllowedEndpoint(c.family, c.daddr, c.dport, c.rule);
          ep.bytes_tx += extraTx; ep.bytes_rx += extraRx; ep.last_seen = now;
        }
      }
      c.closed = now;
      pushFeed({
        ts: now, kind: "close", sk,
        family: c.family,
        saddr: c.saddr, sport: c.sport,
        daddr: c.daddr, dport: c.dport,
        pid: c.pid, comm: c.comm,
        bytes_tx: c.bytes_tx, bytes_rx: c.bytes_rx,
        flagged: c.flagged,
        rule_comment: c.rule?.comment || "",
        duration_ms: now - c.first_seen,
      });
    }
    return;
  }
}

/* ---- per-tick advance + reaping ----------------------------------- */
export function advance() {
  const now = Date.now();

  pushHist(flaggedTxHist, tickFlaggedTx); tickFlaggedTx = 0;
  pushHist(flaggedRxHist, tickFlaggedRx); tickFlaggedRx = 0;
  pushHist(totalTxHist,   tickTotalTx);   tickTotalTx   = 0;
  pushHist(totalRxHist,   tickTotalRx);   tickTotalRx   = 0;
  pushHist(opensHist,     tickOpens);     tickOpens     = 0;

  let active = 0;
  for (const c of conns.values()) if (!c.closed) active++;
  pushHist(activeHist, active);

  for (const c of callers.values()) {
    const lastFTx = c._lastFTx ?? c.flagged_bytes_tx;
    const lastATx = c._lastATx ?? c.allowed_bytes_tx;
    pushHist(c.flagged_tx_hist, c.flagged_bytes_tx - lastFTx);
    pushHist(c.allowed_tx_hist, c.allowed_bytes_tx - lastATx);
    c._lastFTx = c.flagged_bytes_tx; c._lastATx = c.allowed_bytes_tx;
  }
  for (const e of flagged.values()) {
    const lastTx = e._lastTx ?? e.bytes_tx;
    const lastRx = e._lastRx ?? e.bytes_rx;
    pushHist(e.tx_rate_hist, e.bytes_tx - lastTx);
    pushHist(e.rx_rate_hist, e.bytes_rx - lastRx);
    e._lastTx = e.bytes_tx; e._lastRx = e.bytes_rx;
  }
  for (const e of allowed.values()) {
    const lastTx = e._lastTx ?? e.bytes_tx;
    const lastRx = e._lastRx ?? e.bytes_rx;
    pushHist(e.tx_rate_hist, e.bytes_tx - lastTx);
    pushHist(e.rx_rate_hist, e.bytes_rx - lastRx);
    e._lastTx = e.bytes_tx; e._lastRx = e.bytes_rx;
  }

  /* reap */
  for (const [sk, c] of conns) {
    if (c.closed && now - c.closed > CLOSE_FADE_MS) conns.delete(sk);
  }
  for (const [k, c] of callers) if (now - c.last_seen > CALLER_STALE_MS)   callers.delete(k);
  for (const [k, e] of flagged) if (now - e.last_seen > ENDPOINT_STALE_MS) flagged.delete(k);
  for (const [k, e] of allowed) if (now - e.last_seen > ENDPOINT_STALE_MS) allowed.delete(k);

  while (feed.length && now - feed[0].ts > 60_000) feed.shift();
}

/* ---- accessors ---------------------------------------------------- */
const oneSecTicks = Math.max(1, Math.round(1000 / TICK_MS));
function sumTail(arr, n) {
  const start = Math.max(0, arr.length - n);
  let s = 0;
  for (let i = start; i < arr.length; i++) s += arr[i];
  return s;
}

export function liveRates() {
  return {
    total_tx_bps:   sumTail(totalTxHist,   oneSecTicks),
    total_rx_bps:   sumTail(totalRxHist,   oneSecTicks),
    flagged_tx_bps: sumTail(flaggedTxHist, oneSecTicks),
    flagged_rx_bps: sumTail(flaggedRxHist, oneSecTicks),
    active:         activeHist.length ? activeHist[activeHist.length - 1] : 0,
  };
}

/* List flagged endpoints sorted by current bandwidth (descending),
 * with bandwidth-zero endpoints sorted by recency. */
export function listFlagged(n) {
  const out = [];
  for (const e of flagged.values()) {
    const tx = sumTail(e.tx_rate_hist, oneSecTicks);
    const rx = sumTail(e.rx_rate_hist, oneSecTicks);
    out.push({ e, tx_bps: tx, rx_bps: rx, total: tx + rx });
  }
  out.sort((a, b) => {
    if (b.total !== a.total) return b.total - a.total;
    return b.e.bytes_tx + b.e.bytes_rx - (a.e.bytes_tx + a.e.bytes_rx);
  });
  return out.slice(0, n);
}

export function listAllowed(n) {
  const out = [];
  for (const e of allowed.values()) {
    const tx = sumTail(e.tx_rate_hist, oneSecTicks);
    const rx = sumTail(e.rx_rate_hist, oneSecTicks);
    out.push({ e, tx_bps: tx, rx_bps: rx, total: tx + rx });
  }
  out.sort((a, b) => b.total - a.total);
  return out.slice(0, n);
}

export function listCallers(n) {
  const out = [];
  for (const c of callers.values()) {
    const ftx = sumTail(c.flagged_tx_hist, oneSecTicks);
    const atx = sumTail(c.allowed_tx_hist, oneSecTicks);
    out.push({ c, flagged_bps: ftx, allowed_bps: atx, total: ftx + atx,
               flagged_bytes: c.flagged_bytes_tx + c.flagged_bytes_rx });
  }
  /* Sort: callers with any flagged traffic come first (descending by
   * flagged_bytes), then callers without flagged traffic by total
   * current bandwidth. Effect: anything making a flagged connection
   * bubbles to the top of the panel immediately. */
  out.sort((a, b) => {
    if ((a.flagged_bytes > 0) !== (b.flagged_bytes > 0))
      return b.flagged_bytes - a.flagged_bytes;
    return b.total - a.total;
  });
  return out.slice(0, n);
}

export function recentEvents(n) { return feed.slice(-n).reverse(); }

export function counts() {
  return {
    flagged_endpoints: flagged.size,
    allowed_endpoints: allowed.size,
    callers:           callers.size,
    alert_pids:        Array.from(callers.values()).filter(c => c.flagged_bytes_tx + c.flagged_bytes_rx > 0).length,
  };
}
