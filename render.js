/* Pure rendering toolkit for egresstop: ANSI escapes, color ramps,
 * byte/port/address formatters. No application state, no allowlist
 * logic — the policy lives in allowlist.js. */

export const ESC = "\x1b[";
export const RESET = `${ESC}0m`;
export const EOL = `${ESC}K`;
export const bold = `${ESC}1m`;
export const dim = `${ESC}2m`;
export const ital = `${ESC}3m`;
export const fg = (n) => `${ESC}38;5;${n}m`;
export const bg = (n) => `${ESC}48;5;${n}m`;

export const SILENT_BG = 234;
export const EIGHTH = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/* role colors */
export const C_AXIS    = 238;
export const C_DIM     = 240;
export const C_ALERT   = 196;    /* flagged outbound — red, attention */
export const C_FLAGGED = 202;    /* row tint for flagged endpoints    */
export const C_ALLOWED = 84;     /* allowed (in allowlist) — green    */
export const C_NORMAL  = 244;
export const C_TX      = 51;
export const C_RX      = 215;

/* ---- byte / rate formatters ---------------------------------------- */
const KB = 1024, MB = 1024 * 1024, GB = 1024 * 1024 * 1024, TB = 1024 * GB;
export function formatBytes(n) {
  if (!isFinite(n) || n < 0) return "—";
  if (n >= TB) return (n / TB).toFixed(n >= 10 * TB ? 0 : 1) + "TB";
  if (n >= GB) return (n / GB).toFixed(n >= 10 * GB ? 0 : 1) + "GB";
  if (n >= MB) return (n / MB).toFixed(n >= 10 * MB ? 0 : 1) + "MB";
  if (n >= KB) return (n / KB).toFixed(n >= 10 * KB ? 0 : 1) + "KB";
  return Math.round(n) + "B";
}
export function formatBps(bps) { return formatBytes(bps) + "/s"; }
export function compactNum(n) {
  if (!isFinite(n)) return "—";
  if (n >= 1e9) return (n / 1e9).toFixed(n >= 1e10 ? 0 : 1) + "G";
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(0) + "k";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(Math.round(n));
}

/* ---- address formatters (with the ::-collapse bugfix incorporated) - */
export function fmtIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}
export function fmtIPv6(bytes) {
  const g = new Array(8);
  for (let i = 0; i < 8; i++) g[i] = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0xffff) {
    return `::ffff:${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }
  let bs = -1, bl = 0, cs = -1, cl = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (cs === -1) { cs = i; cl = 1; } else cl++;
      if (cl > bl) { bs = cs; bl = cl; }
    } else { cs = -1; cl = 0; }
  }
  if (bl < 2) { bs = -1; bl = 0; }
  const parts = [];
  for (let i = 0; i < 8; ) {
    if (i === bs) { parts.push(""); i += bl; continue; }
    parts.push(g[i].toString(16));
    i++;
  }
  let s = parts.join(":");
  if (bs === 0) s = ":" + s;
  if (bs + bl === 8 && bs >= 0) s = s + ":";
  return s;
}
export function fmtAddr(family, bytes) {
  return family === 10 ? fmtIPv6(bytes) : fmtIPv4(bytes);
}
export function fmtEndpoint(family, bytes, port) {
  const addr = fmtAddr(family, bytes);
  return family === 10 ? `[${addr}]:${port}` : `${addr}:${port}`;
}

/* ---- time formatters ---------------------------------------------- */
export function mmss(ms) {
  const t = Math.floor(ms / 1000);
  const h = Math.floor(t / 3600);
  const m = Math.floor((t % 3600) / 60);
  const s = t % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${p(h)}:${p(m)}:${p(s)}` : `${p(m)}:${p(s)}`;
}
export function fmtDuration(ms) {
  if (!isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return Math.round(ms) + "ms";
  const s = Math.round(ms / 1000);
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m " + (s % 60) + "s";
  const h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}

/* ---- visible-length-aware string ops ------------------------------ */
export function vlen(s) {
  return String(s).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").length;
}
export function clipAnsi(s, n) {
  let out = "", vis = 0, i = 0;
  while (i < s.length) {
    if (s[i] === "\x1b") {
      const m = /^\x1b\[[0-9;?]*[A-Za-z]/.exec(s.slice(i));
      if (m) { out += m[0]; i += m[0].length; continue; }
    }
    if (vis >= n) break;
    out += s[i]; vis++; i++;
  }
  return out + RESET;
}
export function fixw(s, w) {
  const v = vlen(s);
  if (v < w) s = s + " ".repeat(w - v);
  return clipAnsi(s, w);
}

/* ---- sparkline ---------------------------------------------------- */
export function sparkline(hist, w, color = C_TX) {
  if (w <= 0 || hist.length === 0) return " ".repeat(Math.max(0, w));
  const vis = Math.min(w, hist.length);
  const start = hist.length - vis;
  let max = 0;
  for (let i = start; i < hist.length; i++) if (hist[i] > max) max = hist[i];
  let out = "";
  for (let i = 0; i < w - vis; i++) out += " ";
  if (max === 0) {
    for (let i = 0; i < vis; i++) out += fg(C_AXIS) + EIGHTH[0] + RESET;
  } else {
    for (let i = 0; i < vis; i++) {
      const v = hist[start + i] / max;
      const idx = Math.max(1, Math.min(8, Math.round(v * 8)));
      out += fg(color) + EIGHTH[idx] + RESET;
    }
  }
  return out;
}
