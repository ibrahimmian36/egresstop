/* Allowlist for egresstop.
 *
 * This file is intentionally the ONLY thing you need to edit to
 * customize what's considered "expected" outbound traffic on your box.
 * Don't touch state.js / dashboard.js / render.js — change RULES.
 *
 * Each rule is matched against every observed outbound TCP connection.
 * A rule MATCHES a connection when every field it specifies matches
 * the connection. Fields:
 *
 *   cidr   — IPv4 or IPv6 CIDR (e.g. "10.0.0.0/8", "2606:50c0::/32")
 *   port   — destination port number
 *   comment — human-readable note (not used for matching)
 *
 * A rule with only `cidr` matches that subnet at any port.
 * A rule with only `port` matches that port at any address.
 * A rule with both is a tight (subnet, port) tuple.
 *
 * Order doesn't matter — any matching rule allows the connection.
 *
 * The defaults below are tuned for a developer laptop / general-
 * purpose Linux box: loopback, RFC1918 internal networks, DNS, NTP,
 * and the published GitHub IP ranges. Anything else gets flagged.
 *
 * For a GitHub Actions self-hosted runner, the same defaults are a
 * good starting point — you may want to add IP ranges for your
 * package registries (npm/pypi/cargo) once you've observed them.
 * For a hardened "lockdown" profile, remove the GitHub ranges and
 * keep only loopback + DNS. */

export const RULES = [
  /* loopback — never alert on these */
  { cidr: "127.0.0.0/8",      comment: "IPv4 loopback" },
  { cidr: "::1/128",          comment: "IPv6 loopback" },

  /* RFC1918 private networks — internal traffic */
  { cidr: "10.0.0.0/8",       comment: "RFC1918 private" },
  { cidr: "172.16.0.0/12",    comment: "RFC1918 private" },
  { cidr: "192.168.0.0/16",   comment: "RFC1918 private" },

  /* IPv6 internal-use ranges */
  { cidr: "fe80::/10",        comment: "IPv6 link-local" },
  { cidr: "fc00::/7",         comment: "IPv6 unique local (ULA)" },

  /* common system-level ports — DNS and time sync go anywhere */
  { port: 53,                 comment: "DNS (any address)" },
  { port: 123,                comment: "NTP (any address)" },

  /* GitHub.com IP ranges — published at https://api.github.com/meta
   * (snapshot, refresh periodically as GH rotates ranges). */
  { cidr: "140.82.112.0/20",  comment: "github.com (api, web, git)" },
  { cidr: "143.55.64.0/20",   comment: "github.com" },
  { cidr: "185.199.108.0/22", comment: "github.com (pages, raw)" },
  { cidr: "192.30.252.0/22",  comment: "github.com (legacy)" },
  { cidr: "2a0a:a440::/29",   comment: "github.com (IPv6)" },
  { cidr: "2606:50c0::/32",   comment: "github.com pages (IPv6)" },
];

/* ---- CIDR parsing -------------------------------------------------- */
/* A compiled rule is { addr16: Uint8Array(16), prefix: number, port?: number,
 * family: 4 | 6, comment: string }. addr16 is always 16 bytes — for IPv4
 * rules the first 12 bytes are zero and the IPv4 octets sit in
 * positions 12..15 (IPv4-mapped form). This lets one matcher handle
 * both families uniformly. */

function parseIPv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseIPv6(s) {
  /* split off zone if present (e.g. fe80::1%eth0) */
  const noZone = s.split("%")[0];
  const parts = noZone.split("::");
  if (parts.length > 2) return null;

  function parseGroup(g) {
    if (g === "") return null;
    if (g.includes(".")) {
      /* embedded IPv4 — e.g. ::ffff:1.2.3.4 last 32 bits */
      const v4 = parseIPv4(g);
      if (!v4) return null;
      const buf = new Uint8Array(4);
      for (let i = 0; i < 4; i++) buf[i] = v4[i];
      return { bytes: buf, isV4: true };
    }
    const n = parseInt(g, 16);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff || !/^[0-9a-fA-F]+$/.test(g))
      return null;
    return { bytes: new Uint8Array([(n >> 8) & 0xff, n & 0xff]), isV4: false };
  }

  let head = [], tail = [];
  if (parts[0] !== "") {
    for (const g of parts[0].split(":")) {
      const p = parseGroup(g);
      if (!p) return null;
      head.push(p.bytes);
    }
  }
  if (parts.length === 2 && parts[1] !== "") {
    for (const g of parts[1].split(":")) {
      const p = parseGroup(g);
      if (!p) return null;
      tail.push(p.bytes);
    }
  }
  const headLen = head.reduce((s, b) => s + b.length, 0);
  const tailLen = tail.reduce((s, b) => s + b.length, 0);
  if (headLen + tailLen > 16) return null;
  if (parts.length === 1 && headLen + tailLen !== 16) return null;

  const out = new Uint8Array(16);
  let i = 0;
  for (const b of head) { for (const x of b) out[i++] = x; }
  i = 16 - tailLen;
  for (const b of tail) { for (const x of b) out[i++] = x; }
  return out;
}

export function compileRule(rule) {
  const out = { comment: rule.comment || "", port: null, addr16: null, prefix: null, family: null };
  if (rule.port !== undefined && rule.port !== null) {
    if (!Number.isInteger(rule.port) || rule.port < 0 || rule.port > 65535)
      throw new Error("rule.port out of range: " + rule.port);
    out.port = rule.port;
  }
  if (rule.cidr) {
    const [a, p] = rule.cidr.split("/");
    if (p === undefined) throw new Error("rule.cidr missing prefix: " + rule.cidr);
    const prefix = Number(p);
    if (!Number.isInteger(prefix) || prefix < 0) throw new Error("bad prefix: " + rule.cidr);

    const v4 = parseIPv4(a);
    if (v4) {
      if (prefix > 32) throw new Error("v4 prefix > 32: " + rule.cidr);
      out.addr16 = new Uint8Array(16);
      for (let i = 0; i < 4; i++) out.addr16[12 + i] = v4[i];
      out.prefix = 96 + prefix;     /* shift into IPv4-mapped space */
      out.family = 4;
    } else {
      const v6 = parseIPv6(a);
      if (!v6) throw new Error("bad CIDR address: " + rule.cidr);
      if (prefix > 128) throw new Error("v6 prefix > 128: " + rule.cidr);
      out.addr16 = v6;
      out.prefix = prefix;
      out.family = 6;
    }
  }
  if (out.port === null && out.addr16 === null)
    throw new Error("rule has neither cidr nor port: " + JSON.stringify(rule));
  return out;
}

/* Compile rules once at module load. Throws if any rule is malformed —
 * deliberate, surfaces errors immediately rather than at first match. */
export const COMPILED = RULES.map(compileRule);

/* ---- matching ----------------------------------------------------- */
/* Compare prefix bits of two 16-byte addresses. */
function prefixMatches(a, b, prefix) {
  const fullBytes = prefix >>> 3;
  const tailBits  = prefix & 7;
  for (let i = 0; i < fullBytes; i++) {
    if (a[i] !== b[i]) return false;
  }
  if (tailBits === 0) return true;
  const mask = (0xff << (8 - tailBits)) & 0xff;
  return (a[fullBytes] & mask) === (b[fullBytes] & mask);
}

/* Normalize an event's destination into the same 16-byte form rules
 * compile to. Two cases collapse into one:
 *
 *  - family=AF_INET: daddr[0..3] are the IPv4 octets, [4..15] are zero
 *    (BPF zero-fills before copying). We place the octets at [12..15]
 *    to match the IPv4-mapped form rules compile to.
 *
 *  - family=AF_INET6 with IPv4-mapped form (::ffff:a.b.c.d) — common
 *    when an AF_INET6 socket connects to an IPv4 destination. We strip
 *    the 0xff 0xff marker so the bytes match an IPv4 rule.
 *
 *  - family=AF_INET6 with a real IPv6 address: pass through unchanged. */
function normalizeAddr(family, addrBytes) {
  if (family === 10) {
    /* IPv4-mapped IPv6 detection: first 10 bytes zero, [10..11] = 0xff 0xff */
    if (addrBytes[10] === 0xff && addrBytes[11] === 0xff &&
        addrBytes[0] === 0 && addrBytes[1] === 0 && addrBytes[2] === 0 &&
        addrBytes[3] === 0 && addrBytes[4] === 0 && addrBytes[5] === 0 &&
        addrBytes[6] === 0 && addrBytes[7] === 0 && addrBytes[8] === 0 &&
        addrBytes[9] === 0) {
      const out = new Uint8Array(16);
      for (let i = 0; i < 4; i++) out[12 + i] = addrBytes[12 + i] | 0;
      return out;
    }
    return addrBytes;
  }
  /* family === AF_INET — promote IPv4 octets to IPv4-mapped form. */
  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i++) out[12 + i] = addrBytes[i] | 0;
  return out;
}

/* Match a connection against the compiled allowlist.
 * Returns { matched: true, rule: <rule> } or { matched: false }. */
export function matchAllowlist(family, daddr, dport) {
  const target = normalizeAddr(family, daddr);
  for (const r of COMPILED) {
    if (r.port !== null && r.port !== dport) continue;
    if (r.addr16 !== null) {
      if (!prefixMatches(r.addr16, target, r.prefix)) continue;
    }
    return { matched: true, rule: r };
  }
  return { matched: false };
}

/* For tests / introspection */
export function compiledRulesCount() { return COMPILED.length; }
