# egresstop

**Outbound TCP connection watchdog.** Set an allowlist. Anything that doesn't match shows up red in 200ms — with the PID, the comm, the destination, and the bytes.

```
$ sudo yeet run https://github.com/YOUR-USERNAME/egresstop
```

The supply-chain compromises of the last two years — `tj-actions/changed-files`, `xz-utils`, the npm waves — all share a shape: a compromised process makes outbound connections to a destination nobody on the team would have authorized if asked. **egresstop is what asks.** Every TCP connection your box opens is matched against an allowlist; anything that doesn't match goes to the top of the dashboard in red.

It's built on [**yeet**](https://yeet.cx), a Linux runtime that makes a kernel-side BPF program, a per-tick render loop, and a JS state model feel like one program.

<!-- Demo GIF: vhs assets/egresstop.tape on a Linux box with yeet
     installed, then add:
     ![egresstop](assets/egresstop.gif) -->

---

## What you actually see

```
 ▌ EGRESSTOP · outbound TCP watchdog · allowlist mode ─────────────────────────────────────────────────────────
● LIVE 00:34   12 conn   ▲60KB/s ▼180KB/s   ⚠ 25% flagged   🚨 2 alerts

  EGRESS ALERTS · destinations not in allowlist ──────────────────────────────────────────────────────────────
   ⚠ 185.220.101.45:443             pid 8842   curl              ▲8KB/s    ▼32KB/s   18s
   ⚠ 23.94.182.7:8080               pid 8842   curl              ▲4KB/s    ▼16KB/s   9s

  CALLERS · processes producing outbound (⚠ flagged · ✓ allowed) ─────────────────────────────────────────────
   ⚠ curl             pid 8842   ⚠12KB/s     ✓0B/s         [██████████]
   · git              pid 7100   ⚠0B/s       ✓30KB/s       [██████████]
   · npm              pid 7321   ⚠0B/s       ✓18KB/s       [██████████]

  ALLOWED · destinations matching allowlist · 1.2MB↑ 4.8MB↓ allowed bytes total ──────────────────────────────
   ✓ 140.82.114.4:443               github.com (api…   ▲30KB/s   ▼90KB/s
   ✓ 185.199.108.153:443            github.com (pa…   ▲18KB/s   ▼42KB/s
   ✓ 127.0.0.1:6379                 IPv4 loopback      ▲0B/s     ▼0B/s

  CONNECTION FEED · opens and closes, newest first ───────────────────────────────────────────────────────────
   00:34  ⚠ ● OPEN   10.0.0.12:54234         → 185.220.101.45:443             pid 8842 curl
   00:33  ⚠ ● OPEN   10.0.0.12:54233         → 23.94.182.7:8080               pid 8842 curl
   00:30  · ● OPEN   10.0.0.12:54232         → 140.82.114.4:443               pid 7100 git
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Top to bottom:

A **header strip** with the live system rates, the percentage of bytes flowing to flagged destinations, and the count of distinct flagged endpoints active right now.

**EGRESS ALERTS** — the headline. Every destination your box has reached that didn't match the allowlist. Sorted by current bandwidth, with the top responsible process called out. This panel goes red when alerts exist and turns green-titled when it's empty.

**CALLERS** — every process producing outbound TCP, with its flagged and allowed bandwidth side by side and a ratio bar so you can see at a glance how mixed its behavior is. A process pushing only to allowed destinations stays grey; the moment it makes a flagged connection it turns flagged-color and bubbles to the top.

**ALLOWED** — the quiet panel. Destinations matching the allowlist, with the rule's human-readable comment so you remember why each rule exists. Useful for confirming that legitimate traffic is being correctly classified.

**CONNECTION FEED** — every open and close, color-coded by allowlist verdict. The raw event log.

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
yeet run https://github.com/YOUR-USERNAME/egresstop
```

For a shareable screenshot, anonymize process names and remote addresses (everything identifying gets relabeled `proc-01`, `host-02`, …):

```sh
yeet run https://github.com/YOUR-USERNAME/egresstop -- --anonymize
```

Runs until `Ctrl-C`. Resize the terminal and the layout reflows; minimum 80×28.

## Editing the allowlist

The allowlist lives in [`allowlist.js`](allowlist.js) as a JavaScript array. The whole point of egresstop is that you tune this file to your environment — there is no "right" default. The shipped defaults are loopback, RFC1918 private networks, IPv6 link-local + ULA, DNS, NTP, and a snapshot of GitHub's published IP ranges.

Each rule has up to three fields:

```js
{ cidr: "10.0.0.0/8",     port: 22, comment: "internal ssh" }
{ cidr: "185.199.108.0/22",         comment: "github pages" }
{                         port: 53, comment: "DNS to anywhere" }
```

A rule matches a connection when **every field it specifies** matches. `cidr` matches the destination address; `port` matches the destination port; `comment` is for humans only. A rule with only `cidr` allows that subnet at any port. A rule with only `port` allows that port at any address. With both, it's a tight tuple.

CIDRs are matched in both directions: an IPv4 rule will also match an IPv4-mapped IPv6 destination (`::ffff:1.2.3.4`), which is what AF_INET6 sockets see when connecting to IPv4 hosts.

### Pre-built profiles

The shipped defaults are a developer-laptop profile. Two common patterns you might want instead:

**GitHub Actions self-hosted runner:** keep the defaults, then add the IP ranges your jobs need — npm registry, PyPI mirror, container registry. As you observe legitimate-looking flagged traffic in the CONNECTION FEED, add rules for it. Within a few job runs your allowlist is fitted to what your CI actually does.

**Lockdown / canary box:** delete everything except loopback and DNS:

```js
export const RULES = [
  { cidr: "127.0.0.0/8", comment: "IPv4 loopback" },
  { cidr: "::1/128",     comment: "IPv6 loopback" },
  { port: 53,            comment: "DNS" },
];
```

Now any outbound connection to a non-loopback destination on a non-DNS port lights up red. Useful for detecting *anything* trying to phone home.

## What's under the hood

Three BPF programs feed one ring buffer:

| BPF program        | hook                            | what it does                                                |
|--------------------|---------------------------------|-------------------------------------------------------------|
| `on_set_state`     | `tp_btf/inet_sock_set_state`    | track new conns at `TCP_ESTABLISHED`, reap at `TCP_CLOSE`   |
| `on_sendmsg`       | `fentry/tcp_sendmsg`            | count tx bytes; fix pid to the real sender (app ctx)        |
| `on_cleanup_rbuf`  | `fentry/tcp_cleanup_rbuf`       | count rx bytes; fix pid to the real receiver (app ctx)      |

One `HASH` map (`conns`, keyed by sock pointer) stores per-connection state. One `RINGBUF` (256 KiB) carries three event kinds to JS:

- `OPEN` — new connection observed, after we know who owns it
- `BYTES` — periodic delta, emitted every 64 KiB transferred in either direction
- `CLOSE` — connection terminating, with the final cumulative byte counts

The kernel side knows nothing about the allowlist — it just streams every TCP connection. **All allowlist matching happens in userspace**, in `allowlist.js`. This means you can edit rules and restart without rebuilding the BPF object.

- `main.js` — entry: tty size, render loop, BPF bind/subscribe
- `state.js` — connection model + flagged/allowed split
- `allowlist.js` — **the rules database + CIDR matcher**
- `render.js` — ANSI, color ramps, byte/port/address formatters
- `dashboard.js` — panels + layout (`renderDashboard`)

## Requirements

- Linux ≥ 5.5 (for `fentry` and `tp_btf`); Debian 13, Ubuntu 22.04+, Fedora 36+, recent Arch all fine
- Kernel BTF: `CONFIG_DEBUG_INFO_BTF=y`, default on current Arch, Fedora, Ubuntu, and Debian 12+
- `CAP_BPF` + `CAP_PERFMON` (typically root)
- `clang` and `bpftool` to build the BPF object — `yeet run` does this for you on first launch

## Build it from a clone

```sh
git clone https://github.com/YOUR-USERNAME/egresstop
cd egresstop
make                       # builds bin/egresstop.bpf.o
sudo yeet run main.js      # run from source
```

## Trying it locally

The fastest demo: run egresstop, then have a separate shell hit an arbitrary external host:

```sh
# in one shell
sudo yeet run main.js

# in another
curl https://example.com/                  # → flagged, example.com isn't in defaults
curl https://api.github.com/zen            # → allowed, github IP range
ssh -p 22 user@some-public-host.com        # → flagged unless you add the host
```

The flagged connections appear in the EGRESS ALERTS panel within ~200 ms. The allowed ones land in ALLOWED. Now you have a real, immediate picture of what your box is talking to vs what you've expected it to.

## Caveats — read these

egresstop is honest about its surface area. A few things it deliberately does *not* do:

- **It only sees direct TCP destinations.** Proxied traffic (HTTP CONNECT proxies, SOCKS, anything tunneled) appears as a connection to the proxy, not to the real destination. If you're using a corporate proxy, the only destination egresstop sees is the proxy itself. The same applies to mesh VPNs (Tailscale, Wireguard): tunneled traffic looks like UDP to the mesh peer.
- **It can't catch CDN-fronted services by IP.** npm, PyPI, Cargo, and most public APIs sit behind CDNs (Cloudflare, Fastly, AWS CloudFront) with rotating IPs. You can't write a stable IP-based rule for "the npm registry." The honest workaround: observe legitimate traffic, see what IPs your registry actually resolves to in *your* network, and add those IPs.
- **It's TCP-only.** UDP traffic (DNS over UDP/53 is the obvious one, plus QUIC/HTTP3 over UDP/443) is not observed. The port-53 allowlist rule covers DNS only insofar as DNS happens over TCP (rare). DNS-over-UDP and QUIC are invisible.
- **It can't read TCP payloads.** Egresstop doesn't do SNI sniffing, HTTP host header inspection, or TLS fingerprinting. The destination is judged purely by IP and port — never by what the application is actually saying.
- **Process attribution is best-effort.** Same model as the rest of the family. TCP state transitions can fire from softirq context where `current` is `swapper` or a `kworker`. We refuse those as the real owner and let `tcp_sendmsg` / `tcp_cleanup_rbuf` (always app context) update us with the true PID. Attribution converges within microseconds for any process that actually does I/O.
- **Connections created before egresstop starts are invisible** until they next transition state. No kernel walk on startup. Restart egresstop in a long-lived job and you'll see the existing connections appear gradually as bytes flow.

## Differences from sibling tools

- **vs `bytetop`** — same BPF surface; bytetop is bandwidth accounting, egresstop is policy enforcement (read-only). bytetop says *how much*, egresstop says *should this be happening at all*.
- **vs `minertop`** — minertop checks every connection against a hardcoded list of mining pool ports. egresstop checks every connection against a user-tunable allowlist. The allowlist file *is* the program's configuration surface.
- **vs `soltop`** — soltop classifies destinations by Solana port. egresstop classifies them by user-defined rules. Same kernel, different lens.

---

Built on [yeet](https://yeet.cx). yeet is a Linux runtime for writing eBPF programs and live system dashboards in JavaScript.
