# Webpage Journey — Design

Date: 2026-08-20
Status: Approved, ready for implementation planning

## Purpose

Two teaching artifacts already exist at `~/Projects`:

- `webpage_journey_osi.py` — a terminal tool that opens real sockets and narrates DNS,
  TCP, TLS, and HTTP for a given host, tagging each step with its OSI layer.
- `webpage-journey.html` — a self-contained interactive walkthrough of the same journey,
  with live DNS-over-HTTPS lookups and a clickable OSI panel.

They work, but each stops short. The script cannot see below the socket API, so it
declares layers 1 and 2 unobservable. The page cannot see TCP or TLS at all, so its most
technical steps stay illustrative. Neither follows redirects, negotiates HTTP/2, reads a
certificate chain, or measures a network path.

This design makes the pair equally good at two jobs: **diagnosing a real host** and
**explaining every result in OSI terms**. A shared trace document is the mechanism — the
script measures what only a real socket can measure, and the page renders it.

## Audience and destination

For DevOps learners and for the author's own diagnostic use, weighted equally. Every
measurement is paired with what it means and what to do when it is wrong.

The pair stays standalone for now. It should remain cheap to move into the
`~/Projects/Learning` Learning Hub later, which forbids all external network requests, so
the page's live-lookup code sits behind a single feature constant.

## Non-goals

- Packet capture or protocol fuzzing. This traces one host politely.
- A hosted service, build system, or bundler. The HTML stays a single self-contained file.
- Comparing two hosts side by side. Considered and cut.
- A third "expert" content tier in the page. Two levels (Simple / Technical) is enough.

## Architecture

### File layout

```
webpage-journey/
  webpage-journey.html          # the teaching page, single self-contained file
  trace.py                      # CLI entry point:  python3 trace.py example.com
  wj/
    __init__.py
    schema.py                   # trace document construction, version constant, validation
    capabilities.py             # libs / system tools / privilege detection, auto-install
    render.py                   # all rich terminal output, including the OSI finale
    collect/
      __init__.py
      local.py                  # L1/L2: interface, MTU, MAC, gateway, DHCP, NAT
      dns.py                    # records, TTLs, resolver, delegation walk, DNSSEC
      tcp.py                    # Happy Eyeballs, per-IP connect timing, TCP_INFO
      tls.py                    # ALPN, full chain, trust root, resumption
      http.py                   # redirect chain, HTTP/2-3, decoding, security grading
      path.py                   # traceroute, ASN per hop, path MTU
  tests/
    fixtures/                   # captured command output, DER certs, golden traces
    test_*.py
  README.md
```

`~/Projects/webpage_journey.py` (the superseded 18 KB predecessor of
`webpage_journey_osi.py`) is deleted. `webpage_journey_osi.py` and `webpage-journey.html`
move into this directory as `trace.py` (split across `wj/`) and `webpage-journey.html`.

Rationale for splitting the script: it is ~600 lines today and this design roughly doubles
it. Each collector answers one question and returns one schema section, so each is
independently testable, and the HTML never needs to know they exist.

A git repository is initialised in `webpage-journey/` so each implementation task can be
committed and rolled back. A dedicated virtualenv lives at `webpage-journey/.venv`.

### The trace contract

One versioned JSON document is the only coupling between the two files.

```json
{
  "schema": "webpage-journey-trace/1",
  "generated_at": "2026-08-20T09:31:02Z",
  "tool": { "name": "trace.py", "version": "2.0.0" },
  "target": { "input": "https://example.com/dashboard", "host": "example.com",
              "scheme": "https", "port": 443, "path": "/dashboard" },
  "capabilities": { "privileged": false, "tools": ["dig", "traceroute"],
                    "libs": { "cryptography": true, "h2": true, "aioquic": false },
                    "installed_during_run": ["cryptography"] },
  "redacted": true,
  "local":   { "observed": true, "...": "..." },
  "dns":     { "observed": true, "...": "..." },
  "tcp":     { "observed": true, "...": "..." },
  "tls":     { "observed": true, "...": "..." },
  "http":    { "observed": true, "...": "..." },
  "path":    { "observed": false, "why_not": "traceroute not on PATH" },
  "timings": { "...": "..." },
  "osi":     { "l1": {}, "l2": {}, "l3": {}, "l4": {}, "l5": {}, "l6": {}, "l7": {} },
  "notes":   [ { "severity": "warn", "section": "tls", "text": "..." } ]
}
```

**The rule that governs everything: every field is either measured or absent.** Each
section carries `observed`, and a `why_not` string whenever `observed` is false. This
promotes the current script's refusal to invent plausible-looking values into the data
model itself.

`schema` is checked on import. An unknown major version is refused rather than
mis-rendered.

### Three data states

The page renders every fact in one of three states, and shows which:

| State | Source | Badge |
|---|---|---|
| **measured** | an imported trace document | ● |
| **live** | what browser JS can genuinely fetch: DNS-over-HTTPS, IP geolocation | ◐ |
| **illustrative** | the page's own teaching examples | ○ |

Precedence per field is measured → live → illustrative. Illustrative content lives only in
the HTML and never enters a trace document. A fourth display state, **redacted at export**,
is distinct from "not observed" so a hidden MAC address is never confused with a missing
one.

## Python: the diagnostic engine

### Capability detection

`capabilities.py` probes three tiers at startup and records the result in the trace, so
every `why_not` is explainable:

1. **Importable libraries** — `cryptography`, `httpx`/`h2`, `dnspython`, `rich`.
2. **System tools** via `shutil.which` — `dig`, `traceroute`/`tracepath`, `openssl`,
   `ip`/`ifconfig`, `route`, `arp`, `ipconfig`, `ethtool`/`wdutil`.
3. **Privilege** — `os.geteuid()`, plus `sudo -n true` to detect whether passwordless
   escalation is even possible.

### Dependency auto-install

Missing optional libraries install themselves via `sys.executable -m pip install`, with a
venv guardrail:

- Inside a virtualenv (`sys.prefix != sys.base_prefix`): install quietly, print one line
  per package naming why it is wanted.
- Against a system interpreter: prompt once; on decline or failure, fall back to `--user`,
  and if that also fails, degrade with a note.
- `--offline` skips the bootstrap entirely and degrades.

Packages installed during the run are recorded in `capabilities.installed_during_run`.

### Collectors

**`local.py` — layers 1 and 2, currently declared unobservable.**
Route lookup for the target IP (`route -n get <ip>` on macOS, `ip route get <ip>` on Linux)
yields the egress interface. From there: link type, MTU, negotiated rate and RSSI where the
OS still exposes it, the local MAC, the default gateway, and **the gateway's MAC from the
ARP table** — the concrete demonstration that frames bound for a remote server are
addressed at L2 to the local router. Plus the DHCP lease (`ipconfig getpacket en0` on
macOS) showing which resolver was handed out, and local IP versus public IP to make NAT
visible.

**`dns.py` — layer 7 riding on 4 and 3.**
All record types with real TTLs: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `CAA`, and
`HTTPS`/`SVCB` — the last revealing advertised HTTP/3 support and Encrypted Client Hello
configuration. Which recursive resolver was actually used (`scutil --dns` on macOS,
`/etc/resolv.conf` on Linux), including split-DNS and VPN cases. The DNSSEC AD bit
(`secure` / `insecure` / `bogus`). A real root → TLD → authoritative delegation walk,
performed with dnspython so it works without `dig`. Reverse PTR for the resolved address. A
second timed query demonstrating resolver cache-hit latency.

**`tcp.py` — layer 4.**
Happy Eyeballs per RFC 8305: race IPv6 and IPv4 concurrently, report both connect times and
which won. Connect timing to every resolved address, exposing anycast and CDN spread. Then
kernel-level truth via `TCP_INFO` (Linux) / `TCP_CONNECTION_INFO` (macOS): smoothed RTT,
MSS, retransmit counts. Local ephemeral port and address as today.

**`path.py` — layer 3.**
Traceroute via the system tool when present, else a privileged raw-socket TTL walk, else
skipped with `why_not`. Each hop annotated with reverse DNS, RTT, and **ASN via Team Cymru's
DNS interface** (`<reversed-ip>.origin.asn.cymru.com` TXT) — no API key, and it yields the
real AS path from ISP through transit to the CDN. Path MTU discovery via DF-bit probes when
privileged. Destination geolocation by default; `--geo-hops` geolocates every hop.

**`tls.py` — layers 6 and 5.**
ALPN offered and negotiated. Full certificate chain via `SSLSocket.get_unverified_chain()`,
falling back to `openssl s_client -showcerts`, falling back to the leaf alone. Each
certificate parsed with `cryptography`: subject, issuer, validity, key type and size,
signature algorithm, SANs, Certificate Transparency SCTs, OCSP and AIA URLs — through to
which root CA in the local trust store is the reason the chain is trusted. Cross-checked
against the CAA record from the DNS step. Under `--deep`: session resumption timing and a
TLS 1.0/1.1 downgrade probe.

**`http.py` — layer 7.**
The redirect chain followed and recorded hop by hop, up to 10 hops, with per-hop status,
`Location`, protocol, and timing. HTTP/2 via `h2`/`httpx` when available; HTTP/3
advertisement detected from `Alt-Svc` and the HTTPS RR. Correct chunked and gzip/brotli
decoding, so wire bytes, decoded bytes, and compression ratio are all real — today's "body
size received" counts framing overhead and is misleading. CDN cache state from
`cf-cache-status` / `x-cache` / `x-served-by` / `Age`. A security-header grade covering
HSTS and preload, CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
COOP/COEP, and `Set-Cookie` flags, reported as a grade plus a plain list of what is missing.
Under `--deep`: a conditional-request replay with `If-None-Match` to produce a real `304`.

### Probe etiquette

All of the above targets a single host with a handful of requests. Three probes constitute
mild active scanning — the TLS downgrade probe, the session-resumption retest, and the
conditional-request replay — and are gated behind `--deep`. The README states plainly that
users should trace only hosts they are authorized to.

### Execution model

Collectors run as a small dependency graph on a thread pool:

- `local` starts immediately, independent of everything.
- `dns` next.
- `tcp → tls → http` in sequence, while `path` runs concurrently on its own socket.

`--budget` (default 25 seconds) caps total wall clock, with per-collector sub-caps, so a
stalled traceroute cannot hold the trace hostage.

### CLI surface

```
trace.py <target>
  --port N                  override the port
  --no-tls                  plain HTTP
  --timeout SECONDS         per-operation timeout (default 8)
  --budget SECONDS          total wall-clock cap (default 25)
  --json PATH | -           export the trace document ( - writes to stdout )
  --deep                    extra probes: TLS downgrade, resumption, 304 replay
  --privileged              allow sudo for traceroute, path MTU, Wi-Fi detail
  --no-path                 skip traceroute entirely
  --geo-hops                geolocate every hop, not only the destination
  --redact / --no-redact    MAC / local IP / public IP redaction in exports
  --auto-install / --offline
  --insecure                continue past certificate validation failure, still report it
  --osi                     print the OSI reference table alone, no trace
```

### Redaction

Exports are intended to be shared and dropped into a web page, and would otherwise carry
MAC addresses, local IPs, and the public IP. Redaction is therefore **on by default for
`--json`** and off for terminal output, where the operator is the only reader. Redacted
fields are replaced with a sentinel that the page renders as "redacted at export".

## Python: terminal rendering

The per-step panel structure and layer chips are kept. Four additions:

**Findings panel.** Collectors append to `notes`; the run ends with them sorted by
severity. Covered: certificate expiring within 21 days, DNSSEC insecure, no AAAA record, no
HTTP/3 advertised, a redirect hop traveling in plaintext, TLS 1.0/1.1 accepted (`--deep`),
missing HSTS, cookies lacking `Secure` / `SameSite`.

**A true waterfall.** The current chart draws each stage independently against the maximum,
so it reads as five unrelated bars. Stages get absolute offsets instead: each bar starts
where the previous ended, redirect hops nest as their own rows, and the total is the
timeline's end rather than a sum that can double-count.

**A fully observed OSI finale.** All seven layers carry measured values:

| Layer | Example of what is now shown |
|---|---|
| L1 | `en0`, Wi-Fi, MTU 1500, negotiated rate |
| L2 | local MAC → gateway MAC — the frame's real destination |
| L3 | private IP → NAT → public IP → 11 hops, AS8708 → AS13335 |
| L4 | `:54213 → :443`, RTT 12.4 ms, MSS 1460, 0 retransmits, IPv6 won the race |
| L5 | TLS session established, resumed on redirect hop 2, reused for 3 requests |
| L6 | TLSv1.3 · AES_128_GCM · br, 61 KB → 14 KB (4.4:1) |
| L7 | HTTP/2 · GET /dashboard → 200 · DNS via 1.1.1.1, AD bit set |

The `why_not` mechanism remains for cases where a layer genuinely cannot be observed — no
traceroute binary, no privilege, a VPN masking the gateway — so the honesty principle
survives; it simply fires far less often.

**A troubleshooting ladder with this host's commands.** Per layer, the command to test it,
pre-filled with the trace's own values: `ping <ip>` for L3, `nc -vz <host> 443` for L4,
`openssl s_client -connect <host>:443 -servername <host>` for L6,
`curl -sSI <url>` for L7.

When `--json -` writes to stdout, all rich output is redirected to stderr so the document
stays pipeable.

## HTML: data layer

Three sources with per-field precedence: imported trace → live DoH lookup → illustrative
default. The page works with no input, improves with a live lookup, and becomes real with a
trace.

**Provenance badges** (● measured, ◐ live, ○ illustrative, plus the redacted state) sit
beside every rendered fact, with a legend in the header.

**Import** works by dragging a `.json` trace anywhere on the page, a file picker, or paste.
Schema version is validated on load. A trace header bar then shows host, capture time, tool
version, and the capability summary, so `path: not observed — traceroute not on PATH` is
explained rather than blank. The last imported trace persists in `localStorage`.
`?host=example.com` deep-links a live lookup.

A trace whose host does not match the URL input shows a mismatch warning rather than
blending two hosts' data.

## HTML: the journey

The journey grows from 10 stages to 15. Three new stages exist to fix a structural gap: at
present **no step has L1, L2, or L3 as its primary layer**, so those chips appear only as
dim secondaries on the TCP card and the bottom of the OSI panel never fully lights up.

| # | Stage | Change |
|---|---|---|
| 1 | You hit Enter | unchanged |
| 2 | **Your local network** | new — L1/L2 primary: interface, MTU, local MAC → gateway MAC, ARP, DHCP lease, NAT |
| 3 | DNS Resolution | + resolver used, root → TLD → authoritative walk, DNSSEC, CAA, HTTPS/SVCB, cache-hit timing |
| 4 | **Choosing an address** | new — Happy Eyeballs, IPv6 vs IPv4 race, anycast spread |
| 5 | **Crossing the internet** | new — L3 primary: hop list, AS path, RTT growth, path MTU |
| 6 | TCP Connection | + measured RTT, MSS, retransmits from `TCP_INFO` |
| 7 | TLS Handshake | + full chain to the trusted root, ALPN, CAA cross-check, resumption, ECH |
| 8 | HTTP Request Sent | + HTTP/1.1 vs /2 vs /3 framing and multiplexing |
| 9 | **Redirects** | new — the measured chain, why each hop exists, cost in round trips |
| 10 | Reaches your infrastructure | + real CDN fingerprint, cache HIT/MISS, `Age` |
| 11 | Server-side processing | unchanged |
| 12 | HTTP Response | + security-header grade, caching directives, compression ratio, cookie flags |
| 13 | Browser parses & renders | + connection reuse for subresources |
| 14 | Page becomes interactive | unchanged |
| 15 | **Teardown & what's cached now** | new — what a second visit skips: DNS TTL, TLS resumption, HTTP cache |

Every stage gains two fixed blocks: **"test this yourself"** — the same copy-pasteable
command the Python ladder prints, filled with the current host — and **"what breaks here"**,
the failure modes owned by that layer.

## HTML: UI and accessibility

**Expansion.** `max-height: 600px` on expanded cards is replaced with a
`grid-template-rows: 0fr → 1fr` transition, which animates to true auto height and cannot
truncate. The current value would clip the richer content immediately.

**Escaping.** One contract: all code content is stored as plain text and escaped exactly
once at render. The hand-written `&lt;` entities currently embedded in the `JOURNEY` data
are removed, resolving the present inconsistency where `buildDnsCode`/`buildTcpCode` return
escaped output into the same slot as pre-escaped literals.

**Theme.** Flips to dark-first: `:root` dark, `body.light` override, `wj-theme` in
`localStorage`, seeded from `prefers-color-scheme`. This matches the Learning Hub
convention so a later move costs nothing.

**Contrast.** White text on the L4 yellow `#eda100` is roughly 2.1:1 and fails WCAG AA. The
full layer palette is corrected to at least 4.5:1 against its text colour in both themes,
by darkening backgrounds or switching to dark text on the light chips.

**Keyboard and motion.** Step cards become a `<button>` header inside a `<section>`, wired
with `aria-expanded` and `aria-controls`; they are currently `<div>`s with click handlers
and unreachable by keyboard. Added: `↑`/`↓` to move between steps, `Enter`/`Space` to
toggle, `Esc` to collapse, visible focus rings, and `prefers-reduced-motion` honored — which
specifically converts the 1.9-second-per-step autoplay into an instant manual walk.

**Bidirectional OSI panel.** Steps already light up layers; clicking a layer now also
filters the journey to the steps where that layer is primary.

**Failure-mode simulator.** A control that selects a failure and shows its blast radius:
cable unplugged (L1), DNS NXDOMAIN (L7/L3), port 443 blocked by a firewall (L4), expired
certificate (L6), 502 from the load balancer (L7), JavaScript exception (no layer). The
failing layer is marked, every stage that consequently never happens is greyed out, and the
page shows both the real error text a browser displays and the diagnostic command that
isolates it. Entirely client-side.

**Trace-only panels.** When a trace is loaded, two panels appear: the findings list
mirroring the terminal's, and an SVG timing waterfall matching the terminal's — theme-aware
and horizontally scrollable within its own container so the page body never scrolls
sideways.

**Smaller items.** Copy buttons on every code block; a trace summary strip at the top;
single column below 860px with the OSI stack collapsing above the steps; no horizontal
overflow at 375px.

**Portability hook.** All live-fetch code sits behind a single `LIVE_LOOKUPS_ENABLED`
constant. Setting it to `false` makes the page fully offline and `file://`-clean, which is
the entire Learning Hub migration.

## Error handling and degradation

**Only an unresolvable host is fatal.** The current script exits on a failed TCP connect
and again on a failed TLS handshake, discarding completed DNS work and emitting no JSON — yet
a rejected handshake is among the most instructive outcomes possible. New behavior: each
collector records `observed: false` with a `why_not`, the run continues, the failure is
rendered in place and reported at its layer in the OSI finale, and a partial trace is still
exported. Partial traces are a first-class result, not an error.

Exit codes: `0` trace completed, including with findings; `1` target unresolvable;
`2` usage error.

Specific degradations:

- Sudo is never escalated silently. One prompt; a decline yields `why_not: "not privileged"`.
- A failed auto-install degrades with a note naming the package.
- A blown `--budget` marks unstarted collectors `why_not: "budget exhausted"`.
- Sockets move to `try/finally`, closing the leaks the current error paths produce.
- In the page: an unknown schema major version refuses to render; malformed JSON reports a
  clear parse error; DoH blocked by the network keeps the existing error state.

## Known defects being fixed

Recorded so the implementation plan covers them explicitly.

**`webpage_journey_osi.py`**

1. `render_tcp` (lines 315–316) omits a `\n`, so both `└─` annotation lines collide onto
   one line.
2. `cert_subject_field`'s issuer loop keeps the last match of `commonName` *or*
   `organizationName`, so the issuer displayed depends on RDN ordering rather than intent.
3. `A`/`AAAA` resolution goes through `getaddrinfo`, which hides TTL, even though dnspython
   is already loaded for the other record types.
4. Only the leaf certificate is read; no chain, no ALPN, no HTTP/2, no redirect following.
5. `records["A"][0]` is always chosen; IPv6 is resolved but never connected to.
6. Body size counts wire bytes including chunked framing and compression, and is presented
   as though it were content size.
7. `sys.exit(1)` on TCP or TLS failure discards the run and leaks the open socket.

**`webpage-journey.html`**

1. `.step-card.expanded .step-body { max-height: 600px }` hard-clips taller content.
2. Inconsistent escaping between `step.code` literals and `buildDnsCode`/`buildTcpCode`.
3. TXT records are fetched and discarded in the live grid, losing the SPF/DMARC/DKIM lesson.
4. Theme neither reads `prefers-color-scheme` nor persists, and is light-first against the
   Hub's dark-first convention.
5. Step cards are `<div>`s with click handlers: no keyboard access, no ARIA.
6. Layer chip contrast fails WCAG AA for at least L4.
7. No deep-linking and no state persistence.

## Testing

No test infrastructure exists today, and the collectors are the part that needs it — they
parse `traceroute`, `ifconfig`, `dig`, and DER certificates, and those outputs differ
between macOS and Linux.

- **`pytest` over `wj/`**, fixture-driven and fully offline. Real command output is captured
  once into `tests/fixtures/` for both platforms and parsed in tests. Unit tests never touch
  the network.
- **Coverage targets**: the parsers, schema construction and validation, header grading,
  redaction, and capability detection against a faked `PATH`.
- **One opt-in integration test** (`pytest -m network`) traces a real host end to end and
  validates the emitted document against the schema.
- **Golden traces**: two or three sample documents stored in `tests/fixtures/` — a CDN-fronted host, a plain
  single-server host, and an unprivileged partial capture. They serve as both Python
  regression inputs and HTML import fixtures.
- **HTML verification checklist**, run in a real browser against those golden traces:
  keyboard-only walk, reduced motion, 375px overflow, both themes, measured contrast values
  on the layer chips, schema-mismatch handling, and `LIVE_LOOKUPS_ENABLED = false`
  producing a fully offline page.

## Decisions made during design

| Decision | Choice |
|---|---|
| Destination | Standalone now, structured so a Learning Hub move stays cheap |
| Audience | Learners and operator diagnostics, weighted equally |
| Python dependencies | System tool shell-outs, opt-in sudo, and auto-installed pip libraries |
| Coupling | Script exports a trace document; page imports it; live DoH remains the fallback |
| Staging | One design covering everything, built together |
| Version control | `git init` inside `webpage-journey/`; dedicated `.venv` in the project |
