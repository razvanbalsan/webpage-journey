# HTTP/2 and HTTP/3 — Design

Date: 2026-08-21
Status: Approved, ready for implementation planning

## Purpose

`webpage-journey` traces a webpage request end to end and maps it onto the OSI model. Its
premise is *what really happens when you load a webpage*. But it speaks only HTTP/1.1 — it
offers just `http/1.1` over ALPN, because it has no other framing — while a real browser
negotiates HTTP/2 with most of the web and HTTP/3 with a growing share of it.

So the tool measures a path browsers no longer take. This design closes that gap: a trace
should follow the protocol a browser would actually have used.

The driver is **fidelity**, not teaching or completeness. That choice puts HTTP/3 on the
critical path rather than making it optional, because a browser given the choice will take
it.

## What governs every decision here

The project's central rule is unchanged and applies to all new fields:

**Every field is either measured or absent.** Nothing renders, exports or asserts a value
the trace does not carry. A section that could not be collected says `observed: false` with
a real `why_not`. Exports are redacted by default because they are meant to be shared.

Two consequences are load-bearing in this design and are called out where they apply:
0-RTT must not report `false` when it was never possible, and a protocol downgrade must be
recorded rather than silently succeeding.

## Decisions already settled

| Decision | Choice |
|---|---|
| Driver | Fidelity — trace the path a browser actually takes |
| `cryptography` | A hard dependency again; HTTP/3's QUIC library requires it regardless |
| Negotiation | Browser-like: one connection, best available protocol |
| Layer 4 under h3 | Honest swap — a `quic` section replaces `tcp`; the OSI table shows UDP |
| Architecture | Three transports behind one interface (`wj/transport/`) |
| Schema | Bump to `webpage-journey-trace/2`; the page accepts both majors |
| `aioquic` | A hard dependency. Fidelity puts HTTP/3 on the critical path, so a build that cannot speak QUIC does not meet the goal. The missing-`aioquic` path below is honest degradation for an import that fails at runtime, not an install-time option. |

## Non-goals

- **Tracing several protocols for comparison.** One connection per trace, like a browser.
  A comparison mode was considered and cut — it is three traces in a trench coat and no
  longer answers "what would a browser do".
- **Server push.** Deprecated and removed from browsers.
- **Replacing the HTTP client with `httpx` or similar.** Rejected explicitly: such a
  library owns the connection, which would cost the kernel `TCP_INFO` readings, the
  per-candidate connect timing and the TLS handshake measurement. Those measurements are
  the product.
- **A full Happy-Eyeballs-style race between h3 and h2.** Sequential attempt with a bounded
  timeout instead; the recorded outcome is the same and it keeps concurrency out of a path
  that already embeds an event loop.
- **Reworking the page's prose** about multiplexing and head-of-line blocking. It is
  already accurate; it simply becomes backed by measurement rather than illustration.

## Scope: build this in two phases

This is large enough to warrant decomposition — comparable to the original build — and
HTTP/2 and HTTP/3 have a clean seam between them. Each phase produces working, shippable
software on its own, and each gets its own implementation plan.

**Phase 1 — negotiation and HTTP/2.** The `wj/transport/` split, `h1.py` extracted, `h2.py`
written, the `negotiate` collector, the fallback ladder, and the `http` section's additive
fields (`connection_reused`, `stream_id`, compression sizes). No new transport, no asyncio,
no `quic` section, and **no schema major bump** — every change is additive, so v1 consumers
stay correct. Ships real browser fidelity for the large majority of the web that negotiates
h2.

**Phase 2 — HTTP/3.** `h3.py` and `aioquic`, the `quic` section, the layer-4 swap, the
schema bump to `/2` with dual-major support in the page, the sixteenth page stage, and the
redaction work for the new sections.

The phases are sequenced, not parallel: phase 2's negotiation extension and fallback ladder
build directly on phase 1's. Everything below describes the finished system; each phase's
plan takes the parts it needs.

## Architecture

### Negotiation, and the orchestration order

A new `negotiate` collector runs between `dns` and `tcp`, and decides what runs after it.

The deciding signal is already measured: `dns.alpn_advertised`, read from the host's
HTTPS/SVCB record. That is exactly what a browser uses to decide whether to attempt HTTP/3
on a *first* connection — `Alt-Svc` only helps on a return visit, which a one-shot tracer
never has.

- `h3` advertised → attempt QUIC over UDP
- otherwise → TCP, offering `h2, http/1.1` in ALPN, taking whatever the server selects

The DAG changes shape, because under HTTP/3 there is no TCP connection and no separate TLS
handshake — QUIC carries TLS 1.3 inside itself:

```
local ∥ dns → negotiate ─┬─ h3 → quic ──────────┐
                         └─ h2/h1 → tcp → tls ──┴→ http    (path ∥ throughout)
```

`wj/run.py`'s threading model does not change. `negotiate` is one more synchronous
collector, and the branch is a condition on which downstream collectors run — the same
`DEPENDS_ON` mechanism that already skips `tls` for plain HTTP.

### The transport interface

`wj/collect/http.py` already takes an injectable `fetch(url, sock)` returning a normalized
dict — `protocol`, `status`, `reason`, `headers`, `body`, `ttfb_ms`, `total_ms`,
`wire_bytes`. Every existing test injects through that seam. It becomes the transport
contract rather than something new:

```python
fetch(url, connection) -> response dict     # same shape for all three transports
```

`http.py` keeps everything protocol-independent: the redirect chain, decoding, compression
ratio, security-header grading, cache and CDN detection, findings. It loses only framing.

### The three transports

New package `wj/transport/`:

- **`h1.py`** — today's framing, moved unchanged. `parse_response` moves with it: parsing a
  status line is an HTTP/1.1 concern.
- **`h2.py`** — drives the `h2` library. Sans-IO, so the socket stays ours: the kernel
  `TCP_INFO` RTT/MSS/retransmits and the measured TLS handshake all survive. Produces the
  normalized dict from `:status` and header frames, and adds HPACK compression sizes and
  the stream ID.
- **`h3.py`** — drives `aioquic` on its own UDP socket. Calls `asyncio.run()` internally and
  returns synchronously; the orchestrator already runs collectors in worker threads, so a
  fresh event loop per thread is legal and fully contained. Produces the `quic` section.

`h2` returns as a declared dependency — it was removed earlier as dead weight when nothing
imported it, and now something does.

### Connection reuse becomes true

An earlier correction in this project established that redirect hops each open a *fresh*
connection, because HTTP/1.1 sends `Connection: close`. Under h2 and h3 a same-authority
redirect genuinely reuses the connection. The layer-5 story stops being "one request per
connection" and becomes an observation of real reuse — which is what the page has taught in
prose all along. `http.hops[]` gains `connection_reused`.

## Schema

Bump to `webpage-journey-trace/2`. The page accepts both majors so previously-saved v1
traces keep opening; `importTraceText` branches on the major and renders v1 documents
without the new sections.

The bump is not merely additive bookkeeping. An existing v1 page shown an h3 trace would
render "TCP not observed — this connection used QUIC over UDP", which is truthful, and then
show *nothing* for layer 4, because it has no idea a `quic` section exists. That is absence
you cannot see. A refused document that says why is the honest alternative.

### New section: `negotiation`

Records why the trace took the path it did — what was advertised, which signal decided,
what was attempted, what was chosen, and why anything was abandoned.

```json
{"observed": true,
 "advertised": ["h3", "h2"],
 "signal": "HTTPS record",
 "attempted": [{"protocol": "h3", "outcome": "no response in 3.0s"}],
 "chosen": "h2",
 "downgraded_from": "h3",
 "downgrade_reason": "QUIC did not respond — UDP may be blocked on this network"}
```

### New section: `quic`

```json
{"observed": true,
 "handshake_ms": 41.2,
 "version": "1",
 "connection_id": "…",
 "local": {"ip": "…", "port": 54213},
 "chosen": {"ip": "…", "port": 443},
 "datagram_size": 1200,
 "qpack": {"wire_bytes": 118, "decoded_bytes": 412},
 "zero_rtt": {"observed": false,
              "why_not": "no prior session — 0-RTT requires a resumed connection"}}
```

Two honesty requirements:

- **`zero_rtt` must never report `false`.** A one-shot tracer holds no prior session ticket,
  so 0-RTT is not merely unused but impossible. Reporting `false` would imply it was
  attempted and declined.
- **`connection_id` goes on the redaction review list explicitly.** It is ephemeral and
  server-chosen and probably identifies nothing, but it is new identifying-shaped data
  entering a document designed to be shared, and this project has shipped three leaks that
  hid in fields nobody thought about. It is reviewed, not assumed.

### Changed sections

- `tcp` and `tls` report `observed: false` with
  `why_not: "this connection used QUIC over UDP"` on an h3 trace.
- `http.hops[]` gains `connection_reused` and `stream_id`.
- `http.final` gains header-compression sizes (wire versus decoded) — a measurement HTTP/1.1
  cannot produce.
- `osi.l4` reports UDP and QUIC rather than TCP, ports and MSS; `osi.l6` reports the TLS
  version negotiated inside QUIC.

## Rendering

### Terminal

For an h3 trace, one `3 · QUIC connection` panel replaces both `3 · TCP connection` and
`4 · TLS handshake`, because QUIC genuinely is both. It carries the layer tags `L4 L6 L5`.

Negotiation is a line, not a panel — "advertised h3, h2 · chose h3 via the HTTPS record" is
one fact. A downgrade adds its reason to that line and a `warn` finding.

### The page

**The skipped stages stay visible.** On an h3 trace, the TCP Connection and TLS Handshake
stages are *not* hidden; they render not-observed with the real reason: *"this connection
used QUIC over UDP, so no TCP handshake happened"*.

This is deliberate and is the design's clearest teaching decision. The page's job is showing
the journey a request takes, and that HTTP/3 **skips two entire stages** the reader has just
learned about is the most vivid thing about it. Hiding those cards would delete the lesson.
The existing not-observed treatment renders this at no cost.

A new **QUIC connection** stage slots in beside them with L4 as primary, making sixteen
stages. This changes the layer-filter counts previously verified (L4 goes from three stages
to four); those counts must be re-measured, not assumed.

## Error handling and degradation

**The fallback ladder is browser behaviour, and every rung is a measurement.** When h3 is
advertised and QUIC then fails — UDP blocked, handshake timeout, version negotiation failure
— the trace falls back to TCP with `h2, http/1.1`, and records the attempt and the reason.
*"Advertised h3; attempted QUIC; no response in 3s — UDP likely blocked; fell back to h2"*
is a true fact about the network the user is on that no other part of the tool can discover.

**The h3 attempt gets its own bounded timeout, carved out of `--budget`.** Without one, a
network silently dropping UDP would burn the whole run's wall clock before falling back. A
short fixed ceiling, not a fraction of the budget: the useful signal is whether QUIC answered
promptly.

**A missing `aioquic` is not an error.** Negotiation records *"host advertises h3, but this
build has no QUIC support"* and proceeds over h2 — reusing the shape of the honesty note the
tool already emits about ALPN rather than inventing a new one.

**h2 failing after ALPN selected it is a genuine error, not a fallback.** The server agreed
to h2; if framing then fails, something is actually wrong, and the section reports
`observed: false` with the real reason. Silently retrying on HTTP/1.1 and reporting success
would hide a real defect, and would recreate the exact negotiate-one-speak-another mismatch
this project already fixed once.

## Testing

**Both protocols are testable entirely offline.** The `h2` library is sans-IO by design: a
client and a server connection drive each other through byte buffers with no socket.
`aioquic` has the same property — `QuicConnection` is a sans-IO core, so a client and server
handshake run in memory with datagrams handed between them. The project's "unit tests never
touch the network" rule survives intact, and framing is tested against a real peer
implementation rather than a mock of one.

- **Negotiation** is a pure function over `dns.alpn_advertised` plus capabilities — decision
  and reason out, no I/O.
- **The fallback ladder** tests by injecting a transport that times out, asserting both the
  outcome and the recorded reason, since the reason is the measurement.
- **Two new golden fixtures** — an h2 trace and an h3 trace — because the page tasks need
  something to develop against and the existing three predate this work.
- **The opt-in network test** extends to a host that genuinely advertises h3
  (`cloudflare.com` does), asserting negotiation chose it.

### A required task, not a nicety

The final whole-branch review of this project found that three separate privacy leaks
survived because a test fixture lacked the key being leaked — most recently the OSI
narrative republishing the local MAC address in a document stamped `"redacted": true`,
invisible because the leak fixture had no `osi` key. It concluded the suite would not catch
a fourth.

Adding `quic` and `negotiation` is exactly the moment that bites again; the `quic` section
carries a connection ID and UDP endpoint details.

So, before either section ships: extend `wj/redact.py` to consider both new sections, extend
the leak fixture to populate them, and confirm the structural walker sees them. This is a
task with its own gate, not a line item inside another.

## Documentation

- The README's "What this tool does not do" section is rewritten. It currently explains that
  the tool speaks only HTTP/1.1 and why; that becomes a description of what it negotiates and
  when it falls back.
- `--help`'s protocol section changes with it.
- Neither may overstate. `aioquic` is a hard dependency, so a default build speaks all
  three protocols and the docs say so plainly.
