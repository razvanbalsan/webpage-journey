# Webpage Journey

Two teaching artifacts that answer the same question — what actually happens when you
load a webpage — from opposite ends.

- **`trace.py`** opens real sockets and shells out to real tools, so it can measure the
  parts a browser will never show you: the gateway MAC your frames are addressed to, the
  negotiated cipher, the certificate chain up to the root in your trust store, the
  traceroute hops and their AS numbers, the redirect chain, and the compression ratio.
- **`webpage-journey.html`** is a self-contained interactive walkthrough of the same
  journey, mapped onto the OSI model. Drop a trace document on it and every stage swaps
  its teaching example for your real measurement.

## Quick start

### Homebrew (macOS)

The formula lives in this repo, not a tap, so it is installed from a URL rather than by
name. Nothing to clone:

```bash
HOMEBREW_DEVELOPER=1 brew install --formula \
  https://raw.githubusercontent.com/razvanbalsan/webpage-journey/main/webpage-journey.rb

webpage-journey example.com
```

The `HOMEBREW_DEVELOPER=1` is not optional on Homebrew 6.x — see the caveats below.

Or from a clone, if you already have one:

```bash
git clone https://github.com/razvanbalsan/webpage-journey.git
cd webpage-journey
HOMEBREW_DEVELOPER=1 brew install --formula ./webpage-journey.rb
```

The formula builds the tagged release (`v0.1.0`), not your working tree — so a clone that
is ahead of the tag still installs the tagged code.

A few things worth knowing before you rely on this path:

- **There is no `brew upgrade` for this.** Homebrew's upgrade tracking is per-tap; a
  formula installed from a bare path or URL isn't in one, so `brew upgrade
  webpage-journey` won't find a new version even after one is tagged. To update, pull the
  repo (or re-fetch the raw URL) and re-run the install command — add `--force` if
  Homebrew reports the formula is already installed at that version.
- **Recent Homebrew (6.x) requires developer mode for path/URL installs.** If the command
  above is refused with "Homebrew requires formulae to be in a tap", re-run it with
  `HOMEBREW_DEVELOPER=1 brew install --formula ./webpage-journey.rb`.
- **The first install builds `cryptography` from source**, which needs a Rust toolchain.
  Homebrew will pull in `rust` (and its own build dependencies) automatically the first
  time this formula — or anything else that needs `cryptography` built this way — is
  installed; that adds real time (several minutes of compiling) and disk space to a
  from-scratch install. Later installs of other formulae reuse the already-installed
  `rust`.

### pip (any OS)

```bash
python3 -m venv .venv
.venv/bin/python -m pip install rich dnspython cryptography
.venv/bin/python trace.py example.com
```

Missing optional libraries install themselves on first run (quietly inside a virtualenv,
after asking against a system Python). `--offline` disables that.

## Feeding the page

```bash
.venv/bin/python trace.py example.com --json trace.json
```

Then open `webpage-journey.html` and drop `trace.json` onto it.

Exports are redacted by default: MAC addresses, your local IP, your public IP, and
private traceroute hops are replaced with a marker the page renders as
"redacted at export". Use `--no-redact` to keep them.

Every run also contacts `https://ipwho.is/` once, unauthenticated, to learn your
public IP for the NAT determination in the `local` section — this happens even if
you never export anything, and even with `--no-redact` off. There is no flag to
disable it.

## What this tool does not do

`trace.py` speaks only `http/1.1`. It offers just that one protocol over ALPN during the
TLS handshake, because it has no HTTP/2 framing to fall back on — offering `h2` without
being able to speak it would mean lying about what actually happened on the wire. What a
host *supports* is a separate, honestly-labelled measurement: the collectors read the
protocols advertised in ALPN and in the DNS HTTPS record and report them as findings
("this host advertises h2, h3, but this tool only offers HTTP/1.1"). The connection
itself is always HTTP/1.1.

## The rule these tools follow

Every field is either measured or absent. When something could not be observed, both the
script and the page say so and say why — they never fill the gap with a plausible-looking
value. The page labels every fact as **measured** (from a trace), **live** (fetched by the
page just now) or **illustrative** (a teaching example).

## Useful flags

| Flag | What it does |
|---|---|
| `--json PATH` | Export the trace document (`-` writes to stdout) |
| `--no-path` | Skip traceroute |
| `--no-redact` | Keep identifying detail in the export |
| `--budget N` | Total wall-clock cap in seconds (default 25) |
| `--osi` | Print the OSI reference table alone |

Trace only hosts you are authorised to probe.

## Tests

```bash
.venv/bin/python -m pytest          # offline unit tests
.venv/bin/python -m pytest -m network   # opt-in, hits the real network
```

Golden trace documents live in `tests/fixtures/golden/` and double as import fixtures for
the HTML page.

## Offline / Learning Hub build

Set `LIVE_LOOKUPS_ENABLED = false` near the top of the page's script. The page then makes
no network requests at all and works from `file://`, which is what the Learning Hub's
conventions require.
