# Releasing

## Publishing a version so `webpage-journey.rb` can install it

The formula's `url` points at a GitHub release archive that does not exist yet
(`https://github.com/razvanbalsan/webpage-journey/archive/refs/tags/v0.1.0.tar.gz`),
and its `sha256` is a placeholder. Both need the real values before anyone can
`brew install --formula ./webpage-journey.rb` from a clean checkout.

1. Make sure `pyproject.toml`'s `version` and the tag you are about to push agree
   (currently `0.1.0` / `v0.1.0`). Bump both together for future releases.
2. Make sure the full suite passes: `.venv/bin/python -m pytest -q`.
3. Tag and push:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. GitHub builds the source archive for every tag automatically — no separate
   "release" object is required, `archive/refs/tags/<tag>.tar.gz` works as
   soon as the tag exists on the default remote.
5. Compute the real digest of that exact archive:

   ```bash
   curl -sL https://github.com/razvanbalsan/webpage-journey/archive/refs/tags/v0.1.0.tar.gz \
     | shasum -a 256
   ```

6. Paste that digest into `webpage-journey.rb`'s `sha256` line, replacing the
   placeholder `0000…0000`. Commit that one-line change.
7. Re-verify the formula end to end before telling anyone to use it:

   ```bash
   brew install --formula ./webpage-journey.rb
   webpage-journey --osi
   brew uninstall webpage-journey
   ```

   As of Homebrew 6.x, installing a formula from a local path is gated behind
   developer mode (`brew install ./package.rb` is refused with "Homebrew
   requires formulae to be in a tap" otherwise). Run the command above with
   `HOMEBREW_DEVELOPER=1` set, e.g.:

   ```bash
   HOMEBREW_DEVELOPER=1 brew install --formula ./webpage-journey.rb
   ```

   This is the same path a user cloning the repo will need — document it
   alongside the install instructions rather than assuming the bare command
   works on every Homebrew version.

## Keeping the resource list current

`webpage-journey.rb` vendors `rich`, `dnspython`, and `cryptography` plus
their transitive dependencies (`markdown-it-py`, `mdurl`, `pygments`, `cffi`,
`pycparser`) as Homebrew `resource` blocks, because Homebrew builds Python
dependencies from sdists rather than reusing prebuilt wheels. When any of
`pyproject.toml`'s dependencies changes version, regenerate the resource
blocks rather than hand-editing them:

```bash
brew update-python-resources ./webpage-journey.rb
```

If `brew` is not available, fetch each package's sdist URL and sha256 from
`https://pypi.org/pypi/<package>/<version>/json` (the `urls[].packagetype ==
"sdist"` entry) and verify the hash by downloading the file and running
`shasum -a 256` on it — never copy a hash without checking it against a real
download.

`cryptography` has no source build path without a Rust toolchain (it is a
`maturin`/PyO3 extension since it dropped the legacy CFFI-only OpenSSL
backend). The formula declares `depends_on "rust" => :build` and
`depends_on "pkgconf" => :build` (so cryptography's Rust build can locate
OpenSSL via pkg-config) for this reason. On a machine that does not already
have the `rust` formula installed, this adds a real first-install cost: an
extra multi-hundred-megabyte toolchain download plus several minutes of
`cargo` compilation for the `cryptography` resource specifically (the other
resources are pure Python or small C extensions and are fast). There is no
way to avoid this while staying with the vendored-resource design; the
alternative is `depends_on "cryptography"` against Homebrew's own
already-bottled `cryptography` formula instead of vendoring it, which trades
away self-containment for a much faster first install.
