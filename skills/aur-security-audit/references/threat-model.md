# AUR threat model

The AUR hosts build scripts, not binaries. Whatever the PKGBUILD says runs on your machine, as your user, with your SSH keys and token paths visible. A clean-chroot build only produces the package's `.install` scriptlet; installing the built package (`pacman -U`, `pkgctl build -i --install-to-host`) then sources it as root. The package text is the attack surface.

## Attack patterns, in order of observed frequency

**Orphan adoption.** An unmaintained package is adopted, then a version bump changes a source host, drops a checksum, or adds an `.install`. `orphan` plus a fresh `committer-change` is the signature. Demand: the adoption trail and a source URL that matches upstream's own release page.

**Account takeover of a trusted maintainer.** The history stays coherent — same package, same email — but the newest bump moves a download to a new host or adds a fetch in `build()`. No static check can distinguish this from a normal release. Demand: upstream's published checksum or signature for that exact version, and the AUR comments around the release date.

**Checksum removal.** `SKIP`, a short "hash", or a checksum array that no longer lines up with `source`. Makes every later step vacuous. `skip-checksum`/`malformed-checksum`/`checksum-count-mismatch` are hard blocks.

**Build-time download.** The declared source is benign; `build()` fetches the real payload. Defeats both the checksums and the AUR review. `net-fetch`/`pipe-to-shell` are blocks, not warnings.

**Patch smuggling.** A `.patch` shipped in the AUR repo is applied in `prepare()`. Its checksum covers bytes you never read. Read the patch or treat the package as unreviewed.

**Local helper scripts.** A `.sh`, `.desktop`, service or `.install`-adjacent file shipped beside the PKGBUILD can be installed and executed. Its checksum only proves the AUR upload matches the PKGBUILD, not that the script is safe. Read every local source; the collector lists them and hashes them against the declared sums.

**Runtime hardening regression.** A launcher can keep the build clean and still hand the renderer the user's full privileges: `--no-sandbox`/`--disable-gpu-sandbox`/`--in-process-gpu`, or a shipped SUID `chrome-sandbox` while the sandbox is disabled. The package is then an unsandboxed browser over remote content. Demand the upstream bug reference for the workaround and a written statement that rendered/remote content runs unsandboxed; the collector flags the flags (`sandbox-weakened`) and `inspect_pkg.py` lists shipped SUID.

**Top-level execution.** `_x=$(curl … | sh)` or `depends=($(…))` outside a function runs when makepkg sources the PKGBUILD, before any checksum is looked at. `dynamic-shell`/`top-level-substitution` cover it; a quoted literal is the only safe form.

**VCS floating.** `-git` packages track a branch; `SKIP` is correct there, so the checksum no longer attests to content. Demand: a pinned commit is not possible for a true `-git` package, so the trust anchor becomes the upstream repository and the `pkgver()` output. Prefer a release tarball package when one exists.

**`.install` root execution.** `post_install` runs as root and is easy to overlook. Every command in an `.install` function is listed (`install-script-command`), and writes to system paths, `sed -i`, `rm`, `chmod`, `chown` or redirections raise `install-script-root-write`; network/credential/privilege patterns inside `.install` are HIGH.

**Prebuilt payload (`-bin` and friends).** Nothing is compiled, so review cannot see inside the blob; the checksum only binds you to whatever the maintainer downloaded. The name is not reliable: `google-chrome` ships a `.deb`, `spotify` ships a `.deb`, and neither ends in `-bin`. The collector flags a downloaded `.deb`/`.rpm`/`.AppImage`/`.run`/`.7z`, a `-bin` name, or a package with no `build()` whose `package()` only extracts a payload. Demand: an upstream-published hash or signature for this exact file. The collector compares a GitHub release asset's SHA-256 with the `SHA256SUMS` beside it when `--verify-sources` runs, and reports `prebuilt-payload` until that comparison is recorded.

**Transitive AUR dependencies.** A clean PKGBUILD can `depends` on another AUR package that is not clean. The audit covers one package; walk the `depends`/`makedepends` chain with the same gate when it resolves to AUR.

**Dependency-mode abuse.** `pkgmgr-in-build` (pip/npm/cargo/go install at build time) pulls unpinned code past the declared dependency list and the checksums.

## Evidence that clears a suspicion

- The source URL is on the upstream project's own domain or its official release forge, and the version string matches the upstream release.
- The checksum matches a value published upstream (release notes, `SHA256SUMS`, signature file), not just the AUR PKGBUILD.
- The commit that introduced the version has a normal `upgpkg:` subject by the long-standing author, and the diff touches only version, sums, and dependency pins.
- AUR comments around that date show no "why did the source host change" questions.
- The build succeeds in a clean chroot with `--nocheck` unused and no flags weakened.

## What this audit cannot establish

- That the tarball contents are benign. Only the hash was checked, and only if `--verify-sources` ran.
- That the built binary does nothing hostile at runtime, including the launch flags and network traffic the app uses after start.
- That the maintainer's AUR account is uncompromised.
- That a correctly signed upstream release is not malicious.
- That a `.sig`/`.asc`/`.sign` source was cryptographically verified. The collector hashes files and verifies npm registry signatures; the clean-chroot build runs `gpg --verify` only for signature sources the PKGBUILD declares. A `.gpg`/`.pgp` file is not a signature to makepkg.
- That the package's AUR dependencies are clean, or that the build is reproducible.

Say which of these were not covered. A verdict that hides its coverage is worse than `REVIEW`.
