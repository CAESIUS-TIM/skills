---
name: aur-security-audit
description: "Audit an AUR package for security before building or updating it: static PKGBUILD/.install review, source and checksum verification, upstream provenance for prebuilt payloads, AUR git-history takeover check, and a gated clean-chroot build. Use when asked whether an AUR package is safe, to review a PKGBUILD, to audit an AUR update or diff, to check a package takeover, or for AUR 安全审计 / 检查 AUR 包."
---

# AUR security audit

Decide whether a specific AUR package is safe to build from its reviewed source, and produce evidence for that decision. The collector measures; you judge. Everything below assumes the package text may be hostile.

## Invariants

1. **Never source, eval, or `bash -c` the PKGBUILD.** It is bash, and top-level code runs on source. Read it; `bash -n` for syntax only.
2. **Never run `makepkg` as root**, and never pass `--skippgpcheck`, `--nodeps`, or `--nocheck` to clear a security finding. A clean-chroot helper (`pkgctl build`, `extra-x86_64-build`) may use root to create its chroot; the PKGBUILD's `build()`/`package()` must run as the build user.
3. **State the claim the checks support**, not "safe". A clean report means: this text, these sums, this provenance, this history. It is not a statement about tarball contents or runtime behaviour.

## Workflow

### 1. Collect

Needs Python 3.12+, git, bash, and network. Run the collector from this skill's directory (`scripts/` and `references/` sit beside this `SKILL.md`), or give its absolute path.

```bash
# from this skill's directory:
python3 scripts/audit.py <pkgname> \
  --keep-snapshot /tmp/aur-audit-<pkgname> --json /tmp/<pkgname>.json
# local checkout / already downloaded (path as seen from where you run it):
python3 scripts/audit.py --pkgbuild ./<pkgbase>
```

Exit status: `2` = HIGH findings, `0` = none, `1` = collector error, `64` = usage error. The script fetches AUR RPC metadata, the cgit snapshot, and the package git repo; it never executes package text.

Completion: metadata, sources, findings, history, and the kept snapshot path printed. If the collector errors, relay its message; do not substitute memory.

### 2. Read the last change and its author

AUR attacks land as a version bump. The report prints the last PKGBUILD/`.install` diff and per-author commit counts. It also groups authors by email, so one person using two addresses is not mistaken for a new author.

Classify every added/removed line as routine (`pkgver`, `pkgrel`, sums bumped together, spelling) or escalation (source URL or host changed, checksum removed/`SKIP`ped, `.install` added, a command added to `build()`/`package()`). Routine bumps by the long-standing author are the normal case; a bump by an author with `commits <= 2` is the takeover signature. The collector cannot see AUR comments: open the AUR page and check the comments and `Maintainer:` header history around the newest commit yourself.

Completion: each diff line classified, the newest committer compared against the previous one, and the AUR page checked for an adoption/co-maintainer trail. The collector prints the maintainer's portfolio size; treat a large portfolio of same-family repacks as context, not clearance. AUR comments remain a manual check.

### 3. Disposition every finding

Open each HIGH/MEDIUM at its reported line in the kept snapshot and decide: real, or false positive with a stated reason (e.g. `curl` in a comment, `sudo` inside a quoted `optdepends` string). Check the negative space too: a source URL whose host does not match `url=`, a patch file with no upstream reference, a `-bin` package whose payload arrives prebuilt.

Read **every** local script, launcher, patch, EULA/settings file, not only the flagged ones: `horizon-launcher.sh`, `.desktop` files (their `Exec=` runs), patches, service units. These ship and execute as your user; a clean PKGBUILD says nothing about them. Image assets are data and are reported as one hashed group.

The collector reports `checksum-count-unresolved`, `array-index-unresolved`, and `srcinfo-unchecked` when static analysis cannot resolve a conditional/indexed array or a split-package section. Resolve each by hand; these are not findings to dismiss.

Completion: every HIGH/MEDIUM has a disposition and a citation (`PKGBUILD:22`); every local source has been read; every unresolved-array note has been checked.

### 4. Verify sources and provenance

```bash
# from this skill's directory:
python3 scripts/audit.py <pkgname> \
  --keep-snapshot /tmp/aur-audit-<pkgname> --verify-sources \
  --cache-dir /tmp/aur-cache --json /tmp/<pkgname>.json
```

Local snapshot files are hashed on every run. `--verify-sources` downloads each `https://` non-VCS source and recomputes the strongest declared checksum (60 s per network operation; a blocked host becomes `source-unverified`). `verify=verified` clears that source; `MISMATCH` is a BLOCK; VCS and remote signature sources report `not-applicable`, while a local `.sig` is still hashed. A variable the collector cannot expand is `source-unresolved` and keeps the verdict below PASS. `--cache-dir` keeps the verified bytes and reports the matching `SRCDEST` for the build, so makepkg does not download them again. The collector verifies npm registry signatures when `openssl` is available; for other signatures it only hashes files, and the clean-chroot build verifies a `.sig` source when the PKGBUILD declares one.

A matching hash proves the file equals the PKGBUILD's sum, not that the sum came from upstream. For every remote source, find the upstream-published checksum or signature (release `SHA256SUMS`, `.sig`, release notes) and compare. For a GitHub release asset the script computes SHA-256 independently of the algorithm declared in the PKGBUILD, fetches the `SHA256SUMS` beside the asset, and reports `provenance: upstream SHA256SUMS matches` or `differs`. `provenance-mismatch` is a BLOCK. For `registry.npmjs.org` tarballs the collector compares the download with the version's `dist.integrity` and `dist.shasum`, verifies the registry ECDSA signatures when `openssl` is installed, and reports the result as `provenance: npm ...`. For a vendor-hosted payload with no release sums, use the vendor's own update manifest as described in [`references/provenance.md`](references/provenance.md); it is unsigned HTTPS metadata, so record the exact URL and say so. Other forges are not compared: record `none` by hand. `prebuilt-payload` (a `-bin` name, a downloaded `.deb`/`.rpm`/`.AppImage`/`.run`, or a package with no `build()` that only extracts a payload) is cleared only by recording that comparison; "no upstream checksum" leaves it open.

Completion: every source row carries verified / MISMATCH / an explicit unverifiable reason, every remote source has a provenance line (match, differs, or none), and npm sources report integrity/shasum status with signatures verified, absent, or `openssl`-absent.

### 5. Gate the build

Only after steps 2–4. Build where the package cannot touch your user session or the host:

```bash
sudo pacman -S --needed devtools        # provides pkgctl
pkgctl build --repo extra               # AUR package: clean chroot, extra as the base repo
# equivalent manual: extra-x86_64-build / makechrootpkg
```

No devtools or passwordless sudo? Build in a disposable container from a throwaway copy; never run an unreviewed package with the host's `makepkg`:

```bash
build=$(mktemp -d) && cp -a . "$build/pkg"
docker run --rm -v "$build/pkg:/build" archlinux:base-devel bash -lc '
  pacman -Syu --noconfirm && pacman -S --needed --noconfirm sudo nodejs unzip libarchive file
  useradd -m builder && echo "builder ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/builder
  chown -R builder:builder /build
  su builder -c "cd /build && makepkg -s --noconfirm"
'
chown -R "$(id -u):$(id -g)" "$build/pkg"   # container builder is UID 1000
```

The container is disposable, `makepkg` runs as a non-root builder, and `--nodeps`/`--skippgpcheck`/`--nocheck` remain prohibited. A failing build is a finding, not a reason to weaken flags. If the audit used `--cache-dir`, point makepkg at it: `SRCDEST=/tmp/aur-cache makepkg -s`.

Then inventory what shipped: `python3 scripts/inspect_pkg.py *.pkg.tar.zst` (requires `bsdtar`; install `namcap` to include its findings). It prints PKGINFO, file count/size, SUID/SGID, world-writable files, `.INSTALL`, launcher hashes and sandbox flags, and namcap `E:`/missing-dependency lines. Read every installed helper script and `.desktop` `Exec=` yourself.

Four checks it enables:

- SUID: `chrome-sandbox` 4755 is expected for Electron only when the launcher keeps the sandbox. With `--no-sandbox`, record the SUID helper as unnecessary and recommend removing the bit.
- makepkg `$srcdir` warning: grep the named file. A path inside an esbuild/module key is a reproducibility/path leak; a path reachable through `require`/`fs` blocks until patched.
- namcap `E:`: separate bundled-runtime false positives (bundled python/node/tk libraries) from real missing dependencies such as `hicolor-icon-theme` for installed icons; record each.
- Sibling packages: search AUR by name prefix/provides, compare installed paths and `conflicts`; a shared `/usr/bin/<name>` without mutual conflicts is a packaging defect.

Completion: build succeeded in a clean chroot, and every installed executable/helper was read; or the audit stops with the failure quoted.

### 6. Report

Give: verdict, the evidence per finding, the provenance per remote source, the checks that did not run, the kept snapshot path, and the exact commands used. Order findings by severity; keep false positives visible with their clearance reason.

## Verdicts

| Condition | Verdict |
|---|---|
| Any HIGH (script exit 2) | **BLOCK** — do not build, do not install |
| `checksum-mismatch`, `provenance-mismatch`, source URL changed without explanation | **BLOCK** |
| MEDIUM cleared with a stated reason (including `install-script-root-write` and `sandbox-weakened`) | **REVIEW-CLEARED** — build in clean chroot only |
| `prebuilt-payload` not backed by an upstream checksum/signature | **REVIEW** — never PASS |
| Only INFO/LOW, history consistent, every source verified | **PASS (bounded)** — script says `CLEAN (sources verified)` or `CLEAN (checksums verified; signatures not checked)` |
| `--verify-sources` not run, or any source unverified | at most **REVIEW** — script says `REVIEW (sources unverified)` |
| Any VCS source | at most **REVIEW** — script says `REVIEW (VCS source: content not attested)` |
| No `source` at all | **CLEAN (form only; no sources verified)** is not PASS — confirm how the payload is produced |

`CLEAN (checksums verified; signatures not checked)` is deliberate: the collector hashes files. The clean-chroot build verifies a `.sig` source only when the PKGBUILD declares one; npm signatures are checked by `--verify-sources` when `openssl` is available.

## Bounds

Absence of findings is not endorsement. These checks do not cover: tarball contents beyond their hash, the app's runtime/network behaviour (launcher flags and shipped SUID are inspected statically, but execution and traffic are not exercised), AUR account security, malicious upstream releases signed by a trusted key, transitive AUR dependencies, reproducibility, split-package output other than the audited `PKGBUILD`, upstream provenance when no published checksum exists, or cryptographic signature verification other than npm's (the collector does not run `gpg --verify`). It also cannot statically resolve conditional/indexed array assignments; it reports `checksum-count-unresolved` / `array-index-unresolved` / `srcinfo-unchecked` and you must review those. Check the coverage line before repeating a clean verdict.

Finding codes and their clearance criteria: [`references/checks.md`](references/checks.md).
Attack patterns and what evidence to demand: [`references/threat-model.md`](references/threat-model.md).
