# Finding codes

Every code `audit.py` emits, what it observes, and the condition that clears it. "Observed" is what the script measured; "cleared when" is the judgement step — the audit is not finished until each finding has one.

## Source integrity

| Code | Sev | Observed | Cleared when |
|---|---|---|---|
| `insecure-scheme` | HIGH (`http://`, including `git+http://`), MEDIUM (`git://`, `git+ftp://`, `ftp://`, `svn://`, `tftp://`) | Source fetched over an unauthenticated transport | Never for `http://`; for `git://`/`ftp://`, only if the entry also carries a verified checksum and the upstream cannot serve TLS |
| `dynamic-source` | HIGH | `$(...)` or backticks inside a `source` entry | Never — the fetched URL is not the reviewed text |
| `missing-checksums` | HIGH | No checksum array alongside the sources | Never; makepkg cannot verify anything |
| `weak-checksum` | HIGH (LOW when a strong sum is also present) | `md5sums`, `sha1sums`, or `cksums` present | A strong sum (SHA-2 or BLAKE2) covers every source; otherwise never |
| `checksum-count-mismatch` | HIGH | Checksum entries ≠ source entries, with both arrays statically countable | Never; also breaks makepkg alignment |
| `checksum-count-unresolved` | INFO | `+=`, indexed, function-scoped, conditional, or unexpandable assignments make the static array length differ from the build-time length | Count by hand for the active configuration; not a block by itself |
| `skip-checksum` | HIGH (LOW for `.patch`/`.diff`) | `SKIP` on a non-VCS, non-signature source | VCS and `.sig`/`.asc`/`.sign` are exempt by design. `.gpg`/`.pgp` are **not** signatures to makepkg and are never exempt. A skipped patch is cleared only by reading the patch |
| `malformed-checksum` | HIGH | Value is not the correct hex length for its algorithm | Never; the comparison is vacuous |
| `checksum-mismatch` | HIGH | A downloaded source or a local snapshot file does not match the declared sum | Never. Either upstream republished the file or the sum was wrong — both block |
| `source-unverified` | MEDIUM | A remote source could not be fetched, or a local source is missing or escapes the snapshot (absolute path, `..`, symlink out) | Fetch it by hand and compare, or accept the gap explicitly in the report |
| `source-unresolved` | MEDIUM | A source URL contains a variable or expansion the collector cannot resolve (`${x/…}`, `${arr[@]…}`, `$((…))`), so its real host was never reviewed | Expand by hand and review the resulting host, or verify the source by hand |
| `array-index-unresolved` | MEDIUM | A `source[i]`/`sums[i]` assignment uses a non-literal index, or any source/checksum assignment sits inside a function or conditional block, so the reported table may not be the build-time table | Resolve the assignment by hand and confirm the effective source/checksum |
| `local-source` | INFO | Source is a file shipped in the AUR repo (patch, launcher, EULA); images are grouped into one line | Read scripts, launchers, patches and configs; they are installed and may execute. Their declared hash is verified automatically when a strong sum is present. Images are data, hashed only |
| `no-sources` | INFO | Meta or prebuilt package with no `source` | Confirm how the payload is produced (`package()` copies from where?) |

## Build/package logic (`build()`, `prepare()`, `package()`, `check()`, `pkgver()`, `.install`)

| Code | Sev | Observed | Cleared when |
|---|---|---|---|
| `net-fetch` | HIGH | `curl`/`wget`/`ncat`/`socat`/`rsync`/`scp`, `git clone`/`git fetch`/`git pull`/`git submodule update`, `hg clone`, `svn checkout` in a function or at top level | Never in `build`/`package`; network belongs in declared `source` |
| `pipe-to-shell` | HIGH | `\| sh`, `\| bash`, `\| /bin/sh`, `\| python`, `\| perl`, `\| ruby`, `\| node` | Never |
| `script-exec` | MEDIUM | `bash <file>`, `bash <(…)`, `source file`, `. file` | Read the script end-to-end; record that it only performs the packaging steps the PKGBUILD claims. The hash proves the upload, not the logic |
| `dynamic-shell` | HIGH | `eval`, `sh -c`, `bash -c`, or a top-level/array command substitution containing a downloader or pipe | Only when the evaluated string is a quoted literal visible on the same line |
| `decode-payload` | HIGH | `base64 -d`, `xxd -r`, `openssl enc -d` | Only after decoding and reading the payload; the decoded bytes are the real review target |
| `credential-access` | HIGH | `~/.ssh`, `~/.gnupg`, tokens, `.netrc`, `git config --global`, `credential.helper` | Never |
| `privilege` | HIGH (`sudo`, `su -`); MEDIUM (`chmod +s`, numeric modes such as `chmod 4755`/`6755`/`04755`, `setcap`) | Privilege escalation, or SUID/SGID/capabilities in the PKGBUILD or a shipped local script | Never for escalation; a SUID/SGID/capability set in `package()` or `.install` needs an explicit upstream reason and a written disposition. If the launcher disables the sandbox, a shipped `chrome-sandbox` SUID bit is unnecessary |
| `sandbox-weakened` | MEDIUM | `--no-sandbox`, `--disable-gpu-sandbox`, `--disable-setuid-sandbox`, `--in-process-gpu` in a PKGBUILD function, launcher, or `.desktop` `Exec=` | Record the upstream compatibility reason and state in the report that rendered/remote content runs with the user's full privileges; prefer removing the flag or dropping the now-unused SUID helper |
| `persistence` | MEDIUM | `systemctl enable`, `crontab`, `~/.bashrc`, autostart entries | Never from a package; units belong in the package payload, enabled by the user |
| `pkgmgr-in-build` | MEDIUM | `pacman -U`, `pip install`, `npm install`, `cargo install`, `go install`, `gem install` | Cleared only when it installs into `$pkgdir` from a declared, checksummed source |
| `dynamic-linker` | HIGH | `LD_PRELOAD`, `ld.so.preload` | Never |
| `destructive` | HIGH | Recursive delete of `/`, `/home`, `/etc`, `$HOME`, `~`, or `find / … -delete` | Never |
| `encoded-blob` | MEDIUM | ≥160-char base64-like token | Decode it and read it |
| `top-level-command` | MEDIUM | Statement outside any function or array, not matched by a specific rule | Assignments (including `: "${x:=y}"` and `arr[i]=…`), function definitions, case labels and harmless builtins (`unset`, `echo`) are fine; anything that executes is not |
| `top-level-substitution` | MEDIUM | `$(...)`/backticks in a top-level assignment or array, without a downloader or pipe | Expand and read the command; top-level substitution runs when the PKGBUILD is sourced |
| `syntax-error` | HIGH | `bash -n` rejects the file | Never; the parsed text is not the executed text |
| `install-script-command` | INFO | Any non-shell command in an `.install` function or at its top level (both run as root) | Read the command; `useradd`/`groupadd` should be `sysusers.d`, `systemctl` calls are review items |
| `install-script-root-write` | MEDIUM | An `.install` command — in a function, a compound command such as `if …; then cp …`, or top-level code — touches `/etc`, `/usr`, `$HOME`, `~`, uses `sed -i`, `rm`, `chmod`, `chown`, `mv`, `cp`, or redirects to a system path | Read the script and justify the write; root execution is the threat |
| `install-missing` | MEDIUM | `install=` resolves to a file absent from the snapshot, outside it, or through a variable the collector cannot expand | Never; makepkg fails or picks up a stray file. Subdirectory install scripts are resolved and scanned |
| `root-write` | MEDIUM | A redirection writes under `/etc`, `/usr`, `/var`, `/boot`, `/root` or `/home` from `build()`/`package()` | Never in a package build; the payload belongs under `$pkgdir` |

## Metadata and provenance

| Code | Sev | Observed | Cleared when |
|---|---|---|---|
| `orphan` | MEDIUM | AUR reports no maintainer | Audit the version you build; re-audit on update. Any non-version diff afterwards is a BLOCK |
| `committer-change` | MEDIUM | Newest commits by an author with ≤2 commits, different from the previous author | A visible adoption/co-maintainer trail (AUR comments, `Maintainer:` header change, upstream handover) |
| `thin-history` | INFO | ≤3 commits | Confirm the package was not squashed after a takeover |
| `license-unknown` | MEDIUM | The pkgbase `license` is missing, `unknown`, or `custom` | A concrete SPDX identifier, plus the license file installed under `/usr/share/licenses/`. Per-subpackage overrides are not used for this check |
| `srcinfo-stale` | MEDIUM | `.SRCINFO` arrays (source, checksums, depends, makedepends, checkdepends, arch, license, including per-architecture forms such as `depends_x86_64`) or `pkgver`/`pkgrel` disagree with the PKGBUILD, for a package whose arrays are statically countable | Regenerate; a stale `.SRCINFO` hides what the AUR page and helpers show |
| `srcinfo-unchecked` | INFO | A split package, or an array built with `+=`, indexed, function-scoped, or conditional assignments, was not compared with `.SRCINFO` | Compare the active configuration by hand |
| `srcinfo-missing` | MEDIUM | AUR snapshot has no `.SRCINFO` | Regenerate with `makepkg --printsrcinfo` |
| `arch-any` | INFO | `arch=('any')` with build logic | Confirm no compiled output is shipped |
| `signature-not-verified` | MEDIUM | A `.sig`/`.asc`/`.sign` source is declared but `validpgpkeys` is absent, so any trusted key in the user's keyring is accepted | Add `validpgpkeys` pinning the expected key; makepkg still verifies the signature itself. A `.gpg`/`.pgp` file is not a signature to makepkg and is checked like any other source |
| `prebuilt-payload` | MEDIUM | The package ships a downloaded binary: a `-bin` name, a `.deb`/`.rpm`/`.AppImage`/`.run`/`.7z` source, or no `build()` and a `package()` that only extracts a payload. The checksum binds the download to the PKGBUILD, not to upstream | Record an upstream-published hash or signature, or a vendor update-manifest hash, for this exact file with the URL; npm tarballs clear via the collector's integrity/shasum comparison. Without one the verdict stays REVIEW |
| `provenance-mismatch` | HIGH | The file matches the PKGBUILD but not the upstream hash, vendor manifest, or npm metadata published for it | Never; either upstream republished it or the metadata was altered |

## Reading severities

`HIGH` blocks the build. `MEDIUM` blocks until dispositioned in writing. `LOW` is context for the verdict. `INFO` exists so the reviewer sees the shape of the package, not to be cleared line by line.

The script's findings are static text matches. Line numbers point at the first occurrence inside the function or array; multi-line commands report their first line. Verify before quoting a finding as fact.
