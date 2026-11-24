# Provenance recipes

A checksum in the PKGBUILD proves that makepkg downloads the bytes the AUR
upload names. It says nothing about who published them. For every remote
source, record:

- the URL you compared against,
- the value it published, and
- whether that value is signed or only served over HTTPS.

A matching PKGBUILD sum with no upstream comparison is `none`, not a pass.

## GitHub release assets (automated)

`audit.py --verify-sources` computes SHA-256 regardless of the algorithm the
PKGBUILD declares, fetches `SHA256SUMS` from the same release, and reports
`provenance: upstream SHA256SUMS matches` / `differs` / `asset absent`. A
`differs` result is `provenance-mismatch` and a BLOCK.

## npm registry tarballs (automated)

For `https://registry.npmjs.org/<pkg>/-/<name>-<version>.tgz`,
`audit.py --verify-sources`:

- reads the packument version whose `dist.tarball` is the exact URL,
- compares SHA-512 with `dist.integrity` and SHA-1 with `dist.shasum`,
- verifies the registry's ECDSA signatures over
  `<pkg>@<version>:<integrity>` when `openssl` is installed.

The report reads `provenance: npm <pkg>@<version>: sha512 integrity matches,
sha1 shasum matches, npm registry signatures N/M verified` (or `no registry
signatures`, or `signatures not checked (openssl absent)`). Any digest or
signature mismatch is `provenance-mismatch` and a BLOCK.

Registry signatures attest the npm metadata, not the publisher's identity.
Check the packument's `maintainers` and any `dist.attestations` separately.
Manual fallback:

```bash
curl -s https://registry.npmjs.org/@scope/name/1.2.3 \
  | jq '{version, dist}'
```

## Vendor update manifests (manual)

Some vendors publish no release checksums but expose an update endpoint that
returns the current version and hash. Example (Tencent WorkBuddy):

```bash
curl -s 'https://copilot.tencent.com/v2/update?platform=workbuddy-win32-x64-archive' \
  | jq '{version, sha256hash, url}'
```

Compare `sha256hash` with the PKGBUILD's `sha256sums_x86_64` entry for that
file. This is unsigned HTTPS metadata from the vendor's own server: it proves
the vendor published that hash, not that a signing key endorsed it. Record the
exact URL and call it an unsigned vendor manifest. When the manifest's version
differs from the PKGBUILD's pin, the PKGBUILD is stale rather than tampered;
record both versions.

## Debian/RPM payloads

Confirm the archive layout before trusting a port's claims about which parts
run:

```bash
bsdtar -tf pkg.deb                     # debian-binary, control.tar.*, data.tar.*
ctl=$(bsdtar -tf pkg.deb | grep -E '^control\.tar\.(xz|zst|gz)$')
bsdtar -xOf pkg.deb "$ctl" | bsdtar -tf -
```

The second command lists the maintainer scripts (`preinst`, `postinst`,
`prerm`, `postrm`). A port that extracts only `data.tar.*` never executes
them; verify that claim against the build script. Signature verification for
`.deb`/`.rpm` payloads is not performed by the collector.

## No upstream hash

Record `none`, name what you looked for, and leave the verdict at REVIEW. Do
not invent a hash from the AUR snapshot or from a mirror.
