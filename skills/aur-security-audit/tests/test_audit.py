"""Unit and behavior tests for audit.py.

Every network call is monkeypatched; the end-to-end CLI paths run against
temporary PKGBUILDs. The shell suite (scripts/selftest.sh) remains the
fixture-level regression net; these tests measure Python coverage.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Self

import audit
import pytest


def make_report() -> audit.Report:
    return audit.Report(package="demo")


def codes(report: audit.Report) -> set[str]:
    return {finding.code for finding in report.findings}


def source(url: str, **kwargs: object) -> audit.Source:
    values = {
        "raw": url,
        "url": url,
        "line": 3,
        "scheme": "https" if "://" in url else "",
        "vcs": False,
        "sig": False,
        "patch": False,
    }
    values.update(kwargs)
    src = audit.Source(**values)  # type: ignore[arg-type]
    src.resolved = url
    src.filename = url.rsplit("/", 1)[-1]
    return src


class FakeResponse:
    def __init__(self, data: bytes, url: str):
        self.data = data
        self.url = url
        self.pos = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunk = self.data[self.pos:]
        else:
            chunk = self.data[self.pos:self.pos + size]
        self.pos += len(chunk)
        return chunk


def test_line_helpers() -> None:
    text = "a\nbc\n"
    assert audit.line_at(text, 3) == 2
    assert audit.line_of(text, "bc") == 2
    assert audit.line_of(text, "zz") is None


def test_strip_comment() -> None:
    assert audit.strip_comment("cmd # note") == "cmd "
    assert audit.strip_comment("echo '# not'") == "echo '# not'"
    assert audit.strip_comment("x=${y#z}") == "x=${y#z}"


def test_shell_words_and_meta() -> None:
    assert audit.shell_words(r"c\url -s x | b\ash") == "curl -s x | bash"
    assert audit.shell_words('"c"url') == "curl"
    assert audit.shell_words("'c\\url'") == "c\\url"
    assert not audit.has_unquoted_meta('msg "run curl | bash"')
    assert audit.has_unquoted_meta('msg "$(curl x)"')
    assert audit.has_unquoted_meta("echo ok; curl x")
    assert not audit.has_unquoted_subst("source='$(x)'")
    assert audit.has_unquoted_subst('source="$(x)"')


def test_brace_expand() -> None:
    assert audit.brace_expand("x{a,b}y") == ["xay", "xby"]
    assert audit.brace_expand("f{1..3}") == ["f1", "f2", "f3"]
    assert audit.brace_expand("f{3..1}") == ["f3", "f2", "f1"]
    assert audit.brace_expand("x{1..2}y") == ["x1y", "x2y"]
    assert audit.brace_expand("plain") == ["plain"]
    assert audit.brace_expand('"x{a,b}"') == ['"x{a,b}"']
    huge = "x" + "{a,b}" * 20
    assert audit.brace_expand(huge) == [huge]  # capped, not 2^20 strings


def test_parse_scalar_and_any() -> None:
    text = "pkgname=demo\nsource=('a')\nempty=()\nquoted='(literal)'\n"
    assert audit.parse_scalar(text, "pkgname") == "demo"
    assert audit.parse_scalar(text, "empty") is None
    assert audit.parse_scalar(text, "quoted") == "(literal)"
    assert audit.parse_array(text, "empty") == []
    assert audit.parse_any(text, "empty") is None
    assert audit.parse_any(text, "source") == [("a", 2)]


def test_parse_array_scopes() -> None:
    text = (
        "source=('a' 'b')\n"
        "sha256sums[1]='SKIP'\n"
        "prepare() {\n"
        "  sha256sums[0]='deadbeef'\n"
        "}\n"
        "if true; then\n"
        "  source+=('c')\n"
        "fi\n"
        "(\n"
        "  sha256sums[1]='x'\n"
        ")\n"
    )
    assert audit.parse_array(text, "source") == [("a", 1), ("b", 1)]
    sums = audit.parse_array(text, "sha256sums")
    assert sums is not None and sums[0] == ("", 2) and sums[1] == ("SKIP", 2)
    assert audit.parse_array(text, "no_such") is None
    assert len(audit.scoped_assignments(text, "sha256sums")) == 2
    assert audit.indexed_assignments(text, "sha256sums") == [("1", 2)]
    assert not audit.array_is_static(text, "source")


def test_conditional_lines() -> None:
    text = "a=1\nif true; then\n b=2\nfi\n(c=3)\nd=4\n"
    lines = audit.conditional_lines(text)
    assert 2 in lines and 3 in lines and 4 in lines
    assert 1 not in lines


def test_function_bodies_comment_and_braces() -> None:
    text = (
        "post_install() # comment\n"
        "{\n"
        "  echo $(echo })\n"
        "  echo ok\n"
        "}\n"
        "function other {\n"
        "  :\n"
        "}\n"
    )
    bodies = audit.function_bodies(text)
    names = [f[0] for f in bodies]
    assert names == ["post_install", "other"]
    assert "echo ok" in bodies[0][3]


def test_expand_vars() -> None:
    variables = {"pkgname": "demo", "pkgver": "1.0"}
    assert audit.expand_vars("$pkgname-${pkgver}", variables) == ("demo-1.0", True)
    value, ok = audit.expand_vars("$pkgname/${pkgver//_/-}", variables)
    assert not ok and "${pkgver//_/-}" in value
    assert audit.expand_deep("$url", {"url": "$url"}) == ("$url", False)


def test_parse_sources_states() -> None:
    report = make_report()
    text = (
        "source=('http://e/x.tar.gz' 'git+http://e/r.git'\n"
        "        'p.tar.gz' 'i.png' 'd.patch' '${arr[@]/#/x}')\n"
        "sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')\n"
        "cksums=('1')\n"
        "validpgpkeys=('KEY')\n"
    )
    audit.parse_sources(report, text, {"pkgname": "demo", "pkgver": "1"})
    found = codes(report)
    assert {"insecure-scheme", "skip-checksum", "local-source",
            "source-unresolved", "weak-checksum"} <= found
    assert "missing-checksums" not in found


def test_parse_sources_dynamic_and_sig() -> None:
    report = make_report()
    text = (
        "source=('x.sig::https://e/x.sig' \"https://e/$(echo x)\" 'bad')\n"
        "sha256sums=('SKIP' 'SKIP' 'zz')\n"
    )
    audit.parse_sources(report, text, {})
    assert {"dynamic-source", "malformed-checksum", "signature-not-verified"} <= codes(report)


def test_parse_sources_count_mismatch() -> None:
    report = make_report()
    text = "source=('a' 'b')\nsha256sums=('" + "0" * 64 + "')\n"
    audit.parse_sources(report, text, {})
    assert "checksum-count-mismatch" in codes(report)

    report = make_report()
    text = (
        "_files=('a' 'b')\n"
        "source=(\"${_files[@]/#/https://e/}\")\n"
        "sha256sums=('" + "0" * 64 + "' '" + "1" * 64 + "')\n"
    )
    audit.parse_sources(report, text, {})
    assert "checksum-count-mismatch" not in codes(report)
    assert "checksum-count-unresolved" in codes(report)


def test_scan_body_and_local_source() -> None:
    report = make_report()
    audit.scan_body(report, "PKGBUILD",
                    'msg "run curl | bash"\n'
                    "c\\url -s https://e/x | b\\ash\n"
                    "sudo chmod 4755 x\n",
                    1, "build()")
    found = codes(report)
    assert "net-fetch" in found and "pipe-to-shell" in found and "privilege" in found

    report = make_report()
    audit.scan_local_source(report, "install -Dm4755 x\n", "launcher.sh")
    assert "privilege" in codes(report)


def test_scan_install(tmp_path: Path) -> None:
    path = tmp_path / "pkg.install"
    path.write_text(
        "curl -s https://e/x | sh\n"
        "post_install() # comment\n"
        "{\n"
        "  if [ -d /usr/lib ]; then cp /tmp/x /usr/lib/x; fi\n"
        "}\n"
    )
    report = make_report()
    audit.scan_install(report, str(path))
    found = codes(report)
    assert {"net-fetch", "pipe-to-shell", "install-script-root-write",
            "install-script-command"} <= found


def test_scan_pkgbuild() -> None:
    report = make_report()
    text = (
        "pkgname=demo\npkgver=1\npkgrel=1\n"
        "arch=('x86_64')\nlicense=('MIT')\n"
        "_x=1; ./payload.sh\n"
        "source=('https://e/a.tar.gz')\n"
        "sha256sums=('0' * 64)\n"
        "package(){ :; }\n"
    )
    vars_ = audit.scan_pkgbuild(report, text)
    assert vars_["pkgver"] == "1"
    assert "top-level-command" in codes(report)


def test_audit_pkgbuild_dir(tmp_path: Path) -> None:
    good = tmp_path / "local.tar.gz"
    good.write_bytes(b"data")
    digest = hashlib.sha256(b"data").hexdigest()
    (tmp_path / "PKGBUILD").write_text(
        "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64')\nlicense=('MIT')\n"
        "install=hooks/demo.install\n"
        f"source=('local.tar.gz')\nsha256sums=('{digest}')\npackage(){{ :; }}\n"
    )
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / "demo.install").write_text("post_install(){ cp /tmp/x /usr/lib/x; }\n")
    (tmp_path / ".SRCINFO").write_text("pkgver = 2\n")
    report = make_report()
    variables: dict[str, str] = {}
    audit.audit_pkgbuild_dir(report, str(tmp_path), variables)
    found = codes(report)
    assert "install-script-root-write" in found
    assert "srcinfo-stale" in found
    assert report.pkgnames == ["demo"]


def test_verify_sources_local(tmp_path: Path) -> None:
    payload = tmp_path / "a.bin"
    payload.write_bytes(b"payload")
    digest = hashlib.sha256(b"payload").hexdigest()

    report = make_report()
    src = source("a.bin", scheme="")
    src.sums = {"sha256sums": digest}
    report.sources = [src]
    audit.verify_sources(report, {}, str(tmp_path), remote=False)
    assert src.verify == "verified"

    report = make_report()
    missing = source("missing.bin", scheme="")
    missing.sums = {"sha256sums": "0" * 64}
    report.sources = [missing]
    audit.verify_sources(report, {}, str(tmp_path), remote=False)
    assert missing.verify == "local-missing"
    assert "source-unverified" in codes(report)

    report = make_report()
    outside = source("../outside", scheme="")
    outside.sums = {"sha256sums": "0" * 64}
    report.sources = [outside]
    audit.verify_sources(report, {}, str(tmp_path), remote=False)
    assert outside.verify == "local-escapes-snapshot"


def test_verify_sources_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report()
    src = source("https://e/a.tar.gz")
    src.sums = {"sha256sums": "a" * 64}
    report.sources = [src]
    monkeypatch.setattr(audit, "_digest_url_multi", lambda *a, **k: {"sha256sums": "a" * 64})
    audit.verify_sources(report, {}, "/tmp", remote=True)
    assert src.verify == "verified"


def test_verify_sources_github_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://github.com/o/r/releases/download/v1/a.tar.gz"
    report = make_report()
    src = source(url)
    src.sums = {"sha512sums": "c" * 128}
    report.sources = [src]
    monkeypatch.setattr(audit, "_digest_url_multi",
                        lambda *a, **k: {"sha512sums": "c" * 128, "sha256sums": "b" * 64})
    monkeypatch.setattr(audit, "upstream_sums", lambda *a: ({"a.tar.gz": "b" * 64}, ""))
    audit.verify_sources(report, {}, "/tmp", remote=True)
    assert src.provenance == "upstream SHA256SUMS matches"


def test_verify_sources_github_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://github.com/o/r/releases/download/v1/a.tar.gz"
    report = make_report()
    src = source(url)
    src.sums = {"sha512sums": "c" * 128}
    report.sources = [src]
    monkeypatch.setattr(audit, "_digest_url_multi",
                        lambda *a, **k: {"sha512sums": "c" * 128, "sha256sums": "b" * 64})
    monkeypatch.setattr(audit, "upstream_sums", lambda *a: ({"a.tar.gz": "d" * 64}, ""))
    audit.verify_sources(report, {}, "/tmp", remote=True)
    assert src.provenance == "upstream SHA256SUMS differs"
    assert "provenance-mismatch" in codes(report)


def test_verify_sources_npm(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"
    sha512 = "c" * 128
    sha1 = "d" * 40
    integrity = "sha512-" + base64.b64encode(bytes.fromhex(sha512)).decode()
    report = make_report()
    src = source(url)
    src.sums = {"sha256sums": "b" * 64}
    report.sources = [src]
    monkeypatch.setattr(audit, "_digest_url_multi",
                        lambda *a, **k: {"sha256sums": "b" * 64, "sha512sums": sha512,
                                         "sha1sums": sha1})
    monkeypatch.setattr(audit, "npm_packument",
                        lambda *a: ({"package": "@scope/pkg", "version": "1.0.0",
                                     "integrity": integrity, "shasum": sha1,
                                     "signatures": [{}]}, ""))
    monkeypatch.setattr(audit, "npm_verify_signatures", lambda *a: (True, "1/1 verified"))
    audit.verify_sources(report, {}, "/tmp", remote=True)
    assert src.provenance is not None and "matches" in src.provenance
    assert not report.findings


def test_verify_sources_download_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report()
    src = source("https://e/a.tar.gz")
    src.sums = {"sha256sums": "a" * 64}
    report.sources = [src]
    monkeypatch.setattr(audit, "_digest_url_multi",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    audit.verify_sources(report, {}, "/tmp", remote=True)
    assert src.verify.startswith("download-failed")
    assert "source-unverified" in codes(report)


def test_fetch_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"abc", "https://e/x"))
    assert audit.fetch("https://e/x") == b"abc"

    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"abc", "http://e/x"))
    with pytest.raises(SystemExit):
        audit.fetch("https://e/x")

    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"0123456789", "https://e/x"))
    with pytest.raises(SystemExit):
        audit.fetch("https://e/x", max_bytes=4)


def test_digest_url_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://e/a.tar.gz"
    cache = tmp_path / "a.tar.gz"
    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"payload", "https://e/a.tar.gz"))
    digests = audit._digest_url_multi(url, ["sha256sums"], str(cache))
    assert digests["sha256sums"] == hashlib.sha256(b"payload").hexdigest()
    assert cache.read_bytes() == b"payload"
    assert cache.with_name("a.tar.gz.url").read_text().strip() == url

    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    assert audit._digest_url_multi(url, ["sha256sums"], str(cache))["sha256sums"] == (
        hashlib.sha256(b"payload").hexdigest())

    other = tmp_path / "other.tar.gz"
    other.write_bytes(b"foreign")
    assert not audit._cache_matches(str(other), url)


def test_cache_helpers(tmp_path: Path) -> None:
    path = tmp_path / "a.tar.gz"
    path.write_bytes(b"x")
    audit._write_cache_url(str(path), "https://e/a")
    assert audit._cache_matches(str(path), "https://e/a")
    audit._drop_cache(str(path))
    assert not path.exists()

    part = tmp_path / "a.part"
    os.symlink(tmp_path / "victim", part)
    with audit._open_part(str(part)) as handle:
        handle.write(b"ok")
    assert part.read_bytes() == b"ok"
    part.unlink()
    part.mkdir()
    with pytest.raises(ValueError):
        audit._open_part(str(part))


def test_safe_extract(tmp_path: Path) -> None:
    good = tmp_path / "good.tar"
    with tarfile.open(good, "w") as tar:
        data = b"x"
        info = tarfile.TarInfo("pkg/file")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    dest = tmp_path / "out"
    dest.mkdir()
    with tarfile.open(good) as tar:
        audit.safe_extract(tar, str(dest))
    assert (dest / "pkg" / "file").read_bytes() == b"x"

    bad = tmp_path / "bad.tar"
    with tarfile.open(bad, "w") as tar:
        info = tarfile.TarInfo("pkg/abs")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with tarfile.open(bad) as tar, pytest.raises(SystemExit):
        audit.safe_extract(tar, str(dest))

    traversal = tmp_path / "traversal.tar"
    with tarfile.open(traversal, "w") as tar:
        info = tarfile.TarInfo("../escape")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    with tarfile.open(traversal) as tar, pytest.raises(SystemExit):
        audit.safe_extract(tar, str(dest))


def test_load_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"pkgname=demo\n"
        info = tarfile.TarInfo("demo/PKGBUILD")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    monkeypatch.setattr(audit, "fetch", lambda *a, **k: buffer.getvalue())
    snap = audit.load_snapshot("demo", str(tmp_path))
    assert Path(snap, "PKGBUILD").is_file()

    monkeypatch.setattr(audit, "fetch", lambda *a, **k: b"")
    with pytest.raises(SystemExit):
        audit.load_snapshot("demo", str(tmp_path))


def test_git_history(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    class Result:
        def __init__(self, out: str, rc: int = 0, err: str = ""):
            self.stdout, self.returncode, self.stderr = out, rc, err

    def fake(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> Result:
        calls.append(cmd)
        if "clone" in cmd:
            return Result("")
        if "log" in cmd:
            return Result("abc\x1fa\x1fa@x\x1f2026-01-01T00:00:00+00:00\x1fsubject\n"
                          "def\x1fb\x1fb@x\x1f2025-01-01T00:00:00+00:00\x1fupgpkg\n"
                          "bad\x1frow\n")
        return Result("diff --git a/PKGBUILD b/PKGBUILD\n")

    monkeypatch.setattr(audit, "sh", fake)
    authors, commits, diff, err = audit.git_history("demo", "/tmp")
    assert err is None and commits == 2 and diff and len(authors) == 2


def test_rpc_and_portfolio(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"results": [{"Name": "demo", "Version": "1-1"}]}
    monkeypatch.setattr(audit, "fetch", lambda *a, **k: json.dumps(payload).encode())
    assert audit.rpc_info("demo")["Name"] == "demo"

    monkeypatch.setattr(audit, "fetch",
                        lambda *a, **k: json.dumps({"resultcount": 1,
                                                    "results": [{"FirstSubmitted": 0}]}).encode())
    assert "maintainer demo" in audit.aur_maintainer_portfolio("demo")


def test_upstream_sums_and_npm(monkeypatch: pytest.MonkeyPatch) -> None:
    assert audit.upstream_sums("https://example.org/x")[0] is None

    url = "https://github.com/o/r/releases/download/v1/a.tar.gz"
    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"abc  a.tar.gz\n", "https://e"))
    entries, _ = audit.upstream_sums(url)
    assert entries == {"a.tar.gz": "abc"}

    doc = {"versions": {"1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                                           "integrity": "sha512-x", "shasum": "d"}}}}
    monkeypatch.setattr(audit, "fetch", lambda *a, **k: json.dumps(doc).encode())
    meta, why = audit.npm_packument("https://registry.npmjs.org/x/-/x-1.0.0.tgz")
    assert meta is not None and meta["version"] == "1.0.0" and why == ""

    monkeypatch.setattr(audit.shutil, "which", lambda *a: None)
    assert audit.npm_verify_signatures({"signatures": [{}]}) == (None, "openssl absent")
    assert audit.npm_verify_signatures({"signatures": []}) == (None, "no npm registry signatures")


def test_display_and_human_report() -> None:
    assert audit._display("a\x1b]0;x\x07b") == "a\\x1b]0;x\\x07b"
    report = make_report()
    report.add(audit.HIGH, "net-fetch", "bad", evidence="x\x1b")
    report.sources = [source("https://e/a")]
    report.history_note = "clone failed"
    report.last_change_diff = "\n".join(f"+line{i}" for i in range(70))
    text = audit.human_report(report)
    assert "DO NOT BUILD" in text
    assert "\\x1b" in text
    assert "AUR git history unavailable" in text
    assert "10 more lines omitted" in text


def test_main_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = tmp_path / "a.bin"
    payload.write_bytes(b"x")
    digest = hashlib.sha256(b"x").hexdigest()
    (tmp_path / "PKGBUILD").write_text(
        "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64')\nlicense=('MIT')\n"
        f"source=('a.bin')\nsha256sums=('{digest}')\npackage(){{ :; }}\n"
    )
    out = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["audit.py", "--pkgbuild", str(tmp_path),
                                      "--no-history", "--json", str(out)])
    assert audit.main() == 0
    assert json.loads(out.read_text())["package"] == tmp_path.name


def test_main_usage_conflicts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["audit.py"])
    with pytest.raises(SystemExit) as err:
        audit.main()
    assert err.value.code == 64

    monkeypatch.setattr(sys, "argv", ["audit.py", "demo", "--pkgbuild", "/tmp"])
    with pytest.raises(SystemExit) as err:
        audit.main()
    assert err.value.code == 64


def test_main_aur(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "PKGBUILD").write_text(
        "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64')\nlicense=('MIT')\n"
        "source=()\nsha256sums=()\npackage(){ :; }\n"
    )
    monkeypatch.setattr(audit, "rpc_info", lambda name: {
        "Name": "demo", "Version": "1-1", "Maintainer": "m", "FirstSubmitted": 0,
        "LastModified": 0, "NumVotes": 1, "Popularity": 0.0, "PackageBase": "demo"})
    monkeypatch.setattr(audit, "aur_maintainer_portfolio", lambda name: "portfolio")
    monkeypatch.setattr(audit, "load_snapshot", lambda base, workdir: str(snap))
    monkeypatch.setattr(audit, "git_history",
                        lambda base, workdir: ([{"name": "m", "email": "m@x", "names": ["m"],
                                                 "commits": 1,
                                                 "last": "2026-01-01T00:00:00+00:00",
                                                 "first": "2026-01-01T00:00:00+00:00",
                                                 "last_subject": "s"}], 1, "", None))
    monkeypatch.setattr(sys, "argv", ["audit.py", "demo", "--keep-snapshot", str(tmp_path / "keep")])
    assert audit.main() in (0, 2)


def test_main_local_json_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\n")
    monkeypatch.setattr(sys, "argv", ["audit.py", "--pkgbuild", str(tmp_path),
                                      "--no-history", "--json", str(tmp_path / "missing" / "x.json")])
    with pytest.raises(SystemExit):
        audit.main()


def test_fetch_retry_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise audit.urllib.error.URLError("offline")

    monkeypatch.setattr(audit.urllib.request, "urlopen", boom)
    with pytest.raises(SystemExit):
        audit.fetch("https://e/x", attempts=1)
    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"x", "https://e/x"))
    with pytest.raises(SystemExit):
        audit.fetch("https://e/x", max_bytes=0)


def test_git_history_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        def __init__(self, out: str = "", rc: int = 0, err: str = "") -> None:
            self.stdout, self.returncode, self.stderr = out, rc, err

    monkeypatch.setattr(audit, "sh", lambda *a, **k: Result(rc=1, err="clone failed"))
    assert audit.git_history("demo", "/tmp")[3] == "clone failed"

    def timeout(*args: object, **kwargs: object) -> Result:
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(audit, "sh", timeout)
    assert "timed out" in (audit.git_history("demo", "/tmp")[3] or "")

    def log_fail(cmd: list[str], **kwargs: object) -> Result:
        if "clone" in cmd:
            return Result()
        return Result(rc=1, err="log failed")

    monkeypatch.setattr(audit, "sh", log_fail)
    assert audit.git_history("demo", "/tmp")[3] == "log failed"

    def diff_timeout(cmd: list[str], **kwargs: object) -> Result:
        if "clone" in cmd:
            return Result()
        if "log" in cmd:
            return Result(out="abc\x1fa\x1fa@x\x1f2026-01-01T00:00:00+00:00\x1fs\n")
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(audit, "sh", diff_timeout)
    assert audit.git_history("demo", "/tmp")[2] == ""


def test_load_snapshot_bad_tar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "fetch", lambda *a, **k: b"not a tarball")
    with pytest.raises(SystemExit):
        audit.load_snapshot("demo", str(tmp_path))


def test_upstream_sums_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://github.com/o/r/releases/download/v2/a.tar.gz"
    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(audit.urllib.error.URLError("x")))
    entries, why = audit.upstream_sums(url)
    assert entries is None and "no upstream" in why
    assert audit.upstream_sums(url) == (None, why)  # cached

    url = "https://github.com/o/r/releases/download/v3/a.tar.gz"
    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"", "https://e"))
    entries, why = audit.upstream_sums(url)
    assert entries == {} and "empty" in why


def test_npm_signature_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "NPM_KEYS_CACHE", None)
    monkeypatch.setattr(audit.shutil, "which", lambda *a: "/usr/bin/openssl")
    monkeypatch.setattr(audit, "fetch",
                        lambda *a, **k: json.dumps({"keys": [
                            {"keyid": "k", "key": base64.b64encode(b"key").decode()}]}).encode())
    monkeypatch.setattr(audit.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, b"", b""))
    meta = {"package": "p", "version": "1", "integrity": "sha512-x",
            "signatures": [{"keyid": "k", "sig": base64.b64encode(b"sig").decode()}]}
    assert audit.npm_verify_signatures(meta) == (True, "npm registry signatures 1/1 verified")


def test_npm_packument_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://registry.npmjs.org/y/-/y-1.0.0.tgz"
    monkeypatch.setattr(audit, "fetch", lambda *a, **k: (_ for _ in ()).throw(SystemExit("x")))
    assert audit.npm_packument(url) == (None, "npm metadata unreachable")
    assert audit.npm_packument("https://example.org/x")[0] is None


def test_verify_sources_states(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report()
    vcs = source("git+https://e/r", vcs=True)
    sig = source("https://e/a.sig", sig=True)
    ftp = source("ftp://e/a", scheme="ftp")
    ftp.sums = {"sha256sums": "a" * 64}
    nosum = source("https://e/b")
    unresolved = source("https://e/${x}", verify="unexpanded-variable")
    dynamic = source("https://e/$(x)", verify="dynamic-source")
    report.sources = [vcs, sig, ftp, nosum, unresolved, dynamic]
    monkeypatch.setattr(audit, "_digest_url_multi",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    audit.verify_sources(report, {}, "/tmp", remote=True)
    assert vcs.verify == "not-applicable"
    assert sig.verify == "not-applicable"
    assert ftp.verify == "unverifiable"
    assert nosum.verify == "no-strong-sum"
    assert unresolved.verify == "unexpanded-variable"


def test_verify_sources_cache_and_mismatch(tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://e/a.tar.gz"
    data = b"payload"
    digest = hashlib.sha256(data).hexdigest()
    cache = tmp_path / "a.tar.gz"
    cache.write_bytes(data)
    audit._write_cache_url(str(cache), url)
    report = make_report()
    src = source(url)
    src.sums = {"sha256sums": digest}
    report.sources = [src]
    monkeypatch.setattr(audit.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    assert audit.verify_sources(report, {}, "/tmp", remote=True, cache_dir=str(tmp_path)) == (0, 1)
    assert src.verify == "verified"

    # A foreign same-named file is not used as the download.
    foreign = tmp_path / "foreign.tar.gz"
    foreign.write_bytes(b"foreign")
    report = make_report()
    src2 = source("https://e/foreign.tar.gz")
    src2.sums = {"sha256sums": hashlib.sha256(b"new").hexdigest()}
    report.sources = [src2]
    seen: list[str | None] = []

    def digest(_url: str, _algs: list[str], cache_path: str | None = None) -> dict[str, str]:
        seen.append(cache_path)
        return {"sha256sums": hashlib.sha256(b"new").hexdigest()}

    monkeypatch.setattr(audit, "_digest_url_multi", digest)
    audit.verify_sources(report, {}, "/tmp", remote=True, cache_dir=str(tmp_path))
    assert seen == [None] and foreign.read_bytes() == b"foreign"

    report = make_report()
    src3 = source("https://e/mismatch.tar.gz")
    src3.sums = {"sha256sums": "0" * 64}
    report.sources = [src3]
    monkeypatch.setattr(audit, "_digest_url_multi",
                        lambda *a, **k: {"sha256sums": "1" * 64})
    audit.verify_sources(report, {}, "/tmp", remote=True)
    assert src3.verify.startswith("MISMATCH")
    assert "checksum-mismatch" in codes(report)


def test_record_hash_and_local_sig(tmp_path: Path) -> None:
    report = make_report()
    src = source("x")
    audit._record_hash(report, src, "sha256sums", "a" * 64, "b" * 64, "file")
    assert src.verify.startswith("MISMATCH") and "checksum-mismatch" in codes(report)

    sigfile = tmp_path / "x.sig"
    sigfile.write_bytes(b"sig")
    report = make_report()
    sig = source("x.sig", scheme="", sig=True)
    sig.resolved = "x.sig"
    report.sources = [sig]
    audit.verify_sources(report, {}, str(tmp_path), remote=False)
    assert sig.verify == "not-applicable"


def test_parse_sources_extras() -> None:
    report = make_report()
    text = (
        "source_x86_64=('a.tar.gz' 'b.patch')\n"
        "sha256sums_x86_64=('" + "0" * 64 + "' 'SKIP')\n"
        "md5sums_x86_64=('" + "0" * 32 + "' '" + "1" * 32 + "')\n"
    )
    audit.parse_sources(report, text, {"pkgname": "demo"})
    found = codes(report)
    assert "weak-checksum" in found
    assert any(f.severity == audit.LOW and f.code == "skip-checksum" for f in report.findings)

    report = make_report()
    audit.parse_sources(report, "source=('a')\n", {})
    assert "missing-checksums" in codes(report)

    report = make_report()
    audit.parse_sources(report, "pkgname=demo\n", {})
    assert "no-sources" in codes(report)

    report = make_report()
    report.pkgnames = ["demo-bin"]
    audit.parse_sources(report, "source=('https://e/a')\nsha256sums=('" + "0" * 64 + "')\n",
                        {"pkgname": "demo"})
    assert "prebuilt-payload" in codes(report)


def test_audit_pkgbuild_install_errors(tmp_path: Path) -> None:
    for name, install in (("a", "missing.install"),
                          ("b", "/etc/passwd"),
                          ("c", "${unknown}.install")):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "PKGBUILD").write_text(
            "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64')\nlicense=('MIT')\n"
            f"install={install}\nsource=()\nsha256sums=()\npackage(){{ :; }}\n"
        )
        report = make_report()
        audit.audit_pkgbuild_dir(report, str(directory), {})
        assert "install-missing" in codes(report)

    bad = tmp_path / "syntax"
    bad.mkdir()
    (bad / "PKGBUILD").write_text("pkgname=demo\nif true; then\n")
    report = make_report()
    audit.audit_pkgbuild_dir(report, str(bad), {})
    assert "syntax-error" in codes(report)


def test_human_report_extra() -> None:
    report = make_report()
    report.sources_verified = False
    report.sources = [source("https://e/a")]
    report.sources[0].provenance = "upstream SHA256SUMS matches"
    report.authors = [{"name": f"a{i}", "email": f"a{i}@x", "names": [f"a{i}"], "commits": 1,
                       "last": "2026-01-01T00:00:00+00:00",
                       "first": "2026-01-01T00:00:00+00:00", "last_subject": "s"}
                      for i in range(8)]
    report.commits = 8
    report.notes = ["note"]
    text = audit.human_report(report)
    assert "more authors" in text and "provenance:" in text and "Note: note" in text
    assert "REVIEW (sources unverified)" in text


def test_main_aur_orphan_and_committer(tmp_path: Path,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "PKGBUILD").write_text(
        "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64')\nlicense=('MIT')\n"
        "source=()\nsha256sums=()\npackage(){ :; }\n"
    )
    authors = [
        {"name": "new", "email": "new@x", "names": ["new"], "commits": 1,
         "last": "2026-01-02T00:00:00+00:00", "first": "2026-01-02T00:00:00+00:00",
         "last_subject": "bump"},
        {"name": "old", "email": "old@x", "names": ["old"], "commits": 9,
         "last": "2025-01-02T00:00:00+00:00", "first": "2025-01-02T00:00:00+00:00",
         "last_subject": "init"},
    ]
    monkeypatch.setattr(audit, "rpc_info", lambda name: {
        "Name": "demo", "Version": "1-1", "FirstSubmitted": 0, "LastModified": 0,
        "NumVotes": 1, "Popularity": 0.0, "PackageBase": "demo"})
    monkeypatch.setattr(audit, "load_snapshot", lambda base, workdir: str(snap))
    monkeypatch.setattr(audit, "git_history", lambda base, workdir: (authors, 10, "", None))
    monkeypatch.setattr(sys, "argv", ["audit.py", "demo", "--keep-snapshot", str(tmp_path / "k")])
    assert audit.main() in (0, 2)
