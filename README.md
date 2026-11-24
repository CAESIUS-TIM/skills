# skills

Agent skills maintained by [CAESIUS-TIM](https://github.com/CAESIUS-TIM), laid out for
[`skills.sh`](https://skills.sh) / `npx skills` discovery.

## Install

Requires Node.js 22.20 or later.

```bash
# just this skill, globally, for Claude Code and OpenCode
npx skills@latest add CAESIUS-TIM/skills -g \
  -s aur-security-audit -a claude-code -a opencode

# list what the repository exposes before installing
npx skills@latest add CAESIUS-TIM/skills --list
```

The installer copies the skill to the canonical `~/.agents/skills/<name>` directory and
links it into the selected agent directories. Add `--copy` if symlinks are not suitable.

## Skills

### `aur-security-audit`

Audit an AUR package before building or updating it: static PKGBUILD and `.install`
review, source and checksum verification, upstream provenance for prebuilt payloads,
AUR git-history takeover check, and a gated clean-chroot build.

```
.githooks/
├── pre-commit        # gitleaks on staged changes + working tree
└── pre-push          # full-history gitleaks scan + just check
.gitleaks.toml        # upstream rules + repository allowlist
skills/aur-security-audit/
├── SKILL.md
├── references/
│   ├── checks.md
│   ├── provenance.md
│   └── threat-model.md
├── scripts/
│   ├── audit.py
│   ├── inspect_pkg.py
│   └── selftest.sh
└── tests/
    ├── test_audit.py
    └── test_inspect_pkg.py
```

Requirements: Python 3.12.11+, 3.13.4+, or 3.14+ (patched tarfile extraction filter),
`git`, `bash`, and network access for AUR/vendor metadata.
`bsdtar` is required by the post-build `inspect_pkg.py` only when the interpreter's
`tarfile` cannot read zstd; `openssl` enables npm registry signature checks; `namcap`
is optional.

Direct collector use:

```bash
python3 ~/.agents/skills/aur-security-audit/scripts/audit.py <pkgname> \
  --keep-snapshot /tmp/aur-audit-<pkgname> --verify-sources \
  --cache-dir /tmp/aur-cache --json /tmp/<pkgname>.json
```

Run the offline test suite from the installed or checked-out skill directory:

```bash
cd ~/.agents/skills/aur-security-audit
bash scripts/selftest.sh
```

From a repository checkout, `just` wraps the checks. Development tools (`ruff`, `mypy`,
`pytest`, `coverage`) are fetched through `uvx` when not installed:

```bash
just hooks        # git config core.hooksPath .githooks
just secrets      # gitleaks dir: working tree
just secrets-staged  # gitleaks git --staged
just secrets-history # gitleaks git: full history
just lint         # py_compile + ruff + mypy + bash -n/shellcheck
just types        # mypy: every script def annotated (see pyproject.toml)
just test-py      # pytest + branch coverage (floor: 80%)
just test         # test-py + offline shell fixture suite
just check        # lint + test + secret scan (CI entry point)
just verify       # lint + test + a real AUR smoke audit
```

Secret scanning uses [`gitleaks`](https://github.com/gitleaks/gitleaks) with the
upstream rule set and `.gitleaks.toml` (generated paths, plus the public key used by
the offline PKGBUILD fixtures). Output is redacted. `pre-commit` scans staged changes
and the working tree; `pre-push` scans full git history, then runs `just check`.
Install gitleaks (for example `pacman -S gitleaks`) before using the hooks.

Coverage is measured on `scripts/audit.py` and `scripts/inspect_pkg.py`; the floor is
enforced by `[tool.coverage.report] fail_under` in `pyproject.toml`.

See [`skills/aur-security-audit/SKILL.md`](skills/aur-security-audit/SKILL.md) for the
full workflow, verdict rules, and limits.
