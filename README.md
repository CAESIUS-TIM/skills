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
skills/aur-security-audit/
├── SKILL.md
├── references/
│   ├── checks.md
│   ├── provenance.md
│   └── threat-model.md
└── scripts/
    ├── audit.py
    ├── inspect_pkg.py
    └── selftest.sh
```

Requirements: Python 3.12+, `git`, `bash`, and network access for AUR/vendor metadata.
`bsdtar` is required by the post-build `inspect_pkg.py`; `openssl` enables npm registry
signature checks; `namcap` is optional.

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

See [`skills/aur-security-audit/SKILL.md`](skills/aur-security-audit/SKILL.md) for the
full workflow, verdict rules, and limits.
