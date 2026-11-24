# Tasks for the skills repository.
set shell := ["bash", "-uc"]

skill := "skills/aur-security-audit"
scripts := skill + "/scripts"
tests := skill + "/tests"

default: check

# Compile the collectors and run ruff when it is available.
lint-py:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 -m py_compile {{scripts}}/audit.py {{scripts}}/inspect_pkg.py
    if command -v ruff >/dev/null 2>&1; then ruff check {{scripts}} {{tests}}
    elif command -v uvx >/dev/null 2>&1; then uvx ruff check {{scripts}} {{tests}}
    else echo "ruff required (install ruff or uv)"; exit 1; fi

# Enforce annotations with mypy (strict-ish, see pyproject.toml).
types:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v mypy >/dev/null 2>&1; then mypy
    elif command -v uvx >/dev/null 2>&1; then uvx mypy
    else echo "mypy required (install mypy or uv)"; exit 1; fi

# Parse-check the shell entry points and run shellcheck when it is available.
lint-sh:
    #!/usr/bin/env bash
    set -euo pipefail
    bash -n {{scripts}}/selftest.sh .githooks/pre-commit .githooks/pre-push
    if command -v shellcheck >/dev/null 2>&1; then shellcheck {{scripts}}/selftest.sh .githooks/pre-commit .githooks/pre-push
    elif command -v uvx >/dev/null 2>&1; then uvx --from shellcheck-py shellcheck {{scripts}}/selftest.sh .githooks/pre-commit .githooks/pre-push
    else echo "shellcheck required (install shellcheck or uv)"; exit 1; fi

# Static checks only (offline).
lint: lint-py types lint-sh

# Python unit/behavior tests with branch coverage (network mocked).
test-py:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v uvx >/dev/null 2>&1; then
        uvx --with pytest --with pytest-cov coverage run -m pytest -q
        uvx coverage report
    elif command -v coverage >/dev/null 2>&1 && python3 -m pytest --version >/dev/null 2>&1; then
        coverage run -m pytest -q
        coverage report
    else
        echo "pytest and coverage required (install them or uv)"
        exit 1
    fi

# Offline shell fixture suite; must not touch the network.
selftest:
    bash {{scripts}}/selftest.sh

test: test-py selftest

# Scan the working tree, staged changes, or full history with gitleaks.
secrets:
    gitleaks dir . --redact --no-banner -v --config .gitleaks.toml

secrets-staged:
    gitleaks git . --staged --redact --no-banner -v --config .gitleaks.toml

secrets-history:
    gitleaks git . --redact --no-banner -v --config .gitleaks.toml

# Point git at the versioned hooks.
hooks:
    git config core.hooksPath .githooks
    chmod +x .githooks/pre-commit .githooks/pre-push
    @echo "hooks installed: core.hooksPath=.githooks"

# Everything CI should run.
check: lint test secrets

# Audit an AUR package by name. Extra arguments are passed through.
audit pkg *args:
    python3 {{scripts}}/audit.py {{pkg}} {{args}}

# Audit a local PKGBUILD directory offline.
audit-local dir *args:
    python3 {{scripts}}/audit.py --pkgbuild {{dir}} --no-history {{args}}

# Inventory a built package (.pkg.tar.zst).
inspect pkg:
    python3 {{scripts}}/inspect_pkg.py {{pkg}}

# Lint, test, then audit a real AUR package as a smoke test.
verify pkg="downgrade":
    just lint
    just test
    python3 {{scripts}}/audit.py {{pkg}} --no-history

clean:
    find . -type d -name __pycache__ -prune -exec rm -rf {} +
    rm -rf .ruff_cache .pytest_cache .coverage htmlcov
