# SDK Release Controls

Status: internal release runbook.

## Role Ownership

- Release approver: technical trust owner.
- Release executor: engineering/platform lead.
- PyPI token owner: role-owned secret in the approved password manager.
- Emergency deprecation owner: engineering/platform lead with technical trust owner notification.

Do not publish from a personal long-lived token. Use a scoped PyPI token for the
`policymesh` project and rotate it if a release machine or account is suspected
to be compromised.

Preferred publishing path is the GitHub Actions release workflow using the
protected `pypi` environment and PyPI trusted publishing. Direct `twine upload`
from a workstation is reserved for approved break-glass release response.

## Required Pre-Release Evidence

Run and attach evidence to the release PR:

```bash
python -m py_compile $(find policymesh tests examples scripts -name '*.py' -type f | sort)
python -m unittest discover -s tests
python -m build
python -m twine check dist/*
pip-audit --local
```

Run examples in dry-run mode:

```bash
python examples/custom_agent.py
python examples/openai_agent.py
python examples/anthropic_claude_agent.py
python examples/langchain_agent.py
python examples/crewai_agent.py
```

Run staging smoke with pilot-safe credentials:

```bash
POLICYMESH_API_URL=https://policymesh-staging.up.railway.app/api/v1 \
POLICYMESH_ORG_ID=... \
POLICYMESH_API_KEY=... \
python scripts/staging_smoke.py
```

Run admin bearer-auth smoke with a staging dashboard admin token:

```bash
POLICYMESH_API_URL=https://policymesh-staging.up.railway.app/api/v1 \
POLICYMESH_ORG_ID=... \
POLICYMESH_API_KEY=... \
POLICYMESH_ADMIN_TOKEN=... \
python scripts/admin_auth_smoke.py
```

The admin smoke must prove:

- API-key-only admin calls are rejected.
- SDK admin helpers fail before network without `admin_token`.
- SDK `kill()` fails before network without `confirm="KILL-{agent_id}"`.
- Bearer-auth kill succeeds.
- Evaluation blocks the killed agent with `Agent Killswitch`.
- Bearer-auth revive succeeds.
- Evaluation no longer blocks the revived agent because of killswitch state.

## Release Checklist

1. Confirm `pyproject.toml` and `policymesh.__version__` match.
2. Confirm README and API reference match the released behavior.
3. Confirm SDK issue links and validation evidence are posted.
4. Tag the release after approval:
   ```bash
   git tag v0.4.1
   git push origin v0.4.1
   ```
5. Build from a clean checkout:
   ```bash
   python -m build
   python -m twine check dist/*
   ```
6. Publish through the protected GitHub Actions release workflow. For an
   approved break-glass release only, publish manually:
   ```bash
   python -m twine upload dist/*
   ```
7. Create a GitHub release with validation evidence and notable changes.
8. Install from PyPI in a clean environment and run the import smoke.

## Broken Release Response

1. Stop promoting the broken version in README/docs.
2. Publish a patch release as soon as the fix is validated.
3. If the release is unsafe, mark it as yanked on PyPI with a clear reason.
4. Post the incident summary and remediation evidence to the linked SDK issue.
