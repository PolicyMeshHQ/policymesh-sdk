# Changelog

## 0.4.1 - Unreleased Pilot Gate

- Require explicit SDK killswitch confirmation before calling admin kill routes.
- Add live smoke tooling for staging API-key tenant binding and admin bearer-auth checks.
- Add release workflow checks that reject tag/package version mismatch.

## 0.4.0 - Hardening Baseline

- Align package metadata around `pyproject.toml`.
- Align SDK version export with package version.
- Expand action type contract to the 26 backend/public action types.
- Make boolean `allow()` fail closed by default.
- Add typed HTTP/API exceptions and shared response handling.
- Add SDK user-agent and request correlation headers.
- Add explicit `admin_token` requirement for killswitch admin helpers.
- Add framework-neutral adapter helpers.
- Add runnable dry-run examples for OpenAI, Claude, LangChain, CrewAI, and custom agents.
- Add staging smoke script.
- Add CI, release runbook, and API reference.
- Set supported Python policy to `3.10+`.
