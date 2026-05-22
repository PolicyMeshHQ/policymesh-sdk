# PolicyMesh SDK API Reference

## PolicyMeshClient

Supported Python runtime: `3.10+`.

```python
PolicyMeshClient(
    org_id: str,
    api_key: str,
    api_url: str = "https://policymesh-production.up.railway.app/api/v1",
    raise_on_block: bool = True,
    raise_on_escalate: bool = False,
    agent_id: Optional[str] = None,
    timeout: float = 10,
    max_retries: int = 0,
    fail_open: bool = False,
    admin_token: Optional[str] = None,
)
```

- `org_id`: PolicyMesh organization ID.
- `api_key`: Organization API key for agent-facing endpoints.
- `api_url`: Environment-specific `/api/v1` base URL.
- `raise_on_block`: Raise `PolicyBlockedError` for blocked decisions.
- `raise_on_escalate`: Raise `PolicyEscalateError` for escalate decisions.
- `agent_id`: Optional default agent ID for scan/payload/tool helpers.
- `timeout`: Request timeout in seconds.
- `max_retries`: Retries for connection, timeout, and server errors. Defaults to `0`.
- `fail_open`: Boolean helper fallback. Defaults to `False`.
- `admin_token`: Dashboard-user bearer token for admin-only calls.

## Methods

### `evaluate(...)`

Evaluates an agent action before execution.

Returns `PolicyDecision`.

Common action fields:
- `agent_id`
- `action_type`
- `data_classification`
- `environment` defaults to `development`; pass `staging` or `production` explicitly.
- `record_count`
- `destination`
- `description`
- `metadata`
- `trace`

### `scan(...)`

Scans input before an agent processes it.

Returns `ScanResult`.

### `inspect_payload(...)`

Inspects outbound payloads before data leaves the agent boundary.

Returns `ScanResult`.

### `check_tool(...)`

Checks a tool name against approved and blocked tool lists.

Returns `ScanResult`.

### `guard(...)`

Decorator that evaluates a policy before running a function.

### `allow(...)`

Convenience boolean wrapper. Defaults to fail-closed. Prefer `evaluate()` or
`guard()` for enforcement paths that need full decision or error details.

### `kill(...)` and `revive(...)`

Administrative helpers. These require `admin_token` because backend killswitch
routes require authenticated dashboard-user context. API-key-only agent clients
should not use these methods for admin operations.

## Exceptions

- `PolicyBlockedError`
- `PolicyEscalateError`
- `PolicyMeshAuthError`
- `PolicyMeshForbiddenError`
- `PolicyMeshValidationError`
- `PolicyMeshRateLimitError`
- `PolicyMeshServerError`
- `PolicyMeshTimeoutError`
- `PolicyMeshConnectionError`
- `PolicyMeshUnexpectedResponseError`

All SDK API exceptions inherit from `PolicyMeshError`.
