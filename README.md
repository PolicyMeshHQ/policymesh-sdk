# PolicyMesh Python SDK

Official Python SDK for the [PolicyMesh](https://policymesh.net) AI agent security and policy enforcement platform.

PolicyMesh lets teams evaluate agent actions before execution, scan untrusted input before an agent uses it, and inspect outbound payloads before data leaves the agent boundary.

## Current Package

- Package: `policymesh`
- Current SDK version: `0.4.0`
- API base path: `/api/v1`
- Default production API: `https://policymesh-production.up.railway.app/api/v1`
- Source repo: `https://github.com/Hail15/policymesh-sdk`
- API reference: [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)
- Release controls: [`docs/RELEASE.md`](docs/RELEASE.md)

For demos, tests, and pilots, pass the environment-specific API URL supplied by PolicyMesh. Do not use production for test data, stress testing, or demo setup unless production use has been explicitly approved.

## Installation

```bash
pip install policymesh
```

## Configure The Client

```python
from policymesh import PolicyMeshClient

client = PolicyMeshClient(
    org_id="your_org_id",
    api_key="your_api_key",
    api_url="https://policymesh-production.up.railway.app/api/v1",
    timeout=10,
    max_retries=0,
)
```

The API key is bound to a PolicyMesh organization. Requests must include the matching `org_id`; cross-organization API key use should fail.

You can also set `POLICYMESH_API_URL` before importing the SDK:

```bash
export POLICYMESH_API_URL="https://policymesh-production.up.railway.app/api/v1"
```

SDK action helpers default the action `environment` field to `development`.
Pass `environment="staging"` or `environment="production"` only when the
target environment is intentional and approved.

For staging smoke tests:

```bash
POLICYMESH_API_URL="https://policymesh-staging.up.railway.app/api/v1" \
POLICYMESH_ORG_ID="your_staging_org_id" \
POLICYMESH_API_KEY="your_staging_api_key" \
python scripts/staging_smoke.py
```

## Core Flow

A normal integration has three checkpoints:

1. Scan input before the agent processes it.
2. Evaluate the action before the agent executes it.
3. Inspect outbound payloads before the agent sends data externally.

```python
from policymesh import PolicyMeshClient, PolicyBlockedError

client = PolicyMeshClient(
    org_id="your_org_id",
    api_key="your_api_key",
    raise_on_block=True,
)

scan = client.scan(
    agent_id="support-agent",
    content="Customer request text or tool output goes here",
    source="customer_ticket",
)

if scan.is_blocked:
    raise PolicyBlockedError(f"Unsafe input blocked: {scan.message}")

decision = client.evaluate(
    agent_id="support-agent",
    action_type="data_export",
    data_classification="confidential",
    environment="production",
    record_count=1500,
    destination="external@example.com",
    description="Exporting customer records to an external destination",
)

payload_check = client.inspect_payload(
    agent_id="support-agent",
    action_type="external_api_call",
    destination="https://api.partner.example",
    payload={"record_count": 1500},
    approved_domains=["api.partner.example"],
)

if payload_check.is_blocked:
    raise PolicyBlockedError(f"Outbound payload blocked: {payload_check.message}")
```

## Evaluate Without Raising

For audit-mode reporting, demos, and dashboards, it is often useful to inspect the decision object directly.

```python
from policymesh import PolicyMeshClient

client = PolicyMeshClient(
    org_id="your_org_id",
    api_key="your_api_key",
    raise_on_block=False,
)

decision = client.evaluate(
    agent_id="finance-agent",
    action_type="payment",
    data_classification="confidential",
    environment="production",
    record_count=1,
    destination="payment_processor",
    description="Submitting a high-value payment for approval",
)

print(decision.decision)
print(decision.policy_matched)
print(decision.would_have_blocked)
```

In audit mode, PolicyMesh may allow the action while still returning `would_have_blocked=True` to show what enforcement would have stopped.

## Guard Decorator

Use `guard()` when a function should not run unless PolicyMesh allows the action.

```python
from policymesh import PolicyMeshClient

client = PolicyMeshClient(
    org_id="your_org_id",
    api_key="your_api_key",
    raise_on_block=True,
)

@client.guard(
    action_type="production_deploy",
    agent_id="deploy-agent",
    environment="production",
)
def deploy_to_production():
    print("Deploying to production")

deploy_to_production()
```

## Tool And Payload Checks

```python
tool_check = client.check_tool(
    agent_id="research-agent",
    tool_name="browser",
    approved_tools=["database_query", "email_send", "browser"],
    blocklisted_tools=["unknown_webhook"],
)

if not tool_check.is_safe:
    raise PolicyBlockedError(f"Tool blocked: {tool_check.message}")

payload_check = client.inspect_payload(
    agent_id="research-agent",
    action_type="external_api_call",
    destination="https://api.partner.example",
    payload={"summary": "redacted business data"},
    approved_domains=["api.partner.example"],
)
```

## Action Types

| Action Type | Description |
|-------------|-------------|
| `data_export` | Exporting data to external systems |
| `data_access` | Accessing sensitive data |
| `data_delete` | Deleting data |
| `data_modify` | Modifying data |
| `external_email` | Sending emails to external addresses |
| `external_message` | Sending external messages |
| `webhook_call` | Calling webhooks |
| `production_deploy` | Deploying to production |
| `code_execution` | Executing code |
| `file_read` | Reading files |
| `file_write` | Writing files |
| `file_delete` | Deleting files |
| `permission_change` | Modifying permissions |
| `auth_change` | Changing authentication |
| `api_key_create` | Creating API keys |
| `payment` | Processing payments |
| `vendor_action` | Vendor operations |
| `external_api_call` | Calling external APIs |
| `web_browse` | Browsing the web |
| `web_scrape` | Scraping web content |
| `database_query` | Querying databases |
| `database_write` | Writing to databases |
| `database_delete` | Deleting from databases |
| `model_call` | Calling AI models |
| `prompt_injection` | Detected prompt injection |
| `custom` | Custom action types |

## Data Classifications

| Classification | Description |
|----------------|-------------|
| `public` | Publicly available data |
| `internal` | Internal company data |
| `confidential` | Confidential business data |
| `restricted` | Highly restricted or regulated data |

## Decision Handling

PolicyMesh returns one of four decision values:

| Decision | Meaning |
|----------|---------|
| `allow` | The action can proceed. |
| `flag` | The action can proceed but should be reviewed or reported. |
| `escalate` | Human approval is required before proceeding. |
| `block` | The action must not proceed. |

With `raise_on_block=True`, blocked actions raise `PolicyBlockedError`. With `raise_on_escalate=True`, escalated actions raise `PolicyEscalateError`.

## Boolean Checks

`client.allow(...)` is a convenience wrapper for simple conditional logic. For enforcement paths, prefer `evaluate()` or `guard()` so the caller can handle block, escalate, flag, auth failure, rate limit, and connection failure explicitly.

`allow()` fails closed by default. If a telemetry-only deployment needs fail-open behavior, it must be explicitly configured:

```python
client = PolicyMeshClient(
    org_id="your_org_id",
    api_key="your_api_key",
    fail_open=True,
)
```

## Admin Controls

Agent killswitch and revive operations are administrative controls in the PolicyMesh backend. They require authenticated user context and organization access checks. API-key-only agent clients cannot perform admin operations.

```python
client = PolicyMeshClient(
    org_id="your_org_id",
    api_key="your_api_key",
    admin_token="dashboard_user_bearer_token",
)

client.kill("agent-id", reason="Approved incident response action")
```

## Framework Examples

Runnable dry-run examples are included for:

- OpenAI: [`examples/openai_agent.py`](examples/openai_agent.py)
- Claude: [`examples/anthropic_claude_agent.py`](examples/anthropic_claude_agent.py)
- LangChain: [`examples/langchain_agent.py`](examples/langchain_agent.py)
- CrewAI: [`examples/crewai_agent.py`](examples/crewai_agent.py)
- Custom agents: [`examples/custom_agent.py`](examples/custom_agent.py)

The examples run without live credentials using a dry-run client. Set `POLICYMESH_ORG_ID`, `POLICYMESH_API_KEY`, and `POLICYMESH_API_URL` to run them against a real environment.

## Error Handling

SDK API exceptions inherit from `PolicyMeshError` and include request context where available.

Common errors:

- `PolicyMeshAuthError`
- `PolicyMeshForbiddenError`
- `PolicyMeshValidationError`
- `PolicyMeshRateLimitError`
- `PolicyMeshServerError`
- `PolicyMeshTimeoutError`
- `PolicyMeshConnectionError`
- `PolicyMeshUnexpectedResponseError`

The SDK sends a `User-Agent`, `X-PolicyMesh-SDK`, and `X-Request-ID` header with API calls to help correlate SDK calls with API-side evidence.

## Sensitive Data Guidance

The SDK can send action descriptions, metadata, traces, scanned input, and payload inspection data to PolicyMesh. Send the minimum detail needed for policy evaluation and audit evidence. Avoid sending secrets, raw credentials, full regulated records, or unnecessary customer content in `metadata`, `trace`, or `payload` fields.

## Getting An API Key

1. Sign in at [https://policymesh.net](https://policymesh.net).
2. Open **API Keys** in the dashboard.
3. Generate an organization API key.
4. Store the key securely. It is shown only once.

## Links

- [Dashboard](https://policymesh.net)
- [API reference](docs/API_REFERENCE.md)
- [Release controls](docs/RELEASE.md)
- [SDK issues](https://github.com/Hail15/policymesh-sdk/issues)
- [SDK source](https://github.com/Hail15/policymesh-sdk)
