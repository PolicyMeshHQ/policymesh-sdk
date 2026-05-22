import os
import time
import uuid
from functools import wraps
from typing import Any, Callable, List, Optional

import requests

from policymesh.exceptions import (
    PolicyBlockedError,
    PolicyEscalateError,
    PolicyMeshAuthError,
    PolicyMeshConnectionError,
    PolicyMeshError,
    PolicyMeshForbiddenError,
    PolicyMeshRateLimitError,
    PolicyMeshServerError,
    PolicyMeshTimeoutError,
    PolicyMeshUnexpectedResponseError,
    PolicyMeshValidationError,
)
from policymesh.models import Decision, PolicyDecision

SDK_VERSION = "0.4.0"
DEFAULT_API_URL = os.environ.get(
    "POLICYMESH_API_URL",
    "https://policymesh-production.up.railway.app/api/v1",
)
DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("POLICYMESH_TIMEOUT_SECONDS", "10"))


class TraceStep:
    """Represents a single step in an agent execution trace."""

    def __init__(
        self,
        step: int,
        type: str,
        timestamp: Optional[str] = None,
        model: Optional[str] = None,
        tool: Optional[str] = None,
        input: Optional[str] = None,
        output: Optional[str] = None,
        duration_ms: Optional[int] = None,
        metadata: Optional[dict] = None,
    ):
        self.step = step
        self.type = type
        self.timestamp = timestamp
        self.model = model
        self.tool = tool
        self.input = input
        self.output = output
        self.duration_ms = duration_ms
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "type": self.type,
            "timestamp": self.timestamp,
            "model": self.model,
            "tool": self.tool,
            "input": self.input,
            "output": self.output,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }


class ScanResult:
    """Result of a content, payload, or tool scan."""

    def __init__(self, data: dict):
        self.risk_score = data.get("risk_score", 0)
        self.recommendation = data.get("recommendation", "allow")
        self.safe = data.get("safe", True)
        self.findings = data.get("findings", [])
        self.findings_count = data.get("findings_count", len(self.findings))
        self.message = data.get("message", "")
        self.raw = data

    @property
    def is_blocked(self) -> bool:
        return self.recommendation == "block"

    @property
    def is_flagged(self) -> bool:
        return self.recommendation == "flag"

    @property
    def is_safe(self) -> bool:
        return self.recommendation == "allow"

    def __repr__(self) -> str:
        return (
            "ScanResult("
            f"risk_score={self.risk_score}, "
            f"recommendation={self.recommendation}, "
            f"findings={self.findings_count})"
        )


class PolicyMeshClient:
    """
    PolicyMesh Python SDK.

    Agent-facing methods use an organization API key. Administrative methods
    such as kill() and revive() require an authenticated dashboard user bearer
    token through admin_token.
    """

    def __init__(
        self,
        org_id: str,
        api_key: str,
        api_url: str = DEFAULT_API_URL,
        raise_on_block: bool = True,
        raise_on_escalate: bool = False,
        agent_id: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = 0,
        fail_open: bool = False,
        admin_token: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        self.org_id = org_id
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.raise_on_block = raise_on_block
        self.raise_on_escalate = raise_on_escalate
        self.default_agent_id = agent_id
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.fail_open = fail_open
        self.admin_token = admin_token
        self.session = session or requests.Session()

    def _headers(
        self,
        *,
        bearer_token: Optional[str] = None,
        request_id: Optional[str] = None,
        include_api_key: bool = True,
    ) -> dict:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"policymesh-python/{SDK_VERSION}",
            "X-PolicyMesh-SDK": f"python/{SDK_VERSION}",
            "X-Request-ID": request_id or str(uuid.uuid4()),
        }

        if include_api_key:
            headers["x-api-key"] = self.api_key
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        return headers

    @staticmethod
    def _response_json(response: requests.Response) -> dict:
        try:
            data = response.json()
        except ValueError as exc:
            raise PolicyMeshUnexpectedResponseError(
                f"PolicyMesh API returned non-JSON response: {response.text[:200]}",
                status_code=response.status_code,
                response=response.text,
                request_id=response.request.headers.get("X-Request-ID")
                if response.request
                else None,
            ) from exc

        if not isinstance(data, dict):
            raise PolicyMeshUnexpectedResponseError(
                "PolicyMesh API returned an unexpected JSON payload.",
                status_code=response.status_code,
                response=data,
                request_id=response.request.headers.get("X-Request-ID")
                if response.request
                else None,
            )

        return data

    @staticmethod
    def _detail(data: Any, default: str) -> str:
        if isinstance(data, dict):
            detail = data.get("detail") or data.get("message") or default
            return str(detail)
        return default

    def _raise_for_status(self, response: requests.Response) -> None:
        if 200 <= response.status_code < 300:
            return

        request_id = (
            response.request.headers.get("X-Request-ID")
            if response.request
            else response.headers.get("X-Request-ID")
        )

        try:
            data = response.json()
        except ValueError:
            data = {"detail": response.text}

        message = self._detail(
            data,
            f"PolicyMesh API returned HTTP {response.status_code}",
        )

        kwargs = {
            "status_code": response.status_code,
            "response": data,
            "request_id": request_id,
        }

        if response.status_code == 400 or response.status_code == 422:
            raise PolicyMeshValidationError(message, **kwargs)
        if response.status_code == 401:
            raise PolicyMeshAuthError(message, **kwargs)
        if response.status_code == 403:
            raise PolicyMeshForbiddenError(message, **kwargs)
        if response.status_code == 429:
            raise PolicyMeshRateLimitError(message, **kwargs)
        if response.status_code >= 500:
            raise PolicyMeshServerError(message, **kwargs)

        raise PolicyMeshUnexpectedResponseError(message, **kwargs)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_payload: Optional[dict] = None,
        params: Optional[dict] = None,
        bearer_token: Optional[str] = None,
        include_api_key: bool = True,
    ) -> dict:
        attempts = self.max_retries + 1
        last_error: Optional[Exception] = None

        for attempt in range(attempts):
            request_id = str(uuid.uuid4())
            try:
                response = self.session.request(
                    method,
                    f"{self.api_url}{path}",
                    json=json_payload,
                    params=params,
                    headers=self._headers(
                        bearer_token=bearer_token,
                        request_id=request_id,
                        include_api_key=include_api_key,
                    ),
                    timeout=self.timeout,
                )
                self._raise_for_status(response)
                if response.status_code == 204:
                    return {}
                return self._response_json(response)
            except requests.exceptions.Timeout as exc:
                last_error = PolicyMeshTimeoutError(
                    "PolicyMesh API timed out.",
                    request_id=request_id,
                )
                if attempt == attempts - 1:
                    raise last_error from exc
            except requests.exceptions.ConnectionError as exc:
                last_error = PolicyMeshConnectionError(
                    "Could not connect to PolicyMesh API.",
                    request_id=request_id,
                )
                if attempt == attempts - 1:
                    raise last_error from exc
            except PolicyMeshServerError:
                if attempt == attempts - 1:
                    raise
                last_error = None
            except PolicyMeshError:
                raise

            time.sleep(min(0.25 * (2**attempt), 2.0))

        raise PolicyMeshConnectionError(f"PolicyMesh request failed: {last_error}")

    def _post(self, path: str, payload: dict) -> dict:
        return self._request("POST", path, json_payload=payload)

    def evaluate(
        self,
        agent_id: str,
        action_type: str,
        data_classification: str = "internal",
        environment: str = "development",
        record_count: int = 0,
        destination: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[dict] = None,
        trace: Optional[List[TraceStep]] = None,
    ) -> PolicyDecision:
        """Evaluate an agent action before execution."""

        payload = {
            "agent_id": agent_id,
            "org_id": self.org_id,
            "action_type": action_type,
            "data_classification": data_classification,
            "environment": environment,
            "record_count": record_count,
            "destination": destination,
            "description": description,
            "metadata": metadata or {},
            "trace": [step.to_dict() for step in trace] if trace else [],
        }

        data = self._post("/evaluate", payload)

        decision = PolicyDecision(
            action_id=data["action_id"],
            agent_id=data["agent_id"],
            org_id=data["org_id"],
            action_type=data["action_type"],
            decision=Decision(data["decision"]),
            policy_matched=data.get("policy_matched"),
            would_have_blocked=data.get("would_have_blocked", False),
            message=data.get("message", ""),
        )

        if self.raise_on_block and decision.is_blocked:
            raise PolicyBlockedError(
                f"Action blocked by PolicyMesh: {decision.policy_matched}",
                action_id=decision.action_id,
                policy_matched=decision.policy_matched,
            )

        if self.raise_on_escalate and decision.is_escalated:
            raise PolicyEscalateError(
                f"Action requires approval: {decision.policy_matched}",
                action_id=decision.action_id,
                policy_matched=decision.policy_matched,
            )

        return decision

    def scan(
        self,
        content: str,
        agent_id: Optional[str] = None,
        content_type: str = "text",
        source: Optional[str] = None,
        scan_type: str = "full",
        raise_on_block: bool = False,
    ) -> ScanResult:
        """Scan content before an agent processes it."""

        payload = {
            "org_id": self.org_id,
            "agent_id": agent_id or self.default_agent_id or "sdk_agent",
            "content": content,
            "content_type": content_type,
            "source": source,
            "scan_type": scan_type,
        }

        result = ScanResult(self._post("/scan/content", payload))

        if raise_on_block and result.is_blocked:
            raise PolicyBlockedError(
                f"Content blocked by PolicyMesh scanner: {result.message}",
                policy_matched=f"Content Scan: {result.findings_count} findings",
            )

        return result

    def inspect_payload(
        self,
        action_type: str,
        agent_id: Optional[str] = None,
        destination: Optional[str] = None,
        payload: Optional[dict] = None,
        tool_name: Optional[str] = None,
        approved_domains: Optional[List[str]] = None,
        approved_tools: Optional[List[str]] = None,
        raise_on_block: bool = False,
    ) -> ScanResult:
        """Inspect an outbound payload before an agent sends it."""

        body = {
            "org_id": self.org_id,
            "agent_id": agent_id or self.default_agent_id or "sdk_agent",
            "action_type": action_type,
            "destination": destination,
            "payload": payload or {},
            "tool_name": tool_name,
            "approved_domains": approved_domains,
            "approved_tools": approved_tools,
        }

        result = ScanResult(self._post("/scan/payload", body))

        if raise_on_block and result.is_blocked:
            raise PolicyBlockedError(
                f"Payload blocked by PolicyMesh: {result.message}",
                policy_matched=f"Payload Inspection: {result.findings_count} findings",
            )

        return result

    def check_tool(
        self,
        tool_name: str,
        agent_id: Optional[str] = None,
        approved_tools: Optional[List[str]] = None,
        blocklisted_tools: Optional[List[str]] = None,
        raise_on_block: bool = False,
    ) -> ScanResult:
        """Check whether a tool is allowed before using it."""

        data = self._request(
            "POST",
            "/scan/tool",
            params={
                "org_id": self.org_id,
                "agent_id": agent_id or self.default_agent_id or "sdk_agent",
                "tool_name": tool_name,
                "approved_tools": approved_tools,
                "blocklisted_tools": blocklisted_tools,
            },
        )

        result = ScanResult(
            {
                "risk_score": data.get("risk_score", 0),
                "recommendation": "allow" if data.get("allowed") else "block",
                "safe": data.get("allowed", True),
                "findings": data.get("findings", []),
                "findings_count": len(data.get("findings", [])),
                "message": data.get("message", ""),
            }
        )

        if raise_on_block and not result.is_safe:
            raise PolicyBlockedError(
                f"Tool '{tool_name}' blocked by PolicyMesh",
                policy_matched="Tool Blocklist",
            )

        return result

    def kill(
        self,
        agent_id: str,
        reason: Optional[str] = None,
        killed_by: Optional[str] = None,
        expires_hours: Optional[int] = None,
        admin_token: Optional[str] = None,
    ) -> dict:
        """Disable an agent using authenticated dashboard-user context."""

        token = admin_token or self.admin_token
        if not token:
            raise PolicyMeshAuthError(
                "kill() requires admin_token because killswitch routes require "
                "authenticated dashboard user context."
            )

        return self._request(
            "POST",
            f"/killswitch/{self.org_id}/agent",
            json_payload={
                "agent_id": agent_id,
                "reason": reason or "Disabled via SDK",
                "killed_by": killed_by,
                "expires_hours": expires_hours,
            },
            bearer_token=token,
            include_api_key=False,
        )

    def revive(self, agent_id: str, admin_token: Optional[str] = None) -> dict:
        """Re-enable a disabled agent using authenticated dashboard-user context."""

        token = admin_token or self.admin_token
        if not token:
            raise PolicyMeshAuthError(
                "revive() requires admin_token because killswitch routes require "
                "authenticated dashboard user context."
            )

        return self._request(
            "DELETE",
            f"/killswitch/{self.org_id}/agent/{agent_id}",
            bearer_token=token,
            include_api_key=False,
        )

    def guard(
        self,
        action_type: str,
        agent_id: str = "sdk_agent",
        data_classification: str = "internal",
        environment: str = "development",
        record_count: int = 0,
        destination: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[dict] = None,
        trace: Optional[List[TraceStep]] = None,
    ) -> Callable:
        """Decorator that runs PolicyMesh evaluation before a function."""

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                decision = self.evaluate(
                    agent_id=agent_id,
                    action_type=action_type,
                    data_classification=data_classification,
                    environment=environment,
                    record_count=record_count,
                    destination=destination,
                    description=description or f"Calling {func.__name__}",
                    metadata=metadata,
                    trace=trace,
                )
                if decision.is_blocked:
                    raise PolicyBlockedError(
                        (
                            f"Function {func.__name__} blocked by PolicyMesh: "
                            f"{decision.policy_matched}"
                        ),
                        action_id=decision.action_id,
                        policy_matched=decision.policy_matched,
                    )
                if self.raise_on_escalate and decision.is_escalated:
                    raise PolicyEscalateError(
                        (
                            f"Function {func.__name__} requires approval: "
                            f"{decision.policy_matched}"
                        ),
                        action_id=decision.action_id,
                        policy_matched=decision.policy_matched,
                    )
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def allow(self, agent_id: str, action_type: str, **kwargs: Any) -> bool:
        """
        Boolean helper for simple checks.

        Defaults to fail-closed. Set fail_open=True only for explicitly approved
        telemetry-only deployments where availability is preferred over blocking.
        """

        try:
            decision = self.evaluate(agent_id=agent_id, action_type=action_type, **kwargs)
            return decision.is_allowed or decision.is_flagged
        except (PolicyBlockedError, PolicyEscalateError):
            return False
        except Exception:
            return bool(self.fail_open)
