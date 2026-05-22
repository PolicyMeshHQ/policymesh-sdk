import os
from typing import Optional, List

import requests
from policymesh.models import AgentAction, PolicyDecision, Decision, ActionType, DataClassification
from policymesh.exceptions import (
    PolicyBlockedError,
    PolicyEscalateError,
    PolicyMeshConnectionError,
    PolicyMeshAuthError
)

DEFAULT_API_URL = os.environ.get(
    "POLICYMESH_API_URL",
    "https://policymesh-production.up.railway.app/api/v1"
)


class TraceStep:
    """
    Represents a single step in an agent's execution trace.

    Usage:
        trace = [
            TraceStep(step=1, type="model_call", model="gpt-4", input="summarize data", output="querying db..."),
            TraceStep(step=2, type="tool_call", tool="database_query", output="1500 records returned"),
            TraceStep(step=3, type="action", input="export to email"),
        ]
    """
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
        metadata: Optional[dict] = None
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

    def to_dict(self):
        return {
            "step": self.step,
            "type": self.type,
            "timestamp": self.timestamp,
            "model": self.model,
            "tool": self.tool,
            "input": self.input,
            "output": self.output,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata
        }


class ScanResult:
    """
    Result of a content or payload scan.

    Attributes:
        risk_score      0-100. >= 70 = block, 40-69 = flag, < 40 = allow
        recommendation  "block", "flag", or "allow"
        safe            True if risk_score < 40
        findings        List of detected threats with type, description, severity
        findings_count  Number of findings
        message         Human-readable summary
    """
    def __init__(self, data: dict):
        self.risk_score = data.get("risk_score", 0)
        self.recommendation = data.get("recommendation", "allow")
        self.safe = data.get("safe", True)
        self.findings = data.get("findings", [])
        self.findings_count = data.get("findings_count", 0)
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

    def __repr__(self):
        return f"ScanResult(risk_score={self.risk_score}, recommendation={self.recommendation}, findings={self.findings_count})"


class PolicyMeshClient:
    """
    PolicyMesh Python SDK v0.4.0

    Three methods for full 360-degree agent governance:

        evaluate()        — controls what agents DO
        scan()            — controls what agents SEE (input scanning)
        inspect_payload() — controls what agents SEND (output scanning)

    Admin controls such as kill() and revive() require authenticated dashboard
    user context in the backend. Do not rely on API-key-only SDK calls for
    admin operations until that path is explicitly validated.

    Usage:
        from policymesh import PolicyMeshClient, TraceStep

        client = PolicyMeshClient(
            org_id="your_org_id",
            api_key="your_api_key"
        )

        # 1. Scan content before agent processes it
        scan = client.scan(content=webpage_html, source="https://example.com")
        if scan.is_blocked:
            raise Exception(f"Unsafe content: {scan.message}")

        # 2. Evaluate the action the agent wants to take
        decision = client.evaluate(
            agent_id="my_agent",
            action_type="data_export",
            data_classification="confidential",
            record_count=1500,
            destination="external@gmail.com"
        )

        # 3. Inspect outbound payload before sending
        payload_check = client.inspect_payload(
            action_type="external_api_call",
            destination="https://api.partner.com",
            payload={"customer_data": records}
        )
        if payload_check.is_blocked:
            raise Exception(f"Payload blocked: {payload_check.message}")
    """

    def __init__(
        self,
        org_id: str,
        api_key: str,
        api_url: str = DEFAULT_API_URL,
        raise_on_block: bool = True,
        raise_on_escalate: bool = False,
        agent_id: Optional[str] = None
    ):
        self.org_id = org_id
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.raise_on_block = raise_on_block
        self.raise_on_escalate = raise_on_escalate
        self.default_agent_id = agent_id  # Set once, use everywhere

    def _headers(self) -> dict:
        return {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }

    def _post(self, path: str, payload: dict) -> dict:
        try:
            response = requests.post(
                f"{self.api_url}{path}",
                json=payload,
                headers=self._headers(),
                timeout=10
            )
            if response.status_code == 401:
                raise PolicyMeshAuthError(
                    "Authentication failed. Check your api_key and org_id. "
                    "Generate API keys at https://policymesh.net"
                )
            if response.status_code == 429:
                raise PolicyMeshConnectionError(
                    f"Rate limit exceeded: {response.json().get('detail', 'Monthly action limit reached.')}"
                )
            if response.status_code not in (200, 201):
                raise PolicyMeshConnectionError(
                    f"PolicyMesh API returned {response.status_code}: {response.text}"
                )
            return response.json()
        except (PolicyBlockedError, PolicyEscalateError, PolicyMeshAuthError, PolicyMeshConnectionError):
            raise
        except requests.exceptions.ConnectionError:
            raise PolicyMeshConnectionError(
                "Could not connect to PolicyMesh API. Check your network connection."
            )
        except requests.exceptions.Timeout:
            raise PolicyMeshConnectionError(
                "PolicyMesh API timed out. Try again or check your connection."
            )
        except Exception as e:
            raise PolicyMeshConnectionError(f"Unexpected error: {e}")

    # ── EVALUATE ─────────────────────────────────────────────────────────────

    def evaluate(
        self,
        agent_id: str,
        action_type: str,
        data_classification: str = "internal",
        environment: str = "production",
        record_count: int = 0,
        destination: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[dict] = None,
        trace: Optional[List[TraceStep]] = None
    ) -> PolicyDecision:
        """
        Evaluate an agent action against PolicyMesh policies.

        This is the core method — call it before any agent action.
        Optionally include a trace of the agent's execution chain for
        full decision explainability in the dashboard.

        Returns a PolicyDecision. Raises PolicyBlockedError if blocked
        and raise_on_block=True (default).
        """
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
            "trace": [t.to_dict() for t in trace] if trace else []
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
            message=data.get("message", "")
        )

        if self.raise_on_block and decision.is_blocked:
            raise PolicyBlockedError(
                f"Action blocked by PolicyMesh: {decision.policy_matched}",
                action_id=decision.action_id,
                policy_matched=decision.policy_matched
            )

        if self.raise_on_escalate and decision.is_escalated:
            raise PolicyEscalateError(
                f"Action requires approval: {decision.policy_matched}",
                action_id=decision.action_id,
                policy_matched=decision.policy_matched
            )

        return decision

    # ── SCAN ─────────────────────────────────────────────────────────────────

    def scan(
        self,
        content: str,
        agent_id: Optional[str] = None,
        content_type: str = "text",
        source: Optional[str] = None,
        scan_type: str = "full",
        raise_on_block: bool = False
    ) -> ScanResult:
        """
        Scan content for prompt injection and sensitive data before
        your agent processes it.

        Call this before feeding web pages, documents, database results,
        user inputs, or any external content to your agent.

        Args:
            content       The text content to scan
            agent_id      Which agent will process this content
            content_type  "text", "html", "json", or "url"
            source        Where the content came from (URL, filename, etc.)
            scan_type     "full", "injection_only", or "sensitive_only"
            raise_on_block If True, raises PolicyBlockedError when blocked

        Returns a ScanResult with risk_score, recommendation, and findings.

        Example:
            scan = client.scan(
                content=webpage_content,
                source="https://example.com",
                content_type="html"
            )
            if scan.is_blocked:
                raise Exception("Unsafe content detected")
        """
        payload = {
            "org_id": self.org_id,
            "agent_id": agent_id or self.default_agent_id or "sdk_agent",
            "content": content,
            "content_type": content_type,
            "source": source,
            "scan_type": scan_type
        }

        data = self._post("/scan/content", payload)
        result = ScanResult(data)

        if raise_on_block and result.is_blocked:
            raise PolicyBlockedError(
                f"Content blocked by PolicyMesh scanner: {result.message}",
                action_id=None,
                policy_matched=f"Content Scan — {result.findings_count} findings"
            )

        return result

    # ── INSPECT PAYLOAD ───────────────────────────────────────────────────────

    def inspect_payload(
        self,
        action_type: str,
        agent_id: Optional[str] = None,
        destination: Optional[str] = None,
        payload: Optional[dict] = None,
        tool_name: Optional[str] = None,
        approved_domains: Optional[List[str]] = None,
        approved_tools: Optional[List[str]] = None,
        raise_on_block: bool = False
    ) -> ScanResult:
        """
        Inspect an outbound payload before your agent sends it.

        Checks for sensitive data exfiltration, unapproved destinations,
        unapproved tool usage, and suspicious patterns in outbound data.

        Args:
            action_type     The type of action being performed
            agent_id        Which agent is sending this payload
            destination     Where the payload is being sent (URL, email, etc.)
            payload         The data being sent (dict)
            tool_name       Name of the tool being called
            approved_domains List of allowed destination domains
            approved_tools  List of allowed tool names
            raise_on_block  If True, raises PolicyBlockedError when blocked

        Returns a ScanResult with risk_score, recommendation, and findings.

        Example:
            check = client.inspect_payload(
                action_type="external_api_call",
                destination="https://api.partner.com",
                payload={"records": customer_data},
                approved_domains=["api.partner.com", "api.stripe.com"]
            )
            if check.is_blocked:
                raise Exception("Payload blocked — sensitive data detected")
        """
        body = {
            "org_id": self.org_id,
            "agent_id": agent_id or self.default_agent_id or "sdk_agent",
            "action_type": action_type,
            "destination": destination,
            "payload": payload or {},
            "tool_name": tool_name,
            "approved_domains": approved_domains,
            "approved_tools": approved_tools
        }

        data = self._post("/scan/payload", body)
        result = ScanResult(data)

        if raise_on_block and result.is_blocked:
            raise PolicyBlockedError(
                f"Payload blocked by PolicyMesh: {result.message}",
                action_id=None,
                policy_matched=f"Payload Inspection — {result.findings_count} findings"
            )

        return result

    # ── CHECK TOOL ────────────────────────────────────────────────────────────

    def check_tool(
        self,
        tool_name: str,
        agent_id: Optional[str] = None,
        approved_tools: Optional[List[str]] = None,
        blocklisted_tools: Optional[List[str]] = None,
        raise_on_block: bool = False
    ) -> ScanResult:
        """
        Check if a tool is on the allowlist or blocklist before use.

        Args:
            tool_name         The name of the tool the agent wants to use
            agent_id          Which agent is using the tool
            approved_tools    List of allowed tool names
            blocklisted_tools List of blocked tool names
            raise_on_block    If True, raises PolicyBlockedError when blocked

        Returns a ScanResult indicating if the tool is allowed.

        Example:
            check = client.check_tool(
                tool_name="zapier_webhook",
                approved_tools=["database_query", "email_send", "web_search"]
            )
            if not check.is_safe:
                raise Exception(f"Tool not allowed: {tool_name}")
        """
        try:
            response = requests.post(
                f"{self.api_url}/scan/tool",
                params={
                    "org_id": self.org_id,
                    "agent_id": agent_id or self.default_agent_id or "sdk_agent",
                    "tool_name": tool_name,
                    "approved_tools": approved_tools,
                    "blocklisted_tools": blocklisted_tools
                },
                headers=self._headers(),
                timeout=10
            )
            data = response.json()
            result = ScanResult({
                "risk_score": data.get("risk_score", 0),
                "recommendation": "allow" if data.get("allowed") else "block",
                "safe": data.get("allowed", True),
                "findings": data.get("findings", []),
                "findings_count": len(data.get("findings", [])),
                "message": data.get("message", "")
            })

            if raise_on_block and not result.is_safe:
                raise PolicyBlockedError(
                    f"Tool '{tool_name}' blocked by PolicyMesh",
                    action_id=None,
                    policy_matched="Tool Blocklist"
                )

            return result
        except PolicyBlockedError:
            raise
        except Exception as e:
            raise PolicyMeshConnectionError(f"Tool check failed: {e}")

    # ── KILLSWITCH ────────────────────────────────────────────────────────────

    def kill(
        self,
        agent_id: str,
        reason: Optional[str] = None,
        killed_by: Optional[str] = None,
        expires_hours: Optional[int] = None
    ) -> dict:
        """
        Administrative helper for disabling an agent.

        Current backend killswitch routes require authenticated dashboard user
        context and organization access checks. API-key-only agent clients
        should not rely on this method until the admin SDK path is validated.

        Args:
            agent_id      The agent to kill
            reason        Why the agent is being killed
            killed_by     Who is killing the agent (email or name)
            expires_hours Auto-revive after this many hours (None = permanent)

        Returns dict with success status and message.
        """
        payload = {
            "agent_id": agent_id,
            "reason": reason or "Disabled via SDK",
            "killed_by": killed_by,
            "expires_hours": expires_hours
        }
        try:
            response = requests.post(
                f"{self.api_url}/killswitch/{self.org_id}/agent",
                json=payload,
                headers=self._headers(),
                timeout=10
            )
            if response.status_code in (401, 403):
                raise PolicyMeshAuthError(
                    "Killswitch operations require authenticated dashboard user context."
                )
            if response.status_code not in (200, 201):
                raise PolicyMeshConnectionError(
                    f"PolicyMesh API returned {response.status_code}: {response.text}"
                )
            return response.json()
        except (PolicyMeshAuthError, PolicyMeshConnectionError):
            raise
        except Exception as e:
            raise PolicyMeshConnectionError(f"Kill failed: {e}")

    def revive(self, agent_id: str) -> dict:
        """
        Administrative helper for re-enabling a disabled agent.

        Current backend killswitch routes require authenticated dashboard user
        context and organization access checks. API-key-only agent clients
        should not rely on this method until the admin SDK path is validated.
        """
        try:
            response = requests.delete(
                f"{self.api_url}/killswitch/{self.org_id}/agent/{agent_id}",
                headers=self._headers(),
                timeout=10
            )
            if response.status_code in (401, 403):
                raise PolicyMeshAuthError(
                    "Killswitch operations require authenticated dashboard user context."
                )
            if response.status_code not in (200, 201):
                raise PolicyMeshConnectionError(
                    f"PolicyMesh API returned {response.status_code}: {response.text}"
                )
            return response.json()
        except (PolicyMeshAuthError, PolicyMeshConnectionError):
            raise
        except Exception as e:
            raise PolicyMeshConnectionError(f"Revive failed: {e}")

    # ── GUARD DECORATOR ───────────────────────────────────────────────────────

    def guard(
        self,
        action_type: str,
        agent_id: str = "sdk_agent",
        data_classification: str = "internal",
        environment: str = "production",
        record_count: int = 0,
        destination: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[dict] = None,
        trace: Optional[List[TraceStep]] = None
    ):
        """
        Decorator that wraps a function with PolicyMesh evaluation.

        Example:
            @client.guard(action_type="data_export", agent_id="my_agent")
            def export_customer_data():
                ...
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                decision = self.evaluate(
                    agent_id=agent_id,
                    action_type=action_type,
                    data_classification=data_classification,
                    environment=environment,
                    record_count=record_count,
                    destination=destination,
                    description=description or f"Calling {func.__name__}",
                    metadata=metadata,
                    trace=trace
                )
                if decision.is_blocked:
                    raise PolicyBlockedError(
                        f"Function {func.__name__} blocked by PolicyMesh: {decision.policy_matched}",
                        action_id=decision.action_id,
                        policy_matched=decision.policy_matched
                    )
                if self.raise_on_escalate and decision.is_escalated:
                    raise PolicyEscalateError(
                        f"Function {func.__name__} requires approval: {decision.policy_matched}",
                        action_id=decision.action_id,
                        policy_matched=decision.policy_matched
                    )
                return func(*args, **kwargs)
            return wrapper
        return decorator

    # ── ALLOW ─────────────────────────────────────────────────────────────────

    def allow(self, agent_id: str, action_type: str, **kwargs) -> bool:
        """
        Simple boolean check. Returns True if allowed, False if blocked.
        Fails closed on SDK, API, auth, and policy exceptions.

        Prefer evaluate() or guard() for enforcement paths where the caller
        needs full decision and error details.
        """
        try:
            decision = self.evaluate(agent_id=agent_id, action_type=action_type, **kwargs)
            return decision.is_allowed or decision.is_flagged
        except (PolicyBlockedError, PolicyEscalateError):
            return False
        except Exception:
            return False
