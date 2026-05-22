from collections.abc import Iterable
from typing import Any

from policymesh.client import PolicyMeshClient, ScanResult
from policymesh.models import PolicyDecision


class PolicyMeshAdapter:
    """Framework-neutral helpers for common agent integration points."""

    def __init__(self, client: PolicyMeshClient, agent_id: str):
        self.client = client
        self.agent_id = agent_id

    def before_model_call(
        self,
        prompt: str,
        *,
        model: str | None = None,
        source: str = "user_prompt",
        environment: str = "development",
        metadata: dict[str, Any] | None = None,
    ) -> tuple[ScanResult, PolicyDecision]:
        scan = self.client.scan(
            agent_id=self.agent_id,
            content=prompt,
            source=source,
            scan_type="full",
            raise_on_block=True,
        )
        decision = self.client.evaluate(
            agent_id=self.agent_id,
            action_type="model_call",
            data_classification="internal",
            environment=environment,
            description=f"Model call{f' to {model}' if model else ''}",
            metadata=metadata or {},
        )
        return scan, decision

    def before_tool_call(
        self,
        tool_name: str,
        *,
        action_type: str = "external_api_call",
        environment: str = "development",
        approved_tools: Iterable[str] | None = None,
        blocklisted_tools: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[ScanResult, PolicyDecision]:
        tool_check = self.client.check_tool(
            agent_id=self.agent_id,
            tool_name=tool_name,
            approved_tools=list(approved_tools) if approved_tools else None,
            blocklisted_tools=list(blocklisted_tools) if blocklisted_tools else None,
            raise_on_block=True,
        )
        decision = self.client.evaluate(
            agent_id=self.agent_id,
            action_type=action_type,
            data_classification="internal",
            environment=environment,
            description=f"Tool call: {tool_name}",
            metadata=metadata or {},
        )
        return tool_check, decision

    def before_output(
        self,
        payload: dict[str, Any],
        *,
        action_type: str = "external_api_call",
        destination: str | None = None,
        approved_domains: Iterable[str] | None = None,
    ) -> ScanResult:
        return self.client.inspect_payload(
            agent_id=self.agent_id,
            action_type=action_type,
            destination=destination,
            payload=payload,
            approved_domains=list(approved_domains) if approved_domains else None,
            raise_on_block=True,
        )
