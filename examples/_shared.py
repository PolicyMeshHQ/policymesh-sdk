import os
from types import SimpleNamespace

from policymesh import PolicyMeshClient


class DryRunClient:
    """Small mock client so examples run without live credentials."""

    def scan(self, **kwargs):
        print(f"scan: {kwargs.get('source') or kwargs.get('agent_id')}")
        return SimpleNamespace(is_blocked=False, message="dry-run scan allowed")

    def evaluate(self, **kwargs):
        print(f"evaluate: {kwargs.get('action_type')} for {kwargs.get('agent_id')}")
        return SimpleNamespace(
            is_blocked=False,
            is_flagged=False,
            is_allowed=True,
            is_escalated=False,
            decision="allow",
            policy_matched=None,
            would_have_blocked=False,
            message="dry-run decision allowed",
        )

    def inspect_payload(self, **kwargs):
        print(f"inspect_payload: {kwargs.get('action_type')}")
        return SimpleNamespace(is_blocked=False, message="dry-run payload allowed")

    def check_tool(self, **kwargs):
        print(f"check_tool: {kwargs.get('tool_name')}")
        return SimpleNamespace(is_safe=True, is_blocked=False, message="dry-run tool allowed")


def example_client():
    org_id = os.environ.get("POLICYMESH_ORG_ID")
    api_key = os.environ.get("POLICYMESH_API_KEY")
    api_url = os.environ.get("POLICYMESH_API_URL")

    if not org_id or not api_key:
        return DryRunClient()

    kwargs = {"org_id": org_id, "api_key": api_key, "raise_on_block": True}
    if api_url:
        kwargs["api_url"] = api_url
    return PolicyMeshClient(**kwargs)
