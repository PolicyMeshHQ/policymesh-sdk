from _shared import example_client

from policymesh import PolicyBlockedError, PolicyEscalateError
from policymesh.adapters import PolicyMeshAdapter

APPROVED_GATEWAY_TOOLS = ["crm_lookup", "ticket_summarize"]


def invoke_mcp_tool(tool_name: str, arguments: dict):
    print(f"Invoke MCP tool only after PolicyMesh allows it: {tool_name}")
    return {"tool_name": tool_name, "status": "dry-run", "summary": "approved output"}


def guarded_gateway_call(adapter: PolicyMeshAdapter, tool_name: str, arguments: dict):
    try:
        _, decision = adapter.before_tool_call(
            tool_name,
            action_type="external_api_call",
            environment="staging",
            approved_tools=APPROVED_GATEWAY_TOOLS,
            metadata={"gateway": "mcp", "tool_name": tool_name},
        )
    except PolicyEscalateError as exc:
        print(f"MCP gateway call escalated before tool execution: {exc.policy_matched}")
        raise
    except PolicyBlockedError as exc:
        print(f"MCP gateway call blocked before tool execution: {exc.policy_matched}")
        raise

    if decision.would_have_blocked:
        print("Audit mode would-have-blocked evidence recorded before MCP tool execution.")

    result = invoke_mcp_tool(tool_name, arguments)
    adapter.before_output(
        result,
        action_type="external_api_call",
        destination="mcp_gateway",
    )
    return result


def main():
    adapter = PolicyMeshAdapter(example_client(), agent_id="mcp-tool-gateway-agent")
    guarded_gateway_call(
        adapter,
        "crm_lookup",
        {"customer_id": "redacted-demo-customer"},
    )
    print("mcp tool gateway example completed")


if __name__ == "__main__":
    main()
