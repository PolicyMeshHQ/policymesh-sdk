from _shared import example_client

from policymesh.adapters import PolicyMeshAdapter


def main():
    adapter = PolicyMeshAdapter(example_client(), agent_id="custom-agent")
    prompt = "Summarize internal customer ticket context."

    adapter.before_model_call(prompt, model="custom-agent-runtime")
    adapter.before_tool_call(
        "database_query",
        action_type="database_query",
        approved_tools=["database_query"],
    )
    adapter.before_output(
        {"summary": "redacted customer-safe summary"},
        action_type="external_api_call",
        destination="https://api.partner.example",
        approved_domains=["api.partner.example"],
    )

    print("custom agent example completed")


if __name__ == "__main__":
    main()
