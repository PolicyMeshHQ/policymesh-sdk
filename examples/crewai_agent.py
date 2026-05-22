from _shared import example_client

from policymesh.adapters import PolicyMeshAdapter


def main():
    adapter = PolicyMeshAdapter(example_client(), agent_id="crewai-agent")

    adapter.before_model_call(
        "Coordinate the next research task for the crew.",
        model="crewai:agent",
    )
    adapter.before_tool_call(
        "web_search",
        action_type="web_browse",
        approved_tools=["web_search"],
    )
    adapter.before_output(
        {"crew_result": "approved public-source summary"},
        action_type="external_message",
        destination="operator_console",
    )

    print("crewai example completed")


if __name__ == "__main__":
    main()
