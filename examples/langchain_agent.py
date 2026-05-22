from _shared import example_client

from policymesh.adapters import PolicyMeshAdapter


def main():
    adapter = PolicyMeshAdapter(example_client(), agent_id="langchain-agent")

    adapter.before_model_call(
        "Plan the next retrieval step.",
        model="langchain:chat-model",
    )
    adapter.before_tool_call(
        "retriever",
        action_type="database_query",
        approved_tools=["retriever"],
    )
    adapter.before_output(
        {"answer": "grounded answer with sensitive fields redacted"},
        action_type="external_message",
        destination="customer_chat",
    )

    print("langchain example completed")


if __name__ == "__main__":
    main()
