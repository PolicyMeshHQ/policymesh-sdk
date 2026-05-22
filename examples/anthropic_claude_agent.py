from _shared import example_client

from policymesh.adapters import PolicyMeshAdapter


def main():
    adapter = PolicyMeshAdapter(example_client(), agent_id="claude-agent")
    prompt = "Analyze policy evidence and return only approved summary fields."

    adapter.before_model_call(prompt, model="anthropic:claude")
    print("Call Claude here only after PolicyMesh allows the model action.")
    adapter.before_output(
        {"analysis": "approved summary"},
        action_type="external_api_call",
        destination="https://api.partner.example",
        approved_domains=["api.partner.example"],
    )

    print("anthropic claude example completed")


if __name__ == "__main__":
    main()
