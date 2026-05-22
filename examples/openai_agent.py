from _shared import example_client

from policymesh.adapters import PolicyMeshAdapter


def main():
    adapter = PolicyMeshAdapter(example_client(), agent_id="openai-agent")
    prompt = "Draft a response using approved internal context only."

    adapter.before_model_call(prompt, model="openai:gpt-4.1")
    print("Call OpenAI here only after PolicyMesh allows the model action.")
    adapter.before_output(
        {"response": "customer-safe response"},
        action_type="external_message",
        destination="customer_portal",
    )

    print("openai example completed")


if __name__ == "__main__":
    main()
