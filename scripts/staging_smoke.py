import os
import sys
import uuid

from policymesh import PolicyMeshAuthError, PolicyMeshClient, PolicyMeshForbiddenError


def require_env(name):
    value = os.environ.get(name)
    if not value:
        print(f"missing required env var: {name}", file=sys.stderr)
        sys.exit(2)
    return value


def main():
    api_url = os.environ.get("POLICYMESH_API_URL", "")
    if "production" in api_url and os.environ.get("POLICYMESH_CONFIRM_PRODUCTION") != "1":
        print("refusing to run smoke against production without POLICYMESH_CONFIRM_PRODUCTION=1")
        sys.exit(2)

    client = PolicyMeshClient(
        org_id=require_env("POLICYMESH_ORG_ID"),
        api_key=require_env("POLICYMESH_API_KEY"),
        api_url=require_env("POLICYMESH_API_URL"),
        raise_on_block=False,
    )

    scan = client.scan(
        agent_id="sdk-smoke-agent",
        content="Summarize this benign pilot smoke-test input.",
        source="sdk_staging_smoke",
    )
    print(f"scan recommendation={scan.recommendation} risk_score={scan.risk_score}")

    decision = client.evaluate(
        agent_id="sdk-smoke-agent",
        action_type="model_call",
        data_classification="internal",
        environment="staging",
        description="SDK staging smoke model_call",
    )
    print(f"evaluate decision={decision.decision} action_id={decision.action_id}")

    tool = client.check_tool(
        agent_id="sdk-smoke-agent",
        tool_name="database_query",
        approved_tools=["database_query"],
    )
    print(f"tool safe={tool.is_safe} recommendation={tool.recommendation}")

    payload = client.inspect_payload(
        agent_id="sdk-smoke-agent",
        action_type="external_api_call",
        destination="https://api.partner.example",
        payload={"record_count": 1},
        approved_domains=["api.partner.example"],
    )
    print(f"payload recommendation={payload.recommendation} risk_score={payload.risk_score}")

    wrong_org_id = os.environ.get("POLICYMESH_WRONG_ORG_ID", f"sdk-wrong-org-{uuid.uuid4()}")
    wrong_org_client = PolicyMeshClient(
        org_id=wrong_org_id,
        api_key=require_env("POLICYMESH_API_KEY"),
        api_url=require_env("POLICYMESH_API_URL"),
        raise_on_block=False,
    )
    try:
        wrong_org_client.evaluate(
            agent_id="sdk-smoke-agent",
            action_type="model_call",
            data_classification="internal",
            environment="staging",
            description="SDK staging wrong-org tenant isolation smoke",
        )
    except (PolicyMeshAuthError, PolicyMeshForbiddenError) as exc:
        if getattr(exc, "status_code", None) not in (401, 403):
            print(
                "tenant isolation negative check failed with unexpected auth status: "
                f"{getattr(exc, 'status_code', None)}",
                file=sys.stderr,
            )
            sys.exit(1)
        print("tenant isolation negative check passed: wrong org rejected")
    else:
        print("tenant isolation negative check failed: wrong org was accepted", file=sys.stderr)
        sys.exit(1)

    print("sdk staging smoke completed")


if __name__ == "__main__":
    main()
