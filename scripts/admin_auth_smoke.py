import os
import sys
import uuid

import requests

from policymesh import (
    PolicyMeshAuthError,
    PolicyMeshClient,
    PolicyMeshForbiddenError,
    PolicyMeshValidationError,
)


def require_env(name):
    value = os.environ.get(name)
    if not value:
        print(f"missing required env var: {name}", file=sys.stderr)
        sys.exit(2)
    return value


def refuse_production(api_url):
    if "production" in api_url and os.environ.get("POLICYMESH_CONFIRM_PRODUCTION") != "1":
        print(
            "refusing to run admin smoke against production without "
            "POLICYMESH_CONFIRM_PRODUCTION=1"
        )
        sys.exit(2)


def expect_api_key_only_admin_rejected(api_url, org_id, api_key, agent_id):
    response = requests.post(
        f"{api_url}/killswitch/{org_id}/agent",
        headers={"x-api-key": api_key, "Content-Type": "application/json"},
        json={
            "agent_id": agent_id,
            "reason": "SDK admin smoke should reject API-key-only admin attempt",
            "confirm": f"KILL-{agent_id}",
        },
        timeout=10,
    )
    if response.status_code not in (401, 403):
        print(
            f"api-key-only admin negative check failed: status={response.status_code}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"api-key-only admin negative check passed: status={response.status_code}")


def expect_sdk_local_admin_guards(client, agent_id):
    try:
        PolicyMeshClient(org_id=client.org_id, api_key=client.api_key, api_url=client.api_url).kill(
            agent_id,
            confirm=f"KILL-{agent_id}",
        )
    except PolicyMeshAuthError:
        print("sdk local admin-token guard passed")
    else:
        print("sdk local admin-token guard failed", file=sys.stderr)
        sys.exit(1)

    confirmation_client = PolicyMeshClient(
        org_id=client.org_id,
        api_key=client.api_key,
        api_url=client.api_url,
        admin_token="local-confirmation-test-token",
    )
    try:
        confirmation_client.kill(agent_id)
    except PolicyMeshValidationError:
        print("sdk local kill confirmation guard passed")
    else:
        print("sdk local kill confirmation guard failed", file=sys.stderr)
        sys.exit(1)


def main():
    api_url = require_env("POLICYMESH_API_URL").rstrip("/")
    refuse_production(api_url)

    org_id = require_env("POLICYMESH_ORG_ID")
    api_key = require_env("POLICYMESH_API_KEY")
    admin_token = os.environ.get("POLICYMESH_ADMIN_TOKEN")
    agent_id = os.environ.get("POLICYMESH_ADMIN_SMOKE_AGENT_ID", f"sdk-admin-smoke-{uuid.uuid4()}")

    expect_api_key_only_admin_rejected(api_url, org_id, api_key, agent_id)

    client = PolicyMeshClient(
        org_id=org_id,
        api_key=api_key,
        api_url=api_url,
        admin_token=admin_token,
        raise_on_block=False,
    )
    expect_sdk_local_admin_guards(client, agent_id)

    if not admin_token:
        print(
            "missing POLICYMESH_ADMIN_TOKEN for positive admin bearer-auth smoke",
            file=sys.stderr,
        )
        sys.exit(2)

    killed = False
    try:
        kill_result = client.kill(
            agent_id,
            reason="SDK admin bearer-auth staging smoke",
            expires_hours=1,
            confirm=f"KILL-{agent_id}",
        )
        killed = bool(kill_result.get("success"))
        if not killed:
            print("admin bearer kill did not return success", file=sys.stderr)
            sys.exit(1)
        print("admin bearer kill passed")

        blocked = client.evaluate(
            agent_id=agent_id,
            action_type="model_call",
            data_classification="internal",
            environment="staging",
            description="SDK admin smoke evaluate while agent is killed",
        )
        if not blocked.is_blocked or blocked.policy_matched != "Agent Killswitch":
            print(
                "killed-agent evaluate check failed: "
                f"decision={blocked.decision} policy={blocked.policy_matched}",
                file=sys.stderr,
            )
            sys.exit(1)
        print("killed-agent evaluate block passed")

        revive_result = client.revive(agent_id)
        if not revive_result.get("success"):
            print("admin bearer revive did not return success", file=sys.stderr)
            sys.exit(1)
        killed = False
        print("admin bearer revive passed")

        revived = client.evaluate(
            agent_id=agent_id,
            action_type="model_call",
            data_classification="internal",
            environment="staging",
            description="SDK admin smoke evaluate after revive",
        )
        if revived.is_blocked and revived.policy_matched == "Agent Killswitch":
            print("revived-agent evaluate still blocked by killswitch", file=sys.stderr)
            sys.exit(1)
        print(f"revived-agent evaluate passed: decision={revived.decision}")
    except (PolicyMeshAuthError, PolicyMeshForbiddenError, PolicyMeshValidationError) as exc:
        print(f"admin bearer auth smoke failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if killed:
            try:
                client.revive(agent_id)
                print("cleanup revive completed")
            except Exception as exc:
                print(f"cleanup revive failed: {type(exc).__name__}: {exc}", file=sys.stderr)

    print("sdk admin auth smoke completed")


if __name__ == "__main__":
    main()
