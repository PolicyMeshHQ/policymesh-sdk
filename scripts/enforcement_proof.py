# ruff: noqa: E402,I001
import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from policymesh import PolicyMeshClient
from policymesh.exceptions import PolicyBlockedError, PolicyMeshConnectionError


DEFAULT_LATENCY_THRESHOLD_MS = 5000
DEFAULT_APPROVAL_TIMEOUT_SECONDS = 20


@dataclass
class ProofResult:
    name: str
    passed: bool
    latency_ms: int | None = None
    detail: str | None = None
    action_id: str | None = None
    policy_matched: str | None = None


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"missing required env var: {name}", file=sys.stderr)
        sys.exit(2)
    return value


def refuse_production_without_confirmation(api_url: str) -> None:
    if "production" in api_url and os.environ.get("POLICYMESH_CONFIRM_PRODUCTION") != "1":
        print(
            "refusing to run enforcement proof against production without "
            "POLICYMESH_CONFIRM_PRODUCTION=1",
            file=sys.stderr,
        )
        sys.exit(2)


def milliseconds(start: float) -> int:
    return round((time.perf_counter() - start) * 1000)


class SupabaseRest:
    def __init__(self, url: str, service_role_key: str):
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        self.headers = {
            "apikey": service_role_key,
            "Authorization": f"Bearer {service_role_key}",
            "Content-Type": "application/json",
        }

    def get_rows(self, table: str, params: dict[str, str]) -> list[dict[str, Any]]:
        response = self.session.get(
            f"{self.base_url}/rest/v1/{table}",
            headers=self.headers,
            params=params,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected Supabase response for {table}: {data!r}")
        return data

    def patch_rows(
        self,
        table: str,
        params: dict[str, str],
        payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        headers = dict(self.headers)
        headers["Prefer"] = "return=representation"
        response = self.session.patch(
            f"{self.base_url}/rest/v1/{table}",
            headers=headers,
            params=params,
            json=payload,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected Supabase response for {table}: {data!r}")
        return data


def set_enforcement_mode(db: SupabaseRest, org_id: str, enabled: bool) -> None:
    rows = db.patch_rows(
        "orgs",
        {"id": f"eq.{org_id}"},
        {"enforcement_mode": enabled},
    )
    if not rows:
        raise RuntimeError(f"Org not found while setting enforcement mode: {org_id}")


def get_org_mode(db: SupabaseRest, org_id: str) -> bool:
    rows = db.get_rows(
        "orgs",
        {
            "id": f"eq.{org_id}",
            "select": "id,enforcement_mode,name",
            "limit": "1",
        },
    )
    if not rows:
        raise RuntimeError(f"Org not found: {org_id}")
    return bool(rows[0].get("enforcement_mode"))


def wait_for_approval(
    db: SupabaseRest,
    org_id: str,
    agent_id: str,
    timeout_seconds: int,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        rows = db.get_rows(
            "approvals",
            {
                "org_id": f"eq.{org_id}",
                "agent_id": f"eq.{agent_id}",
                "status": "eq.pending",
                "select": "id,agent_id,action_type,status,policy_matched,created_at",
                "order": "created_at.desc",
                "limit": "1",
            },
        )
        if rows:
            return rows[0]
        time.sleep(1)
    return None


def proof_payload(agent_id: str) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "action_type": "production_deploy",
        "data_classification": "internal",
        "environment": "production",
        "record_count": 0,
        "destination": "production-deployment-controller",
        "description": "P0-45 proof: production deployment should be blocked in enforcement.",
        "metadata": {"proof": "p0-45-runtime-enforcement"},
    }


def run_audit_mode_proof(client: PolicyMeshClient, agent_id: str) -> ProofResult:
    downstream_executed: list[str] = []
    started = time.perf_counter()
    decision = client.evaluate(**proof_payload(agent_id))
    latency_ms = milliseconds(started)

    if decision.is_allowed:
        downstream_executed.append("ran")

    passed = (
        decision.is_allowed
        and decision.would_have_blocked is True
        and bool(downstream_executed)
    )
    return ProofResult(
        name="audit_mode_would_have_blocked_allows_downstream",
        passed=passed,
        latency_ms=latency_ms,
        detail=(
            f"decision={decision.decision.value}, "
            f"would_have_blocked={decision.would_have_blocked}, "
            f"downstream_executed={bool(downstream_executed)}"
        ),
        action_id=decision.action_id,
        policy_matched=decision.policy_matched,
    )


def run_enforcement_block_proof(client: PolicyMeshClient, agent_id: str) -> ProofResult:
    downstream_executed: list[str] = []

    @client.guard(**proof_payload(agent_id))
    def downstream_action() -> None:
        downstream_executed.append("ran")

    started = time.perf_counter()
    try:
        downstream_action()
    except PolicyBlockedError as exc:
        latency_ms = milliseconds(started)
        return ProofResult(
            name="enforcement_mode_blocks_before_downstream",
            passed=not downstream_executed,
            latency_ms=latency_ms,
            detail=f"blocked=True, downstream_executed={bool(downstream_executed)}",
            action_id=exc.action_id,
            policy_matched=exc.policy_matched,
        )

    latency_ms = milliseconds(started)
    return ProofResult(
        name="enforcement_mode_blocks_before_downstream",
        passed=False,
        latency_ms=latency_ms,
        detail=f"blocked=False, downstream_executed={bool(downstream_executed)}",
    )


def run_escalation_proof(
    client: PolicyMeshClient,
    db: SupabaseRest,
    org_id: str,
    agent_id: str,
    approval_timeout_seconds: int,
) -> ProofResult:
    started = time.perf_counter()
    decision = client.evaluate(
        agent_id=agent_id,
        action_type="database_write",
        data_classification="internal",
        environment="production",
        record_count=1,
        destination="production-database",
        description="P0-45 proof: production database write should require approval.",
        metadata={"proof": "p0-45-runtime-enforcement"},
    )
    latency_ms = milliseconds(started)
    approval = wait_for_approval(db, org_id, agent_id, approval_timeout_seconds)
    passed = decision.is_escalated and approval is not None
    return ProofResult(
        name="enforcement_mode_escalation_creates_approval",
        passed=passed,
        latency_ms=latency_ms,
        detail=(
            f"decision={decision.decision.value}, "
            f"approval_created={approval is not None}, "
            f"approval_status={approval.get('status') if approval else None}"
        ),
        action_id=decision.action_id,
        policy_matched=decision.policy_matched,
    )


def run_failure_mode_proof() -> list[ProofResult]:
    results: list[ProofResult] = []
    closed_client = PolicyMeshClient(
        org_id="proof-org",
        api_key="proof-key",
        api_url="http://127.0.0.1:9/api/v1",
        timeout=0.2,
        max_retries=0,
        fail_open=False,
        raise_on_block=False,
    )
    opened_client = PolicyMeshClient(
        org_id="proof-org",
        api_key="proof-key",
        api_url="http://127.0.0.1:9/api/v1",
        timeout=0.2,
        max_retries=0,
        fail_open=True,
        raise_on_block=False,
    )

    started = time.perf_counter()
    fail_closed_allowed = closed_client.allow("proof-agent", "production_deploy")
    results.append(
        ProofResult(
            name="failure_mode_defaults_fail_closed",
            passed=fail_closed_allowed is False,
            latency_ms=milliseconds(started),
            detail=f"allow_returned={fail_closed_allowed}",
        )
    )

    started = time.perf_counter()
    fail_open_allowed = opened_client.allow("proof-agent", "production_deploy")
    results.append(
        ProofResult(
            name="failure_mode_can_be_explicitly_fail_open",
            passed=fail_open_allowed is True,
            latency_ms=milliseconds(started),
            detail=f"allow_returned={fail_open_allowed}",
        )
    )
    return results


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="PolicyMesh P0-45 runtime enforcement proof")
    parser.add_argument("--output", help="Optional JSON evidence output path")
    parser.add_argument(
        "--latency-threshold-ms",
        type=int,
        default=DEFAULT_LATENCY_THRESHOLD_MS,
        help="Maximum acceptable single-call staging proof latency.",
    )
    parser.add_argument(
        "--approval-timeout-seconds",
        type=int,
        default=DEFAULT_APPROVAL_TIMEOUT_SECONDS,
        help="How long to wait for evaluate-created approval evidence.",
    )
    args = parser.parse_args()

    api_url = require_env("POLICYMESH_API_URL")
    refuse_production_without_confirmation(api_url)

    audit_org_id = require_env("POLICYMESH_AUDIT_ORG_ID")
    audit_api_key = require_env("POLICYMESH_AUDIT_API_KEY")
    enforcement_org_id = require_env("POLICYMESH_ENFORCEMENT_ORG_ID")
    enforcement_api_key = require_env("POLICYMESH_ENFORCEMENT_API_KEY")

    db = SupabaseRest(
        url=require_env("POLICYMESH_SUPABASE_URL"),
        service_role_key=require_env("POLICYMESH_SUPABASE_SERVICE_ROLE_KEY"),
    )

    set_enforcement_mode(db, audit_org_id, False)
    set_enforcement_mode(db, enforcement_org_id, True)

    audit_mode = get_org_mode(db, audit_org_id)
    enforcement_mode = get_org_mode(db, enforcement_org_id)
    if audit_mode is not False or enforcement_mode is not True:
        raise RuntimeError(
            "Proof org modes are not correct: "
            f"audit={audit_mode}, enforcement={enforcement_mode}"
        )

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    audit_client = PolicyMeshClient(
        org_id=audit_org_id,
        api_key=audit_api_key,
        api_url=api_url,
        raise_on_block=False,
        raise_on_escalate=False,
    )
    enforcement_client = PolicyMeshClient(
        org_id=enforcement_org_id,
        api_key=enforcement_api_key,
        api_url=api_url,
        raise_on_block=True,
        raise_on_escalate=False,
    )
    escalation_client = PolicyMeshClient(
        org_id=enforcement_org_id,
        api_key=enforcement_api_key,
        api_url=api_url,
        raise_on_block=False,
        raise_on_escalate=False,
    )

    results = [
        run_audit_mode_proof(audit_client, f"p0-45-audit-{run_id}"),
        run_enforcement_block_proof(enforcement_client, f"p0-45-block-{run_id}"),
        run_escalation_proof(
            escalation_client,
            db,
            enforcement_org_id,
            f"p0-45-escalate-{run_id}",
            args.approval_timeout_seconds,
        ),
        *run_failure_mode_proof(),
    ]

    latency_results = [r for r in results if r.latency_ms is not None]
    latency_passed = all(
        (r.latency_ms or 0) <= args.latency_threshold_ms for r in latency_results
    )
    results.append(
        ProofResult(
            name="staging_latency_within_threshold",
            passed=latency_passed,
            detail=(
                f"threshold_ms={args.latency_threshold_ms}, "
                f"max_observed_ms={max((r.latency_ms or 0) for r in latency_results)}"
            ),
        )
    )

    summary = {
        "run_id": run_id,
        "api_url": api_url,
        "audit_org_id": audit_org_id,
        "enforcement_org_id": enforcement_org_id,
        "latency_threshold_ms": args.latency_threshold_ms,
        "results": [asdict(r) for r in results],
        "passed": all(r.passed for r in results),
    }

    if args.output:
        write_summary(Path(args.output), summary)

    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except PolicyMeshConnectionError as exc:
        print(f"PolicyMesh connection failed: {exc}", file=sys.stderr)
        sys.exit(1)
