import unittest
from types import SimpleNamespace

import requests

from policymesh import PolicyMeshClient
from policymesh.exceptions import (
    PolicyBlockedError,
    PolicyEscalateError,
    PolicyMeshAuthError,
    PolicyMeshConnectionError,
    PolicyMeshForbiddenError,
    PolicyMeshRateLimitError,
    PolicyMeshServerError,
    PolicyMeshTimeoutError,
    PolicyMeshUnexpectedResponseError,
    PolicyMeshValidationError,
)
from policymesh.models import Decision, PolicyDecision


def _decision(value):
    return PolicyDecision(
        action_id="action-1",
        agent_id="agent-1",
        org_id="org-1",
        action_type="data_access",
        decision=Decision(value),
        policy_matched=None,
        would_have_blocked=False,
        message="test",
    )


def _raises(error):
    def _raise(*args, **kwargs):
        raise error

    return _raise


class _Response:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = {}
        self.request = SimpleNamespace(headers={"X-Request-ID": "req-1"})

    def json(self):
        if self._payload == "not-json":
            raise ValueError("not json")
        return self._payload if self._payload is not None else {}


class _Session:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.error:
            raise self.error
        return self.response


class ClientBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.client = PolicyMeshClient(org_id="org-1", api_key="key-1")

    def test_allow_returns_true_for_allow_and_flag(self):
        self.client.evaluate = lambda *args, **kwargs: _decision("allow")
        self.assertTrue(self.client.allow("agent-1", "data_access"))

        self.client.evaluate = lambda *args, **kwargs: _decision("flag")
        self.assertTrue(self.client.allow("agent-1", "data_access"))

    def test_allow_fails_closed_for_policy_and_api_failures(self):
        failures = [
            PolicyBlockedError("blocked"),
            PolicyEscalateError("approval required"),
            PolicyMeshAuthError("bad key"),
            PolicyMeshConnectionError("timeout"),
            RuntimeError("unexpected"),
        ]

        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.client.evaluate = _raises(failure)
                self.assertFalse(self.client.allow("agent-1", "data_access"))

    def test_allow_can_be_explicitly_fail_open(self):
        client = PolicyMeshClient(org_id="org-1", api_key="key-1", fail_open=True)
        client.evaluate = _raises(PolicyMeshConnectionError("down"))
        self.assertTrue(client.allow("agent-1", "data_access"))

    def test_http_statuses_raise_typed_errors(self):
        cases = [
            (400, PolicyMeshValidationError),
            (401, PolicyMeshAuthError),
            (403, PolicyMeshForbiddenError),
            (422, PolicyMeshValidationError),
            (429, PolicyMeshRateLimitError),
            (500, PolicyMeshServerError),
        ]

        for status_code, expected in cases:
            with self.subTest(status_code=status_code):
                client = PolicyMeshClient(
                    org_id="org-1",
                    api_key="key-1",
                    session=_Session(_Response(status_code, {"detail": "no"})),
                )
                with self.assertRaises(expected):
                    client.scan("hello")

    def test_non_json_success_response_is_typed_error(self):
        client = PolicyMeshClient(
            org_id="org-1",
            api_key="key-1",
            session=_Session(_Response(200, "not-json", "html")),
        )
        with self.assertRaises(PolicyMeshUnexpectedResponseError):
            client.scan("hello")

    def test_connection_and_timeout_errors_are_typed(self):
        cases = [
            (requests.exceptions.ConnectionError("down"), PolicyMeshConnectionError),
            (requests.exceptions.Timeout("slow"), PolicyMeshTimeoutError),
        ]

        for error, expected in cases:
            with self.subTest(error=expected.__name__):
                client = PolicyMeshClient(
                    org_id="org-1",
                    api_key="key-1",
                    session=_Session(error=error),
                )
                with self.assertRaises(expected):
                    client.scan("hello")

    def test_headers_include_sdk_identity_and_request_id(self):
        client = PolicyMeshClient(
            org_id="org-1",
            api_key="key-1",
            session=_Session(_Response(200, {"risk_score": 0, "recommendation": "allow"})),
        )
        client.scan("hello")
        headers = client.session.calls[0][2]["headers"]

        self.assertEqual(headers["x-api-key"], "key-1")
        self.assertIn("policymesh-python/0.4.1", headers["User-Agent"])
        self.assertEqual(headers["X-PolicyMesh-SDK"], "python/0.4.1")
        self.assertTrue(headers["X-Request-ID"])

    def test_admin_methods_require_admin_token_before_network(self):
        session = _Session(_Response(200, {"success": True}))
        client = PolicyMeshClient(org_id="org-1", api_key="key-1", session=session)

        with self.assertRaises(PolicyMeshAuthError):
            client.kill("agent-1")
        with self.assertRaises(PolicyMeshAuthError):
            client.revive("agent-1")

        self.assertEqual(session.calls, [])

    def test_kill_requires_explicit_confirmation_before_network(self):
        session = _Session(_Response(200, {"success": True}))
        client = PolicyMeshClient(
            org_id="org-1",
            api_key="key-1",
            admin_token="admin-token",
            session=session,
        )

        with self.assertRaises(PolicyMeshValidationError):
            client.kill("agent-1")

        self.assertEqual(session.calls, [])

    def test_admin_methods_use_bearer_token_without_api_key(self):
        session = _Session(_Response(200, {"success": True}))
        client = PolicyMeshClient(
            org_id="org-1",
            api_key="key-1",
            admin_token="admin-token",
            session=session,
        )

        client.kill("agent-1", confirm="KILL-agent-1")
        headers = session.calls[0][2]["headers"]
        payload = session.calls[0][2]["json"]

        self.assertEqual(headers["Authorization"], "Bearer admin-token")
        self.assertNotIn("x-api-key", headers)
        self.assertEqual(payload["confirm"], "KILL-agent-1")

    def test_no_content_success_returns_empty_dict(self):
        client = PolicyMeshClient(
            org_id="org-1",
            api_key="key-1",
            admin_token="admin-token",
            session=_Session(_Response(204)),
        )

        self.assertEqual(client.revive("agent-1"), {})

    def test_evaluate_defaults_action_environment_to_development(self):
        session = _Session(
            _Response(
                200,
                {
                    "action_id": "action-1",
                    "agent_id": "agent-1",
                    "org_id": "org-1",
                    "action_type": "data_access",
                    "decision": "allow",
                },
            )
        )
        client = PolicyMeshClient(org_id="org-1", api_key="key-1", session=session)

        client.evaluate(agent_id="agent-1", action_type="data_access")
        payload = session.calls[0][2]["json"]

        self.assertEqual(payload["environment"], "development")


if __name__ == "__main__":
    unittest.main()
