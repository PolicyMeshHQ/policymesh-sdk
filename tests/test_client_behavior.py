import unittest
from unittest.mock import patch

from policymesh import PolicyMeshClient
from policymesh.exceptions import (
    PolicyBlockedError,
    PolicyEscalateError,
    PolicyMeshAuthError,
    PolicyMeshConnectionError,
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
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


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

    def test_killswitch_methods_do_not_silently_accept_api_key_auth_failures(self):
        response = _Response(401, {"detail": "Authentication required"}, "Authentication required")

        with patch("policymesh.client.requests.post", return_value=response):
            with self.assertRaises(PolicyMeshAuthError):
                self.client.kill("agent-1")

        with patch("policymesh.client.requests.delete", return_value=response):
            with self.assertRaises(PolicyMeshAuthError):
                self.client.revive("agent-1")


if __name__ == "__main__":
    unittest.main()
