import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

import policymesh
from policymesh.models import ActionType


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_ACTION_TYPES = {
    "data_export",
    "data_access",
    "data_delete",
    "data_modify",
    "external_email",
    "external_message",
    "webhook_call",
    "production_deploy",
    "code_execution",
    "file_read",
    "file_write",
    "file_delete",
    "permission_change",
    "auth_change",
    "api_key_create",
    "payment",
    "vendor_action",
    "external_api_call",
    "web_browse",
    "web_scrape",
    "database_query",
    "database_write",
    "database_delete",
    "model_call",
    "prompt_injection",
    "custom",
}


class SdkContractTests(unittest.TestCase):
    def test_action_types_match_backend_contract(self):
        self.assertEqual({action.value for action in ActionType}, EXPECTED_ACTION_TYPES)

    def test_package_versions_are_aligned(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            pyproject_version = tomllib.load(fh)["project"]["version"]

        self.assertEqual(policymesh.__version__, pyproject_version)


if __name__ == "__main__":
    unittest.main()
