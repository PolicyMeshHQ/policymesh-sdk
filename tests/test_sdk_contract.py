import os
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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
            project = tomllib.load(fh)["project"]

        self.assertEqual(policymesh.__version__, project["version"])
        self.assertEqual(project["requires-python"], ">=3.10")

    def test_package_includes_type_marker(self):
        self.assertTrue((ROOT / "policymesh" / "py.typed").exists())

    def test_required_docs_exist(self):
        self.assertTrue((ROOT / "docs" / "API_REFERENCE.md").exists())
        self.assertTrue((ROOT / "docs" / "RELEASE.md").exists())
        self.assertTrue((ROOT / "CHANGELOG.md").exists())
        self.assertTrue((ROOT / "MANIFEST.in").exists())

    def test_examples_are_runnable_without_live_credentials(self):
        examples_dir = str(ROOT / "examples")
        original_path = list(sys.path)
        sys.path.insert(0, examples_dir)
        try:
            with patch.dict(os.environ, {}, clear=True):
                for example in [
                    "custom_agent.py",
                    "openai_agent.py",
                    "anthropic_claude_agent.py",
                    "langchain_agent.py",
                    "crewai_agent.py",
                ]:
                    with self.subTest(example=example):
                        runpy.run_path(str(ROOT / "examples" / example), run_name="__main__")
        finally:
            sys.path = original_path

    def test_staging_smoke_refuses_production_without_confirmation(self):
        with patch.dict(
            os.environ,
            {
                "POLICYMESH_API_URL": "https://policymesh-production.up.railway.app/api/v1",
                "POLICYMESH_ORG_ID": "org-1",
                "POLICYMESH_API_KEY": "key-1",
            },
            clear=True,
        ):
            with self.assertRaises(SystemExit) as context:
                runpy.run_path(str(ROOT / "scripts" / "staging_smoke.py"), run_name="__main__")

        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
