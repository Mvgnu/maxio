"""Negative checks for the write gate; these must not pass by doing no work."""
import copy
import importlib.util
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
module_spec = importlib.util.spec_from_file_location("architecture", ROOT / "scripts/check_architecture.py")
gate = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(gate)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.specs = gate.load_specs()

    def test_storage_cannot_write_api_contract_or_another_spec(self):
        spec = self.specs["storage_engine"]
        for path in ("src/api/object.rs", "src/storage/mod.rs", "Cargo.lock", "specs/domains/web_console_ui.md"):
            with self.subTest(path=path):
                self.assertFalse(gate.allowed(path, spec))
        self.assertTrue(gate.allowed("src/storage/filesystem/object.rs", spec))
        self.assertTrue(gate.allowed("tests/storage_safety.rs", spec))
        self.assertTrue(gate.allowed("specs/domains/storage_engine.md", spec))

    def test_prefixes_do_not_grant_neighbor_directory(self):
        self.assertFalse(gate.matches("src/storage_invented/foo.rs", "src/storage/"))
        self.assertFalse(gate.allowed("ui/package.json", self.specs["web_console_ui"]))

    def test_optional_layers_have_disjoint_bubbles_and_frozen_contracts(self):
        paths = {
            "workspace_catalog": "src/workspace/remote.rs",
            "workspace_cache": "src/workspace/local.rs",
            "agent_execution": "src/execution/runner.rs",
            "fabric_authority": "src/fabric/authority/jobs.rs",
            "fabric_transport": "src/fabric/client.rs",
            "worker_execution": "src/fabric/cache.rs",
        }
        for owner, path in paths.items():
            self.assertEqual([name for name, spec in self.specs.items() if gate.allowed(path, spec)], [owner])
            for contract in ("src/files.rs", "src/workspace/contract.rs", "src/workspace/mod.rs", "src/execution/contract.rs", "src/fabric/contract.rs", "src/fabric/mod.rs"):
                self.assertFalse(gate.allowed(contract, self.specs[owner]))

    def test_server_cannot_acquire_optional_startup_dependencies(self):
        for path in ("src/main.rs", "src/server.rs", "src/server/", "src/config.rs", "src/storage/", "src/api/"):
            self.assertIn("workspace", gate.FORBIDDEN_DEPS[path])
            self.assertIn("execution", gate.FORBIDDEN_DEPS[path])
            self.assertIn("fabric", gate.FORBIDDEN_DEPS[path])

    def test_bar_needs_reference_and_property(self):
        import json
        for key in ("reference", "property"):
            data = copy.deepcopy(self.specs["storage_engine"])
            del data["bar"][key]
            with self.assertRaisesRegex(ValueError, "bar"):
                gate.parse_spec("---\n" + json.dumps(data) + "\n---\n")

    def test_path_escape_rejected(self):
        import json
        for path in ("../neighbor/", "/tmp/", "src/../../"):
            data = copy.deepcopy(self.specs["storage_engine"])
            data["paths"]["owned"].append(path)
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                gate.parse_spec("---\n" + json.dumps(data) + "\n---\n")

    def test_generated_artifacts_never_owned(self):
        spec = self.specs["web_console_ui"]
        self.assertFalse(gate.allowed("ui/dist/index.html", spec))
        self.assertFalse(gate.allowed("ui/node_modules/fake/index.ts", spec))

    def test_all_sources_have_exactly_one_owner(self):
        self.assertEqual(gate.check_repository(self.specs), [])

    def test_vanished_cargo_test_filter_is_not_a_pass(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from run_checks import has_selected_tests
        self.assertFalse(has_selected_tests("0 tests, 0 benchmarks\n"))
        self.assertTrue(has_selected_tests("storage::write_preserves_data: test\n1 test\n"))


if __name__ == "__main__":
    unittest.main()
