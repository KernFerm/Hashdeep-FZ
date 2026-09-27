#!/usr/bin/env python3
import importlib.util
import pathlib
import sys
import tempfile
import threading
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "companion" / "hashdeep_fz_bridge.py"
SPEC = importlib.util.spec_from_file_location("bridge", MODULE_PATH)
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class CompanionTests(unittest.TestCase):
    def test_safe_token(self):
        self.assertEqual(bridge.safe_token("../../bad name;rm"), ".._.._bad_name_rm")
        self.assertLessEqual(len(bridge.safe_token("a" * 100)), 63)

    def test_measured_tree_ignores_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "a.bin").write_bytes(b"abc")
            self.assertEqual(bridge.measured_tree(root), (1, 3))

    def test_only_fixed_operations(self):
        fake = object.__new__(bridge.Bridge)
        fake.executable = "/usr/bin/hashdeep"
        hash_args, _ = fake.command_args("HASH")
        self.assertEqual(hash_args[0], "/usr/bin/hashdeep")
        self.assertNotIn("shell", " ".join(hash_args))
        with self.assertRaises(ValueError):
            fake.command_args("HASH;id")

    def test_failed_audit_preserves_previous_report(self):
        class FailedProcess:
            pid = 123

            def wait(self, timeout=None):
                return 2

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            input_dir = root / "input"
            output_dir = root / "output"
            manifest = root / "known.hashdeep"
            report = output_dir / "hashdeep-report.txt"
            input_dir.mkdir()
            output_dir.mkdir()
            manifest.write_text("known", encoding="utf-8")
            report.write_text("previous valid report", encoding="utf-8")

            instance = object.__new__(bridge.Bridge)
            instance.executable = "/usr/bin/hashdeep"
            instance.state = bridge.State()
            instance.lock = threading.Lock()
            instance.process = None
            instance.send_status = lambda: None
            instance.set_error = lambda message: self.fail(message)

            with mock.patch.multiple(
                bridge,
                ROOT=root,
                INPUT=input_dir,
                OUTPUT=output_dir,
                MANIFEST=manifest,
                REPORT=report,
            ), mock.patch.object(bridge.subprocess, "Popen", return_value=FailedProcess()):
                instance.run_operation("AUDIT")

            self.assertEqual(report.read_text(encoding="utf-8"), "previous valid report")
            self.assertFalse(report.with_suffix(".txt.partial").exists())
            self.assertEqual(instance.state.name, "FAILED")


if __name__ == "__main__":
    unittest.main()
