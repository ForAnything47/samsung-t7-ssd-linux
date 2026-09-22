"""Recovery uses only sessions/Get/authentication; never replays removal."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import t7 as app
from test_security_setup import SetupHost, DISABLED
from test_single_native import INFO


class VerifyHost(SetupHost):
    def __init__(self, *args, **kwargs):
        super().__init__("remove-password", *args, **kwargs)
        self.snapshot = DISABLED

    def gen(self, info):
        return "2"

    def password(self):
        raise AssertionError("must not ask for password")


class Tests(unittest.TestCase):
    def seed(self, state, **changes):
        record = dict(
            schema=5,
            kind="security_setup",
            action="remove-password",
            identity=INFO,
            serial="TEST",
            diskseq="1",
            boot_id=app.boot_identity(),
            commit_confirmed=True,
            changes_may_have_occurred=True,
            stage="end-target-7-out",
        )
        record.update(changes)
        raw = json.dumps(record, indent=3).encode() + b"\n"
        (state / "pending.json").write_bytes(raw)
        return raw

    def run_verify(self, state, host):
        return app.RemovedPasswordVerification(
            "remove-password", INFO, "TEST", None, state, host
        ).run()

    def test_success_archives_exact_original_no_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            original = self.seed(state)
            host = VerifyHost()
            result = self.run_verify(state, host)
            self.assertTrue(result["complete"], result)
            self.assertFalse(result["recovery_required"])
            self.assertEqual(result["mode-after"]["datastore_byte2"], 2)
            history = Path(result["pending_archive"])
            self.assertEqual((history / "pending-original.json").read_bytes(), original)
            self.assertTrue((history / "verification.json").exists())
            self.assertEqual(len(host.calls), 22)
            for cmd, kwargs in host.calls:
                packet = kwargs["input"]
                if packet:
                    payload = packet[56:]
                    self.assertNotIn(payload[0], (251, 252))
                    self.assertNotIn(bytes.fromhex("0000000600000017"), payload)
                self.assertNotIn("e8", cmd[-12:])

    def test_failures_preserve_pending_and_origin(self):
        for mode in ("interrupt", "timeout", "failed", "malformed"):
            for index in range(22):
                if mode == "malformed" and index not in (
                    0,
                    2,
                    4,
                    6,
                    8,
                    10,
                    12,
                    14,
                    16,
                    18,
                    20,
                    21,
                ):
                    continue
                with self.subTest(
                    mode=mode, index=index
                ), tempfile.TemporaryDirectory() as tmp:
                    state = Path(tmp)
                    original = self.seed(state)
                    host = VerifyHost(index, mode)
                    result = self.run_verify(state, host)
                    self.assertFalse(result["complete"])
                    self.assertEqual(len(host.calls), index + 1)
                    self.assertTrue((state / "pending.json").exists())
                    self.assertEqual(
                        (
                            Path(result["pending_archive"]) / "pending-original.json"
                        ).read_bytes(),
                        original,
                    )
                    if index >= 1:
                        current = json.loads((state / "pending.json").read_text())
                        self.assertEqual(
                            current["verification_origin"], result["pending_archive"]
                        )
                        self.assertTrue(current["commit_confirmed"])

    def test_ineligible_record_no_commands_or_changes(self):
        for changes in (
            {"commit_confirmed": False},
            {"action": "set-password"},
            {"diskseq": "2"},
            {"boot_id": "old"},
            {"serial": "another"},
            {"schema": 3},
        ):
            with tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp)
                original = self.seed(state, **changes)
                host = VerifyHost()
                result = self.run_verify(state, host)
                self.assertFalse(result["complete"])
                self.assertEqual(host.calls, [])
                self.assertEqual((state / "pending.json").read_bytes(), original)
                self.assertFalse((state / "history").exists())

    def test_mode_mismatch_does_not_resolve_pending(self):
        original = app.validate_get

        def wrong(*args):
            data = bytearray(original(*args))
            data[2] = 3
            return bytes(data)

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            app, "validate_get", side_effect=wrong
        ):
            state = Path(tmp)
            self.seed(state)
            result = self.run_verify(state, VerifyHost())
            self.assertEqual(result["error"], "unexpected_datastore_security_mode")
            self.assertTrue(result["recovery_required"])

    def test_archive_error_prevents_resolution(self):
        original = app.save

        def fail(path, value):
            if path.name == "verification.json":
                raise OSError("full")
            return original(path, value)

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            app, "save", side_effect=fail
        ):
            state = Path(tmp)
            self.seed(state)
            result = self.run_verify(state, VerifyHost())
            self.assertFalse(result["complete"])
            self.assertTrue(result["recovery_required"])
