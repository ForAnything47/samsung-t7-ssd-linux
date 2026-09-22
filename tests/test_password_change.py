import json
import subprocess
import tempfile
from pathlib import Path
import unittest
from test_single_native import FakeHost, INFO, START, UNLOCKED
import t7 as app


class ChangeHost(FakeHost):
    def __init__(self, stop=None, mode="interrupt"):
        super().__init__()
        self.stop = stop
        self.mode = mode

    def change_password_inputs(self):
        return b"OldTest9", b"NewTest9"

    def run(self, cmd, **kwargs):
        i = len(self.calls)
        self.calls.append((cmd, kwargs))
        if i == self.stop:
            if self.mode == "interrupt":
                raise KeyboardInterrupt
            if self.mode == "timeout":
                raise subprocess.TimeoutExpired(cmd, 45, output=b"NewTest9")
            return subprocess.CompletedProcess(cmd, 2, b"NewTest9", b"OldTest9")
        raw = b""
        if i in (0, 1, 18):
            raw = UNLOCKED
        elif i in (3, 15):
            raw = START.ljust(2048, b"\0")
        elif i in (5, 11):
            raw = app.frame(b"\xfb\0" if i == 5 else b"\xfc\0", 4100, 291, 1).ljust(
                2048, b"\0"
            )
        elif i in (7, 9):
            raw = app.frame(b"\xf0\xf1\xf9" + app.TAIL, 4100, 291, 1).ljust(2048, b"\0")
        elif i in (13, 17):
            raw = app.frame(b"\xfa", 4100, 291, 1).ljust(2048, b"\0")
        return subprocess.CompletedProcess(cmd, 0, raw, b"")


class Tests(unittest.TestCase):
    def test_success_no_secret_in_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            h = ChangeHost()
            r = app.execute_password_change(INFO, "TEST", None, state, h)
            self.assertTrue(r["complete"], r)
            self.assertTrue(r["new_password_verified"])
            self.assertFalse((state / "pending.json").exists())
            self.assertNotIn("NewTest9", json.dumps(r))
            self.assertNotIn("OldTest9", json.dumps(r))
            self.assertEqual(len(h.calls), 19)

    def test_interrupt_timeout_failure_at_every_transfer(self):
        for mode in ("interrupt", "timeout", "failed"):
            for index in range(19):
                with self.subTest(
                    mode=mode, index=index
                ), tempfile.TemporaryDirectory() as tmp:
                    state = Path(tmp)
                    h = ChangeHost(index, mode)
                    r = app.execute_password_change(INFO, "TEST", None, state, h)
                    self.assertFalse(r["complete"])
                    self.assertEqual(len(h.calls), index + 1)
                    self.assertEqual((state / "pending.json").exists(), index >= 2)
                    self.assertNotIn("NewTest9", json.dumps(r))
                    if index >= 2:
                        p = (state / "pending.json").read_text()
                        self.assertNotIn("NewTest9", p)
                        self.assertNotIn("OldTest9", p)

    def test_input_cancel_and_existing_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            h = ChangeHost()

            def cancel():
                raise KeyboardInterrupt

            h.change_password_inputs = cancel
            r = app.execute_password_change(INFO, "TEST", None, state, h)
            self.assertEqual(r["error"], "interrupted")
            self.assertFalse((state / "pending.json").exists())
            (state / "pending.json").write_text("{}")
            h = ChangeHost()
            r = app.execute_password_change(INFO, "TEST", None, state, h)
            self.assertEqual(h.calls, [])
            self.assertEqual((state / "pending.json").read_text(), "{}")

    def test_packet_targets_and_value(self):
        for target, suffix in ((19, "01"), (20, "02")):
            p = app.password_pin_set(target, b"NewTest9")
            self.assertTrue(
                p.startswith(b"\xf8\xa8" + bytes.fromhex("0000000b000100" + suffix))
            )
            self.assertEqual(p.count(b"NewTest9"), 1)
            self.assertTrue(p.endswith(b"\xf3\xf1\xf3\xf1\xf9" + app.TAIL))

    def test_recovery_verifies_both_without_set(self):
        class VerifyHost(ChangeHost):
            def gen(self, info):
                return "2"

            def password(self):
                return b"NewTest9"

            def run(self, cmd, **kwargs):
                i = len(self.calls)
                self.calls.append((cmd, kwargs))
                raw = b""
                if i in (0, 9):
                    raw = UNLOCKED
                elif i in (2, 6):
                    raw = START.ljust(2048, b"\0")
                elif i in (4, 8):
                    raw = app.frame(b"\xfa", 4100, 291, 1).ljust(2048, b"\0")
                return subprocess.CompletedProcess(cmd, 0, raw, b"")

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            app.save(
                state / "pending.json",
                {
                    "schema": 3,
                    "kind": "password_change",
                    "identity": INFO,
                    "diskseq": "1",
                    "boot_id": app.boot_identity(),
                    "changes_may_have_occurred": True,
                    "commit_confirmed": False,
                },
            )
            h = VerifyHost()
            r = app.execute_password_change(
                INFO, "TEST", None, state, h, verify_only=True
            )
            self.assertTrue(r["complete"], r)
            self.assertTrue(r["both_credentials_verified"])
            self.assertFalse((state / "pending.json").exists())
            self.assertTrue(
                all(
                    "set-" not in c["name"] and "commit" not in c["name"]
                    for c in r["commands"]
                )
            )
            self.assertIn(bytes.fromhex("0000000900010002"), h.calls[5][1]["input"])

    def test_recovery_requires_new_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            app.save(
                state / "pending.json",
                {
                    "schema": 3,
                    "kind": "password_change",
                    "identity": INFO,
                    "diskseq": "1",
                    "boot_id": app.boot_identity(),
                },
            )
            h = ChangeHost()
            r = app.execute_password_change(
                INFO, "TEST", None, state, h, verify_only=True
            )
            self.assertEqual(h.calls, [])
            self.assertTrue((state / "pending.json").exists())

    def test_final_report_failure_preserves_device_outcome(self):
        from unittest.mock import patch

        original_save = app.save

        def save(path, value):
            if path.name == "result.json" and value.get("complete"):
                raise OSError("simulated disk full")
            return original_save(path, value)

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            app, "save", side_effect=save
        ):
            state = Path(tmp)
            result = app.execute_password_change(
                INFO, "TEST", state / "report", state, ChangeHost()
            )
            self.assertTrue(result["complete"])
            self.assertTrue(result["commit_confirmed"])
            self.assertEqual(result["result_save_error"], "result_checkpoint_failed")
            self.assertFalse((state / "pending.json").exists())

    def test_explicit_authority_builder_matches_validated_admin1(self):
        credential = b"TestOnly9"
        self.assertEqual(
            app.password_authentication_payload(credential, 6),
            app.start_session(credential),
        )
        with self.assertRaises(app.Stop):
            app.password_authentication_payload(credential, 8)

    def test_verification_failure_preserves_original_incident(self):
        class InterruptedVerification(ChangeHost):
            def gen(self, info):
                return "2"

            def password(self):
                return b"NewTest9"

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            original = {
                "schema": 3,
                "kind": "password_change",
                "identity": INFO,
                "diskseq": "1",
                "boot_id": app.boot_identity(),
                "stage": "commit-in",
                "commit_confirmed": False,
                "changes_may_have_occurred": True,
            }
            app.save(state / "pending.json", original)
            host = InterruptedVerification(stop=1)
            result = app.execute_password_change(
                INFO, "TEST", None, state, host, verify_only=True
            )
            self.assertFalse(result["complete"])
            pending = json.loads((state / "pending.json").read_text())
            self.assertEqual(pending["verification_origin"], original)
