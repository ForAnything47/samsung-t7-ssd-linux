"""Synthetic stateful SSD and fault injection; never accesses a real device."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import t7 as app
from test_single_native import FakeHost, INFO, START, UNLOCKED, LOCKED

DEFAULT = bytes(range(32))
PASSWORD = b"SetTestOnly9"
DISABLED = bytearray(UNLOCKED)
DISABLED[68] &= ~(4 | 16 | 32)
DISABLED = bytes(DISABLED)


class SetupHost(FakeHost):
    def __init__(self, action, fault=None, mode=None):
        super().__init__()
        self.action = action
        self.fault, self.mode = fault, mode
        self.snapshot = UNLOCKED if action == "remove-password" else DISABLED
        self.payload = None
        self.committed = False

    def password(self):
        return PASSWORD

    def new_security_password(self):
        return PASSWORD

    def run(self, cmd, **kwargs):
        index = len(self.calls)
        self.calls.append((cmd, kwargs))
        if index == self.fault:
            if self.mode == "interrupt":
                raise KeyboardInterrupt
            if self.mode == "timeout":
                raise subprocess.TimeoutExpired(
                    cmd, 45, output=DEFAULT, stderr=PASSWORD
                )
            if self.mode == "failed":
                return subprocess.CompletedProcess(cmd, 2, DEFAULT, PASSWORD)
            return subprocess.CompletedProcess(cmd, 0, b"bad", PASSWORD)
        raw = b""
        payload = kwargs["input"]
        if payload:
            self.payload = payload[56:]
        elif "--request=4096" in cmd:
            raw = self.snapshot
        else:
            payload = self.payload
            if bytes.fromhex("000000000000ff02") in payload:
                raw = START
            elif payload.startswith(b"\xf8\xa8" + bytes.fromhex("0000000b00008402")):
                raw = app.frame(
                    b"\xf0\xf0\xf2\x03"
                    + app.byte_atom(DEFAULT)
                    + b"\xf3\xf1\xf1\xf9"
                    + app.TAIL,
                    4100,
                    291,
                    1,
                )
            elif (
                payload.startswith(b"\xf8\xa8" + bytes.fromhex("0000100100000000"))
                and bytes.fromhex("0000000600000016") in payload
            ):
                data = bytearray(144)
                data[2] = 3 if self.snapshot == UNLOCKED else 2
                raw = app.frame(
                    b"\xf0" + app.byte_atom(bytes(data)) + b"\xf1\xf9" + app.TAIL,
                    4100,
                    291,
                    1,
                )
            elif payload[0] in (251, 252):
                raw = app.frame(payload[:2], 4100, 291, 1)
                if payload[0] == 252:
                    self.committed = True
                    self.snapshot = (
                        DISABLED if self.action == "remove-password" else UNLOCKED
                    )
            elif payload[0] == 250:
                raw = app.frame(b"\xfa", 4100, 291, 1)
            else:
                raw = app.frame(b"\xf0\xf1\xf9" + app.TAIL, 4100, 291, 1)
            raw = raw.ljust(2048, b"\0")
        return subprocess.CompletedProcess(cmd, 0, raw, b"")


class Tests(unittest.TestCase):
    def run_case(self, action, state, host, out=None):
        return app.execute_security_setup(action, INFO, "TEST", out, state, host)

    def test_success_both_actions_no_secret_saved(self):
        for action in ("set-password", "remove-password"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp)
                host = SetupHost(action)
                result = self.run_case(action, state, host, state / "report")
                self.assertTrue(result["complete"], result)
                self.assertTrue(result["commit_confirmed"])
                self.assertTrue(result["both_credentials_verified"])
                self.assertFalse(result["recovery_required"])
                self.assertTrue(result["after"]["locking_enabled"])
                self.assertFalse((state / "pending.json").exists())
                self.assertEqual(
                    len(host.calls), 56 if action == "set-password" else 58
                )
                for path in state.rglob("*"):
                    if path.is_file():
                        content = path.read_text()
                        self.assertNotIn(PASSWORD.decode(), content)
                        self.assertNotIn(DEFAULT.hex(), content)
                self.assertEqual(
                    list((state / "report").iterdir()), [state / "report/result.json"]
                )

    def test_fault_at_every_transfer_stops_no_replay(self):
        for action, count in (("set-password", 56), ("remove-password", 58)):
            for mode in ("interrupt", "timeout", "failed", "malformed"):
                for index in range(count):
                    # An outbound success has no payload response to parse.
                    if mode == "malformed":
                        baseline = SetupHost(action)
                        with tempfile.TemporaryDirectory() as tmp:
                            self.run_case(action, Path(tmp), baseline)
                        if baseline.calls[index][1]["input"]:
                            continue
                    with self.subTest(
                        action=action, mode=mode, index=index
                    ), tempfile.TemporaryDirectory() as tmp:
                        state = Path(tmp)
                        host = SetupHost(action, index, mode)
                        result = self.run_case(action, state, host)
                        self.assertFalse(result["complete"], result)
                        self.assertEqual(len(host.calls), index + 1)
                        self.assertEqual((state / "pending.json").exists(), index >= 2)
                        self.assertNotIn(PASSWORD.decode(), json.dumps(result))
                        if index >= 2:
                            before = (state / "pending.json").read_bytes()
                            second = SetupHost(action)
                            self.run_case(action, state, second)
                            self.assertEqual(second.calls, [])
                            self.assertEqual(
                                (state / "pending.json").read_bytes(), before
                            )

    def test_input_cancel_no_pending_next_invocation_works(self):
        for action in ("set-password", "remove-password"):
            with tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp)
                host = SetupHost(action)

                def cancel():
                    raise KeyboardInterrupt

                host.password = host.new_security_password = cancel
                result = self.run_case(action, state, host)
                self.assertEqual(result["error"], "interrupted")
                self.assertEqual(len(host.calls), 1)
                self.assertFalse((state / "pending.json").exists())
                self.assertTrue(
                    self.run_case(action, state, SetupHost(action))["complete"]
                )

    def test_wrong_current_clears_pending_without_get_or_set(self):
        class RejectHost(SetupHost):
            def run(self, cmd, **kwargs):
                reply = super().run(cmd, **kwargs)
                if len(self.calls) == 4:
                    raw = app.frame(
                        b"\xf8"
                        + app.byte_atom(bytes.fromhex("00000000000000ff"))
                        + app.byte_atom(bytes.fromhex("000000000000ff03"))
                        + b"\xf0\x01\x00\xf1\xf9\xf0\x01\x00\x00\xf1",
                        4100,
                    )
                    reply.stdout = raw.ljust(2048, b"\0")
                return reply

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            host = RejectHost("remove-password")
            result = self.run_case("remove-password", state, host)
            self.assertEqual(result.get("error"), "authentication_rejected", result)
            self.assertFalse(result["recovery_required"])
            self.assertFalse(result["changes_may_have_occurred"])
            self.assertEqual(len(host.calls), 4)

    def test_wrong_mode_no_password_or_mutation(self):
        for action in ("set-password", "remove-password"):
            for snapshot in (
                LOCKED,
                UNLOCKED if action == "set-password" else DISABLED,
            ):
                with tempfile.TemporaryDirectory() as tmp:
                    host = SetupHost(action)
                    host.snapshot = snapshot
                    host.password = host.new_security_password = lambda: self.fail(
                        "must not prompt"
                    )
                    result = self.run_case(action, Path(tmp), host)
                    self.assertEqual(
                        result["error"], "security_mode_precondition_failed"
                    )
                    self.assertEqual(len(host.calls), 1)

    def test_default_binary_length_and_user_policy_separate(self):
        for value in (b"", b"a" * 16, b"a" * 31, b"a" * 33):
            with self.assertRaises(app.Stop):
                app.security_auth_payload(value, default=True)
        self.assertIn(DEFAULT, app.security_auth_payload(DEFAULT, default=True))
        with self.assertRaises(ValueError):
            app.start_session(DEFAULT)
        for target in (19, 20):
            self.assertIn(DEFAULT, app.default_pin_set(target, DEFAULT))
        with self.assertRaises(app.Stop):
            app.default_pin_set(17, DEFAULT)

    def test_recovered_write_order_and_wire_constants(self):
        setup = app.security_mutations("set-password", PASSWORD)
        remove = app.security_mutations("remove-password", DEFAULT)
        self.assertEqual(
            [name for name, _ in setup],
            [
                "pin-19",
                "pin-20",
                "enable-read-lock",
                "enable-write-lock",
                "read-unlocked",
                "write-unlocked",
                "mbr-enabled",
                "mbr-done",
                "datastore-mode",
            ],
        )
        self.assertEqual(
            [name for name, _ in remove],
            [
                "mbr-disabled",
                "read-unlocked",
                "write-unlocked",
                "disable-read-lock",
                "disable-write-lock",
                "pin-19",
                "pin-20",
                "datastore-mode",
            ],
        )
        self.assertEqual(
            remove[0][1].hex(),
            "f8a80000080300000001a80000000600000017f0f201f0f20100f3f1f3f1f9f0000000f1",
        )
        self.assertEqual(
            setup[-1][1].hex(),
            "f8a80000100100000000a80000000600000017f0f20002f3f201a103f3f1f9f0000000f1",
        )
        self.assertEqual(
            remove[-1][1].hex(),
            "f8a80000100100000000a80000000600000017f0f20002f3f201a102f3f1f9f0000000f1",
        )

    def test_generation_and_busy_checks_before_every_transfer(self):
        for attribute in ("changed", "busy"):
            with tempfile.TemporaryDirectory() as tmp:
                host = SetupHost("remove-password")
                setattr(host, attribute, 10)
                result = self.run_case("remove-password", Path(tmp), host)
                self.assertFalse(result["complete"])
                self.assertEqual(len(host.calls), 10)
                self.assertTrue(result["recovery_required"])

    def test_final_report_error_preserves_outcome(self):
        original = app.save

        def save(path, value):
            if path.name == "result.json" and value.get("complete"):
                raise OSError("disk full")
            original(path, value)

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            app, "save", side_effect=save
        ):
            state = Path(tmp)
            result = self.run_case(
                "set-password", state, SetupHost("set-password"), state / "report"
            )
            self.assertTrue(result["complete"])
            self.assertEqual(result["result_save_error"], "result_checkpoint_failed")
            self.assertFalse(result["recovery_required"])

    def test_status_reports_disabled_without_weakening_unlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            result = app.execute_unlock(
                INFO, "TEST", "status", None, state, SetupHost("set-password")
            )
            self.assertTrue(result["complete"], result)
            self.assertTrue(result["before"]["locking_enabled"])
            self.assertEqual(len(result["commands"]), 1)
            host = SetupHost("set-password")
            result = app.execute_unlock(INFO, "TEST", "unlock", None, state, host)
            self.assertFalse(result["complete"])
            self.assertEqual(len(host.calls), 1)

    def test_cli_dry_run_is_host_only_and_dispatches_actions(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            app, "BASE", Path(tmp)
        ), patch.object(app, "list_devices", return_value=[INFO]), patch.object(
            app, "local_output"
        ), patch.object(
            app, "usage_snapshot", return_value={"idle": True}
        ), patch.object(
            app, "execute_security_setup"
        ) as execute:
            for action in ("set-password", "remove-password"):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    code = app.main([action, "--json"])
                result = json.loads(stream.getvalue())
                self.assertEqual(code, 0)
                self.assertEqual(result["action"], action)
                self.assertTrue(result["dry_run"])
                self.assertEqual(result["commands"], [])
            execute.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_post_commit_verification_failure_keeps_pending(self):
        class RejectVerification(SetupHost):
            def run(self, cmd, **kwargs):
                reply = super().run(cmd, **kwargs)
                if (
                    self.committed
                    and not kwargs["input"]
                    and "--request=2048" in cmd
                    and bytes.fromhex("000000000000ff02") in self.payload
                ):
                    raw = app.frame(
                        b"\xf8"
                        + app.byte_atom(bytes.fromhex("00000000000000ff"))
                        + app.byte_atom(bytes.fromhex("000000000000ff03"))
                        + b"\xf0\x01\x00\xf1\xf9\xf0\x01\x00\x00\xf1",
                        4100,
                    )
                    reply.stdout = raw.ljust(2048, b"\0")
                return reply

        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_case(
                "remove-password", Path(tmp), RejectVerification("remove-password")
            )
            self.assertEqual(result["error"], "credential_verification_rejected")
            self.assertTrue(result["commit_confirmed"])
            self.assertTrue(result["recovery_required"])
            pending = json.loads((Path(tmp) / "pending.json").read_text())
            self.assertTrue(pending["changes_may_have_occurred"])
            self.assertTrue(pending["commit_confirmed"])
