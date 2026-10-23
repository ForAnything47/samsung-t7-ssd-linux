"""Initial password setup, removal and committed-removal verification."""

import subprocess

from t7manager import credentials as password_input, device as device_api, errors, protocol, records, transport


# Do not merge this with unlock merely because the transport looks similar.
# Security setup changes credentials and policy. Readonly sg_raw access does
# not make B5 non-mutating.
class SecuritySetupFlow:
    """One transaction; uncertain outcomes require review, never automatic Set replay."""

    def __init__(self, action, info, serial, out, state, host):
        self.action, self.info, self.serial = action, info, serial
        self.out, self.state, self.host = out, state, host
        self.generation = host.gen(info)
        self.result = dict(
            action=action,
            complete=False,
            experimental=True,
            identity=info,
            commands=[],
            session_may_be_open=False,
            transaction_may_be_open=False,
            changes_may_have_occurred=False,
            commit_confirmed=False,
            relink_attempted=False,
            credential_bytes_saved=False,
        )

    def checkpoint(self):
        records.operation_checkpoint(self.state, self.result, self.out)

    def transfer(self, name, cdb, payload=None, request=None):
        self.result["error_stage"] = name
        if (
            self.host.identify(self.info["device"]) != self.info
            or self.host.gen(self.info) != self.generation
        ):
            raise errors.Stop("device_identity_or_generation_changed")
        self.host.idle(self.info["device"])
        record = dict(name=name, phase="attempting")
        self.result["commands"].append(record)
        self.checkpoint()
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        command += (
            ["--send=" + str(len(payload))]
            if payload is not None
            else ["--request=" + str(request), "--outfile=-"]
        )
        command += [self.info["device"], *[f"{value:02x}" for value in cdb]]
        try:
            reply = self.host.run(
                command,
                input=payload or b"",
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            record["phase"] = "timeout"
            self.checkpoint()
            raise errors.Stop("transport_timeout_no_retry") from None
        record.update(phase="returned", returncode=reply.returncode)
        if request is not None:
            record["received"] = len(reply.stdout)
        self.checkpoint()
        if reply.returncode:
            raise errors.Stop("transport_failed_no_retry")
        if request is not None:
            if len(reply.stdout) != request:
                raise errors.Stop("unexpected_receive_length")
            return reply.stdout

    def exchange(self, name, payload, sessions):
        packet = protocol.frame(payload, 4100, *sessions)
        self.transfer(
            name + "-out", protocol.security_cdb(181, 1, 4100, len(packet)), payload=packet
        )
        return self.transfer(
            name + "-in", protocol.security_cdb(162, 1, 4100, 2048), request=2048
        )

    def discovery(self, name, enabled):
        snapshot = protocol.security_discovery(self.transfer(name, protocol.DISCOVERY_CDB, request=4096))
        self.result[name.replace("discovery-", "")] = snapshot
        protocol.require_security_mode(snapshot, enabled)
        return snapshot

    def auth(self, name, credential, authority=6, default=False):
        payload = protocol.security_auth_payload(credential, authority, default)
        self.result["session_may_be_open"] = True
        raw = self.exchange(name, payload, (0, 0))
        response = protocol.parse_response(raw, expected_comid=4100, expected_sessions=(0, 0))
        if response.status:
            if protocol.supported_auth_rejection(
                response, len(raw)
            ) and protocol.rejected_sync_checks_match(protocol.sync_session_checks(response)):
                self.result["session_may_be_open"] = False
                raise errors.Stop(
                    "credential_verification_rejected"
                    if self.result["changes_may_have_occurred"]
                    else "authentication_rejected"
                )
            raise errors.Stop("unsupported_auth_response")
        return protocol.validate_start(raw, 4100)

    def end(self, name, sessions):
        protocol.validate_change(
            "end_session", self.exchange(name, b"\xfa", sessions), 4100, sessions
        )
        self.result["session_may_be_open"] = False

    def read_default(self):
        self.result["session_may_be_open"] = True
        sessions = protocol.validate_start(
            self.exchange("anonymous-admin-start", protocol.admin_sp_anonymous_start(), (0, 0)),
            4100,
        )
        response = protocol.parse_response(
            self.exchange("default-get", protocol.default_credential_get(), sessions),
            expected_comid=4100,
            expected_sessions=sessions,
        )
        structure = protocol.default_credential_structure(response)
        if (
            response.kind != "method"
            or response.status != 0
            or not structure["nonempty_credential"]
        ):
            raise errors.Stop("unsupported_default_credential_structure")
        credential = protocol.device_credential(response.values[4])
        self.end("anonymous-admin-end", sessions)
        return credential

    def verify_mode(self, name, enabled):
        """Read Samsung DataStore mode; do not infer it from LockingEnabled."""
        self.result["session_may_be_open"] = True
        sessions = protocol.validate_start(
            self.exchange(name + "-start", protocol.start_session(), (0, 0)), 4100
        )
        data = protocol.validate_get(
            self.exchange(name + "-get", protocol.datastore_get(), sessions), 4100, sessions
        )
        mode = data[2]
        self.result[name] = {"datastore_byte2": mode}
        self.end(name + "-end", sessions)
        if mode != (3 if enabled else 2):
            raise errors.Stop("unexpected_datastore_security_mode")

    def run(self):
        credential = default = target = None
        try:
            if self.action not in ("set-password", "remove-password"):
                raise errors.Stop("unsupported_security_action")
            if not transport.operation_model_allowed(self.info["model"], self.host):
                raise errors.Stop("unsupported_security_profile")
            if self.out is not None:
                self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
            enabled_before = self.action == "remove-password"
            with self.host.claim(self.info["device"]):
                self.discovery("discovery-before", enabled_before)
                self.result["error_stage"] = "password input"
                credential = (
                    self.host.password()
                    if enabled_before
                    else (
                        self.host.new_security_password()
                        if hasattr(self.host, "new_security_password")
                        else password_input.new_security_password()
                    )
                )
                protocol.start_session(credential)
                self.discovery("discovery-before-auth", enabled_before)
                # Match the recovered upper layer's separate current-password validation.
                if enabled_before:
                    sessions = self.auth("verify-current", credential)
                    self.end("end-current-verification", sessions)
                default = self.read_default()
                self.discovery("discovery-before-change", enabled_before)
                self.verify_mode("mode-before", enabled_before)
                sessions = self.auth(
                    "auth-change",
                    credential if enabled_before else default,
                    default=not enabled_before,
                )
                target = default if enabled_before else credential
                self.result["transaction_may_be_open"] = True
                protocol.validate_change(
                    "transaction_start",
                    self.exchange("transaction-start", b"\xfb\x00", sessions),
                    4100,
                    sessions,
                )
                for name, payload in protocol.security_mutations(self.action, target):
                    self.result["changes_may_have_occurred"] = True
                    protocol.validate_change(
                        "set",
                        self.exchange("set-" + name, payload, sessions),
                        4100,
                        sessions,
                    )
                protocol.validate_change(
                    "transaction_end",
                    self.exchange("commit", b"\xfc\x00", sessions),
                    4100,
                    sessions,
                )
                self.result.update(commit_confirmed=True, transaction_may_be_open=False)
                self.checkpoint()
                self.end("end-change", sessions)
                for authority in (6, 7):
                    sessions = self.auth(
                        f"verify-target-{authority}",
                        target,
                        authority,
                        default=enabled_before,
                    )
                    self.end(f"end-target-{authority}", sessions)
                self.result["both_credentials_verified"] = True
                self.verify_mode("mode-after", not enabled_before)
                self.discovery("discovery-after", not enabled_before)
                self.result["password_security"] = (
                    "disabled" if enabled_before else "enabled"
                )
                self.result.update(
                    complete=True,
                    both_credentials_verified=True,
                    outcome="password_removed" if enabled_before else "password_set",
                )
                self.result.pop("error_stage", None)
        except KeyboardInterrupt:
            self.result["error"] = "interrupted"
        except errors.Stop as exc:
            self.result["error"] = str(exc)
        except (protocol.ProtocolError, ValueError):
            self.result["error"] = "unsupported_protocol_response"
        except Exception:
            self.result["error"] = "local_error"
        finally:
            credential = default = target = None
            self.result["recovery_required"] = not self.result["complete"] and bool(
                self.result["changes_may_have_occurred"]
                or self.result["session_may_be_open"]
                or self.result["transaction_may_be_open"]
            )
            if self.result["recovery_required"]:
                self.result["next_step"] = (
                    "review_security_setup_result_do_not_repeat_changes"
                )
            try:
                self.checkpoint()
            except (OSError, errors.Stop, KeyboardInterrupt):
                self.result["result_save_error"] = "result_checkpoint_failed"
        return self.result


def execute_security_setup(action, info, serial, out, state, host=None):
    return SecuritySetupFlow(action, info, serial, out, state, host or transport.Host()).run()
