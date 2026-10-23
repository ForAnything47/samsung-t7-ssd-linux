"""Password-change transaction and candidate-password verification."""

import subprocess

from t7manager import credentials as password_input, device as device_api, errors, protocol, records, transport


# Collect inputs before authentication; log every potentially open session.
# After a possible Set, verification failure leaves the result uncertain.
def execute_password_change(info, serial, out, state, host=None):
    host = host or transport.Host()
    result = {
        "action": "change-password",
        "complete": False,
        "experimental": True,
        "identity": info,
        "commands": [],
        "session_may_be_open": False,
        "transaction_may_be_open": False,
        "changes_may_have_occurred": False,
        "commit_confirmed": False,
        "relink_attempted": False,
    }
    current_password = new_password = None
    initial_generation = host.gen(info)

    def checkpoint():
        records.operation_checkpoint(state, result, out)

    def transfer(name, cdb, payload=None, request=None):
        result["error_stage"] = name
        if (
            host.identify(info["device"]) != info
            or host.gen(info) != initial_generation
        ):
            raise errors.Stop("device_identity_or_generation_changed")
        host.idle(info["device"])
        command_record = {"name": name, "phase": "attempting"}
        result["commands"].append(command_record)
        checkpoint()
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        if payload is not None:
            command += ["--send=" + str(len(payload))]
        else:
            command += ["--request=" + str(request), "--outfile=-"]
        command += [info["device"], *[f"{b:02x}" for b in cdb]]
        try:
            transport_result = host.run(
                command,
                input=payload or b"",
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            command_record["phase"] = "timeout"
            checkpoint()
            raise errors.Stop("transport_timeout_no_retry") from None
        command_record.update(phase="returned", returncode=transport_result.returncode)
        if request:
            command_record["received"] = len(transport_result.stdout)
        checkpoint()
        if transport_result.returncode:
            raise errors.Stop("transport_failed_no_retry")
        if request:
            if len(transport_result.stdout) != request:
                raise errors.Stop("unexpected_receive_length")
            return transport_result.stdout

    def exchange(name, payload, sessions):
        raw = protocol.frame(payload, 4100, *sessions)
        transfer(name + "-out", protocol.security_cdb(181, 1, 4100, len(raw)), payload=raw)
        return transfer(name + "-in", protocol.security_cdb(162, 1, 4100, 2048), request=2048)

    def auth(name, password, authority=6):
        result["session_may_be_open"] = True
        payload = protocol.password_authentication_payload(password, authority)
        raw = exchange(name, payload, (0, 0))
        parsed = protocol.parse_response(raw, expected_comid=4100, expected_sessions=(0, 0))
        if parsed.status:
            if protocol.supported_auth_rejection(
                parsed, len(raw)
            ) and protocol.rejected_sync_checks_match(protocol.sync_session_checks(parsed)):
                result["session_may_be_open"] = False
                raise errors.Stop(
                    "authentication_rejected"
                    if not result["commit_confirmed"]
                    else "new_password_verification_rejected"
                )
            raise errors.Stop("unsupported_auth_response")
        return protocol.validate_start(raw, 4100)

    def end(sessions, name):
        raw = exchange(name, b"\xfa", sessions)
        parsed = protocol.parse_response(raw, expected_comid=4100, expected_sessions=sessions)
        if parsed.kind != "end_session":
            raise errors.Stop("end_session_not_verified")
        result["session_may_be_open"] = False

    try:
        if out is not None:
            out.mkdir(parents=True, exist_ok=False, mode=0o700)
        with host.claim(info["device"]):
            result["before"] = protocol.parse_state(
                transfer("discovery-before", protocol.DISCOVERY_CDB, request=4096), "unlocked"
            )
            result["error_stage"] = "password input"
            current_password, new_password = (
                host.change_password_inputs()
                if hasattr(host, "change_password_inputs")
                else password_input.change_password_inputs()
            )
            protocol.password_pin_set(19, new_password)
            protocol.start_session(current_password)
            if current_password == new_password:
                raise errors.Stop("new_password_same_no_changes")
            result["before_auth"] = protocol.parse_state(
                transfer("discovery-before-auth", protocol.DISCOVERY_CDB, request=4096),
                "unlocked",
            )
            sessions = auth("auth-current", current_password)
            current_password = None
            result["transaction_may_be_open"] = True
            protocol.validate_change(
                "transaction_start",
                exchange("transaction-start", b"\xfb\x00", sessions),
                4100,
                sessions,
            )
            for target in (19, 20):
                result["changes_may_have_occurred"] = True
                raw = exchange(
                    "set-pin-" + str(target),
                    protocol.password_pin_set(target, new_password),
                    sessions,
                )
                protocol.validate_change("pin_set", raw, 4100, sessions)
            protocol.validate_change(
                "transaction_end",
                exchange("commit", b"\xfc\x00", sessions),
                4100,
                sessions,
            )
            result["commit_confirmed"] = True
            result["transaction_may_be_open"] = False
            checkpoint()
            end(sessions, "end-current")
            sessions = auth("verify-new", new_password)
            new_password = None
            end(sessions, "end-verification")
            result["after"] = protocol.parse_state(
                transfer("discovery-after", protocol.DISCOVERY_CDB, request=4096), "unlocked"
            )
            result.update(
                complete=True, outcome="password_changed", new_password_verified=True
            )
            result.pop("error_stage", None)
    except KeyboardInterrupt:
        result["error"] = "interrupted"
    except (errors.Stop, protocol.ProtocolError, ValueError) as exc:
        result["error"] = (
            str(exc) if isinstance(exc, errors.Stop) else "unsupported_protocol_response"
        )
    except Exception:
        result["error"] = "local_error"
    finally:
        current_password = new_password = None
        if not result["complete"]:
            result["recovery_required"] = bool(result["changes_may_have_occurred"] or result["session_may_be_open"] or result["transaction_may_be_open"])
            if result["changes_may_have_occurred"]:
                result["next_step"] = "verify_change_result_do_not_repeat_set"
            elif result["recovery_required"]:
                result["next_step"] = "session_state_requires_review"
        try:
            checkpoint()
        except (OSError, errors.Stop, KeyboardInterrupt):
            result["result_save_error"] = "result_checkpoint_failed"
    return result
