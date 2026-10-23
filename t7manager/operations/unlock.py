"""Unlock/status state machine, including guarded unmount and one Relink."""

import subprocess

from t7manager import errors, protocol, records, safety, transport


# Keep transport ordering explicit: Discovery, anonymous status, authentication,
# transactional unlock, EndSession, Discovery, one Relink, then rediscovery.
# The host adapter makes every stage testable without a real SSD.
def execute_unlock(info, serial, action, out, state, host=None):
    host = host or transport.Host()
    if out is not None:
        out.mkdir(parents=True, exist_ok=False, mode=448)
    report = {
        "complete": False,
        "action": action,
        "identity": info,
        "commands": [],
        "session_may_be_open": False,
        "transaction_may_be_open": False,
        "changes_may_have_occurred": False,
        "relink_attempted": False,
    }
    current_identity = info
    initial_generation = host.gen(current_identity)

    def checkpoint():
        records.operation_checkpoint(state, report, out)

    def transfer(name, cdb, payload=None, request=None, mounted_candidate=None):
        report["error_stage"] = name
        if host.identify(current_identity["device"]) != current_identity or host.gen(current_identity) != initial_generation:
            raise errors.Stop("device_identity_or_generation_changed")
        if mounted_candidate is not None:
            if (
                name != "discovery-before-unmount"
                or cdb != protocol.DISCOVERY_CDB
                or payload is not None
                or (request != 4096)
            ):
                raise errors.Stop("invalid_mounted_query")
            if (
                safety.auto_unmount_candidate(host.usage(current_identity["device"]))
                != mounted_candidate
            ):
                raise errors.Stop("mounted_partition_changed")
        else:
            host.idle(current_identity["device"])
        command_record = {"name": name, "phase": "attempting"}
        report["commands"].append(command_record)
        if name in ("anonymous-start-out", "auth-out"):
            report["session_may_be_open"] = True
        if name == "transaction_start-out":
            report["transaction_may_be_open"] = True
        if name in (
            "mbr_done-out",
            "read_unlock-out",
            "write_unlock-out",
            "datastore_mode-out",
        ):
            report["changes_may_have_occurred"] = True
        if name == "relink":
            report["relink_attempted"] = True
        checkpoint()
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        if payload is not None:
            command += ["--send=" + str(len(payload))]
        elif request:
            command += ["--request=" + str(request), "--outfile=-"]
        command += [current_identity["device"], *[f"{b:02x}" for b in cdb]]
        try:
            transport_result = host.run(
                command,
                input=payload if payload is not None else b"",
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
            if len(transport_result.stdout) > request:
                raise errors.Stop("oversized_response")
            return transport_result.stdout

    def exchange(name, payload, sessions):
        packet = protocol.frame(payload, 4100, *sessions)
        transfer(name + "-out", protocol.security_cdb(181, 1, 4100, len(packet)), payload=packet)
        return transfer(name + "-in", protocol.security_cdb(162, 1, 4100, 2048), request=2048)

    def discovery(name, expected=None):
        raw = transfer(name, protocol.DISCOVERY_CDB, request=4096)
        if action == "status":
            return protocol.security_discovery(raw)
        if expected:
            return protocol.parse_state(raw, expected)
        try:
            return protocol.parse_state(raw, "locked")
        except errors.Stop:
            return protocol.parse_state(raw, "unlocked")

    try:
        checkpoint()
        usage = host.usage(current_identity["device"])
        if action == "unlock" and usage.get("mounts"):
            candidate = safety.auto_unmount_candidate(usage)
            if candidate is None:
                raise errors.Stop("mounted_partition_not_verified_locking_volume")
            raw = transfer(
                "discovery-before-unmount",
                protocol.DISCOVERY_CDB,
                request=4096,
                mounted_candidate=candidate,
            )
            report["before_unmount"] = protocol.parse_state(raw, "locked")
            if host.identify(current_identity["device"]) != current_identity or host.gen(current_identity) != initial_generation:
                raise errors.Stop("device_identity_or_generation_changed")
            if safety.auto_unmount_candidate(host.usage(current_identity["device"])) != candidate:
                raise errors.Stop("mounted_partition_changed")
            record = {"device": candidate, "phase": "attempting"}
            report["unmount"] = record
            checkpoint()
            try:
                unmounted = host.run(
                    [
                        "udisksctl",
                        "unmount",
                        "--block-device",
                        candidate,
                        "--no-user-interaction",
                    ],
                    input=b"",
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                record["phase"] = "timeout"
                raise errors.Stop("unmount_timeout_no_unlock") from None
            record.update(phase="returned", returncode=unmounted.returncode)
            checkpoint()
            if unmounted.returncode:
                raise errors.Stop("unmount_failed_close_files_no_unlock")
            if host.identify(current_identity["device"]) != current_identity or host.gen(current_identity) != initial_generation:
                raise errors.Stop("device_identity_or_generation_changed")
            host.idle(current_identity["device"])
        with host.claim(current_identity["device"]):
            report["before"] = discovery("discovery-before")
            if action == "status" or not report["before"]["locked"]:
                report.pop("error_stage", None)
                report.update(
                    complete=True,
                    outcome="locked" if report["before"]["locked"] else "already_unlocked",
                    partitions=host.partitions(current_identity),
                )
                return report
            report["error_stage"] = "password input"
            credential = host.password()
            discovery("discovery-before-session", "locked")
            sessions = protocol.validate_start(
                exchange("anonymous-start", protocol.start_session(), (0, 0)), 4100
            )
            protocol.validate_get(
                exchange("anonymous-get", protocol.datastore_get(), sessions), 4100, sessions
            )
            reply = protocol.parse_response(
                exchange("anonymous-end", b"\xfa", sessions),
                expected_comid=4100,
                expected_sessions=sessions,
            )
            if reply.kind != "end_session":
                raise errors.Stop("anonymous_end_not_verified")
            report["session_may_be_open"] = False
            discovery("discovery-before-auth", "locked")
            raw = exchange("auth", protocol.start_session(credential), (0, 0))
            del credential
            auth = protocol.parse_response(raw, expected_comid=4100, expected_sessions=(0, 0))
            if auth.kind == "method":
                report["auth_method_status"] = auth.status
            if auth.kind != "method" or auth.status != 0:
                report["auth_response_diagnostic"] = protocol.auth_failure_diagnostic(auth, len(raw))
                report["recovery_eligible_after_reconnection"] = False
            if protocol.supported_auth_rejection(auth, len(raw)) and protocol.rejected_sync_checks_match(
                protocol.sync_session_checks(auth)
            ):
                # Exact refusal has no device session and made no setting change.
                report["session_may_be_open"] = False
                report["retry_without_reconnection"] = True
                raise errors.Stop("authentication_rejected")
            sessions = protocol.validate_start(raw, 4100)
            report["authenticated"] = True
            for name, payload in protocol.unlock_payloads():
                raw = exchange(name, payload, sessions)
                diagnostic = protocol.parse_response(
                    raw, expected_comid=4100, expected_sessions=sessions
                )
                report["commands"][-1].update(
                    response_kind=diagnostic.kind, response_status=diagnostic.status
                )
                protocol.validate_change(name, raw, 4100, sessions)
                report["commands"][-1]["validated"] = True
                if name == "transaction_end":
                    report["transaction_may_be_open"] = False
                if name == "end_session":
                    report["session_may_be_open"] = False
                checkpoint()
            report["after_unlock"] = discovery("discovery-after-unlock", "unlocked")
            transfer("relink", protocol.RELINK_CDB)
            report["relink_transport_success"] = True
            checkpoint()
        new, newseq = host.wait(current_identity, initial_generation, serial)
        if (
            serial not in new["serials"]
            or new["model"] != info["model"]
            or newseq == initial_generation
        ):
            raise errors.Stop("reenumeration_not_verified")
        current_identity = new
        initial_generation = newseq
        report["identity_after"] = current_identity
        report["reenumeration_verified"] = True
        with host.claim(current_identity["device"]):
            report["after"] = discovery("discovery-after-relink", "unlocked")
            report["partitions"] = host.partitions(current_identity)
        report["outcome"] = "unlocked"
        report["complete"] = True
        # The final checkpoint below reports storage failure separately from
        # the completed device operation.
        report.pop("error_stage", None)
    except errors.Stop as e:
        report.update(complete=False, error=str(e))
    except KeyboardInterrupt:
        report.update(complete=False, error="interrupted_no_retry")
    except protocol.ProtocolError:
        report.update(
            complete=False, error="unsupported_or_failed_protocol_response_no_retry"
        )
    except Exception:
        report.update(complete=False, error="local_error_details_suppressed_no_retry")
    finally:
        try:
            checkpoint()
        except (OSError, errors.Stop, KeyboardInterrupt):
            report["result_save_error"] = "result_checkpoint_failed"
    return report
