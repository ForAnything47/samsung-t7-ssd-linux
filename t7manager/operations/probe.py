"""Diagnostic queries and anonymous default-credential structure inspection."""

from dataclasses import asdict
import subprocess

from t7manager import device as device_api, errors, protocol, records, transport


INQUIRY_CDB = bytes.fromhex("12 00 00 00 24 00")


QUERIES = (("inquiry", INQUIRY_CDB, 36), ("discovery", protocol.DISCOVERY_CDB, 4096))


def analyze(raw, model):
    declared = int.from_bytes(raw[:4], "big") if len(raw) >= 4 else None
    if (
        declared is None
        or not 48 <= declared + 4 <= len(raw)
        or any(raw[declared + 4 :])
    ):
        raise errors.Stop("unsupported_discovery_length_convention")
    d = protocol.parse_discovery(raw[: declared + 4])
    features = []
    pos = 48
    while pos < declared + 4:
        if not any(raw[pos : declared + 4]):
            break
        size = raw[pos + 3]
        features.append(
            {
                "code": f"{int.from_bytes(raw[pos:pos + 2], 'big'):04x}",
                "version_byte": raw[pos + 2],
                "payload_length": size,
            }
        )
        pos += 4 + size
    matches = False
    for state in ("locked", "unlocked"):
        try:
            protocol.parse_state(raw, state)
            matches = True
            break
        except errors.Stop:
            pass
    return {
        "discovery": asdict(d),
        "features": features,
        "classification": (
            "observed_profile_match_unverified_device"
            if matches
            else "parsed_profile_differs"
        ),
        "model_has_prior_validation": model.strip().lower() == "pssd t7 shield",
        "unlock_compatibility_proven": False,
        "note": "Discovery similarity does not prove authentication, unlock or Relink compatibility.",
    }


def collect(info, out, host=None, state=None):
    host = host or transport.QueryHost()
    if out is not None:
        out.mkdir(parents=True, exist_ok=False, mode=448)
    result = {
        "action": "probe",
        "complete": False,
        "identity": info,
        "commands": [],
        "unlock_compatibility_proven": False,
    }
    try:
        seq = host.gen(info)
        host.idle(info["device"])
        with host.claim(info["device"]):
            for name, cdb, count in QUERIES:
                if host.identify(info["device"]) != info or host.gen(info) != seq:
                    raise errors.Stop("device_identity_or_generation_changed")
                host.idle(info["device"])
                rec = {
                    "name": name,
                    "cdb": cdb.hex(),
                    "requested": count,
                    "phase": "attempting",
                }
                result["commands"].append(rec)
                if state is not None:
                    records.operation_checkpoint(state, result, out)
                elif out is not None:
                    records.save(out / "result.json", result)
                cmd = [
                    "sg_raw",
                    "--readonly",
                    "--cmdset=1",
                    "--timeout=30",
                    f"--request={count}",
                    "--outfile=-",
                    info["device"],
                    *[f"{b:02x}" for b in cdb],
                ]
                response = host.run(
                    cmd, input=b"", capture_output=True, timeout=45, check=False
                )
                rec.update(
                    phase="returned",
                    returncode=response.returncode,
                    received=len(response.stdout),
                    stderr=response.stderr.decode("utf-8", "replace"),
                )
                if state is not None:
                    records.operation_checkpoint(state, result, out)
                if out is not None:
                    (out / (name + ".bin")).write_bytes(response.stdout)
                if response.returncode:
                    raise errors.Stop("transport_failed_no_retry")
                if len(response.stdout) != count:
                    raise errors.Stop("unexpected_response_length_no_retry")
                if name == "inquiry":
                    raw = response.stdout
                    result["inquiry"] = {
                        "vendor": raw[8:16].decode("ascii", "replace").strip(),
                        "product": raw[16:32].decode("ascii", "replace").strip(),
                        "revision": raw[32:36].decode("ascii", "replace").strip(),
                    }
                else:
                    result.update(analyze(response.stdout, info["model"]))
            if host.identify(info["device"]) != info or host.gen(info) != seq:
                raise errors.Stop("device_identity_or_generation_changed")
            result["complete"] = True
    except subprocess.TimeoutExpired:
        result["error"] = "transport_timeout_no_retry"
        result["commands"][-1]["phase"] = "timeout"
    except (errors.Stop, protocol.ProtocolError) as e:
        result.update(error=str(e), classification="unsupported_or_incomplete")
    except KeyboardInterrupt:
        result["error"] = "interrupted_no_retry"
    except Exception:
        result["error"] = "local_error_no_retry"
    finally:
        if state is not None:
            try:
                records.operation_checkpoint(state, result, out)
            except (OSError, errors.Stop, KeyboardInterrupt):
                result["result_save_error"] = "result_checkpoint_failed"
        if out is not None:
            try:
                records.save(out / "result.json", result)
            except (OSError, errors.Stop, KeyboardInterrupt):
                result["result_save_error"] = "result_checkpoint_failed"
    return result


# The returned value is an authentication secret, even though Get is anonymous.
# Persist only structural metadata, never token values or raw response packets.
def probe_default_credential(info, serial, out, state, host=None):
    """Anonymous AdminSP Get only. Unsupported replies stop without retries."""
    host = host or transport.Host()
    result = {
        "action": "probe-default-credential",
        "complete": False,
        "identity": info,
        "commands": [],
        "session_may_be_open": False,
        "changes_may_have_occurred": False,
        "credential_bytes_saved": False,
    }
    sequence = host.gen(info)

    def transfer(name, cdb, payload=None, receive_bytes=None):
        result["error_stage"] = name
        if host.identify(info["device"]) != info or host.gen(info) != sequence:
            raise errors.Stop("device_identity_or_generation_changed")
        host.idle(info["device"])
        record = {"name": name, "phase": "attempting"}
        result["commands"].append(record)
        records.operation_checkpoint(state, result, out)
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        if payload is not None:
            command += ["--send=" + str(len(payload))]
        else:
            command += ["--request=" + str(receive_bytes), "--outfile=-"]
        command += [info["device"], *[f"{value:02x}" for value in cdb]]
        try:
            reply = host.run(
                command,
                input=payload or b"",
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            record["phase"] = "timeout"
            records.operation_checkpoint(state, result, out)
            raise errors.Stop("transport_timeout_no_retry") from None
        record.update(phase="returned", returncode=reply.returncode)
        if receive_bytes is not None:
            record["received"] = len(reply.stdout)
        records.operation_checkpoint(state, result, out)
        if reply.returncode:
            raise errors.Stop("transport_failed_no_retry")
        if receive_bytes is not None:
            if len(reply.stdout) != receive_bytes:
                raise errors.Stop("unexpected_receive_length")
            return reply.stdout

    def exchange(name, payload, sessions):
        packet = protocol.frame(payload, 4100, *sessions)
        transfer(name + "-out", protocol.security_cdb(181, 1, 4100, len(packet)), payload=packet)
        return transfer(
            name + "-in", protocol.security_cdb(162, 1, 4100, 2048), receive_bytes=2048
        )

    def discovery(name):
        raw = transfer(name, protocol.DISCOVERY_CDB, receive_bytes=4096)
        if int.from_bytes(raw[:4], "big") != 160 or any(raw[164:]):
            raise errors.Stop("discovery_layout_changed")
        decoded = protocol.parse_discovery(raw[:164])
        if decoded.comid != 4100 or not decoded.locking_supported:
            raise errors.Stop("unsupported_security_profile")
        return asdict(decoded)

    try:
        if out is not None:
            out.mkdir(parents=True, exist_ok=False, mode=0o700)
        with host.claim(info["device"]):
            result["before"] = discovery("discovery-before")
            result["session_may_be_open"] = True
            sessions = protocol.validate_start(
                exchange("anonymous-admin-start", protocol.admin_sp_anonymous_start(), (0, 0)),
                4100,
            )
            raw = exchange("default-get", protocol.default_credential_get(), sessions)
            response = protocol.parse_response(
                raw, expected_comid=4100, expected_sessions=sessions
            )
            result["structure"] = protocol.default_credential_structure(response)
            result["method_status"] = response.status
            if response.kind != "method" or response.status != 0:
                raise errors.Stop("default_credential_query_rejected")
            if not result["structure"]["nonempty_credential"]:
                raise errors.Stop("unsupported_default_credential_structure")
            del raw, response
            end = protocol.parse_response(
                exchange("anonymous-admin-end", b"\xfa", sessions),
                expected_comid=4100,
                expected_sessions=sessions,
            )
            if end.kind != "end_session":
                raise errors.Stop("end_session_not_verified")
            result["session_may_be_open"] = False
            result["after"] = discovery("discovery-after")
            if result["before"] != result["after"]:
                raise errors.Stop("security_state_changed_during_probe")
            result.update(complete=True, outcome="credential_structure_verified")
            result.pop("error_stage", None)
    except KeyboardInterrupt:
        result["error"] = "interrupted"
    except errors.Stop as exc:
        result["error"] = str(exc)
    except protocol.ProtocolError:
        result["error"] = "unsupported_protocol_response"
    except Exception:
        result["error"] = "local_error"
    finally:
        result["recovery_required"] = bool(result["session_may_be_open"])
        try:
            records.operation_checkpoint(state, result, out)
        except (OSError, errors.Stop, KeyboardInterrupt):
            result["result_save_error"] = "result_checkpoint_failed"
    return result
