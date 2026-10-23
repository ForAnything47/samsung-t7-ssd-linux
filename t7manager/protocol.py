"""Bounded TCG encoding, parsing and observed response validation.

Pure packet logic: no device access, input prompts or journal writes."""

from dataclasses import asdict, dataclass
import struct

from t7manager import errors


class ProtocolError(ValueError):
    pass


class IncompleteResponse(ProtocolError):
    pass


def uint(value):
    if not 0 <= value < 1 << 64:
        raise ValueError("uint64 required")
    if value < 64:
        return bytes([value])
    size = next((n for n in (1, 2, 4, 8) if value < 1 << 8 * n))
    return bytes([128 | size]) + value.to_bytes(size, "big")


def byte_atom(value):
    value = bytes(value)
    size = len(value)
    if size <= 15:
        return bytes([160 | size]) + value
    if size <= 2047:
        return bytes([208 | size >> 8, size & 255]) + value
    raise ValueError("long byte atoms not implemented")


# Payload length excludes padding; enclosing packet lengths include it.
# Zero-filled reserved fields and four-byte alignment are part of the wire format.
def frame(payload, comid, session_at20=0, session_at24=0):
    payload = bytes(payload)
    if not payload or len(payload) > 1024 * 1024:
        raise ValueError("payload size")
    total = 56 + len(payload) + 3 & ~3
    out = bytearray(total)
    struct.pack_into(">H", out, 4, comid)
    struct.pack_into(">I", out, 16, total - 20)
    struct.pack_into(">II", out, 20, session_at20, session_at24)
    struct.pack_into(">I", out, 40, total - 44)
    struct.pack_into(">I", out, 52, len(payload))
    out[56 : 56 + len(payload)] = payload
    return bytes(out)


def tokens(data):
    """Strict unsigned tiny/short integer, short/medium bytes, control subset."""
    result = []
    offset = 0
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag < 64:
            result.append(tag)
            continue
        if tag >= 240:
            if tag not in (240, 241, 242, 243, 248, 249, 250, 251, 252):
                raise ProtocolError("unknown control")
            result.append(("control", tag))
            continue
        if 128 <= tag <= 143:
            body_length = tag & 15
            kind = "uint"
            if not 1 <= body_length <= 8:
                raise ProtocolError("integer size")
        elif 160 <= tag <= 175:
            body_length = tag & 15
            kind = "bytes"
        elif 208 <= tag <= 215:
            if offset == len(data):
                raise ProtocolError("truncated atom header")
            body_length = (tag & 7) << 8 | data[offset]
            offset += 1
            kind = "bytes"
        else:
            raise ProtocolError("unsupported atom kind")
        if offset + body_length > len(data):
            raise ProtocolError("truncated atom body")
        body = data[offset : offset + body_length]
        offset += body_length
        result.append(int.from_bytes(body, "big") if kind == "uint" else bytes(body))
    return tuple(result)


@dataclass(frozen=True)
class Response:
    comid: int
    session_at20: int
    session_at24: int
    kind: str
    status: int
    values: tuple


# Reject unsupported framing instead of treating incomplete data as success.
# Callers separately validate method-specific tokens, status, and session identity.
def parse_response(data, *, expected_comid=None, expected_sessions=None):
    data = bytes(data)
    if len(data) < 20:
        raise ProtocolError("short ComPacket header")
    if any(data[:4]):
        raise ProtocolError("nonzero reserved ComPacket bytes")
    comid, extension = struct.unpack_from(">HH", data, 4)
    outstanding, minimum, clen = struct.unpack_from(">III", data, 8)
    if expected_comid is not None and comid != expected_comid:
        raise ProtocolError("ComID mismatch")
    if extension:
        raise ProtocolError("ComID extension unsupported")
    if outstanding or minimum:
        raise IncompleteResponse("continuation unsupported; not success")
    if not clen or 20 + clen > len(data):
        raise ProtocolError("ComPacket length")
    if any(data[20 + clen :]):
        raise ProtocolError("nonzero bytes after single ComPacket")
    if clen < 36:
        raise ProtocolError("missing nested headers")
    s0, s1 = struct.unpack_from(">II", data, 20)
    if expected_sessions is not None and (s0, s1) != tuple(expected_sessions):
        raise ProtocolError("session mismatch")
    plen = struct.unpack_from(">I", data, 40)[0]
    slen = struct.unpack_from(">I", data, 52)[0]
    if not slen or plen != 12 + (slen + 3 & ~3) or clen != 24 + plen:
        raise ProtocolError("nested lengths unsupported/inconsistent")
    end = 56 + slen
    if end > 20 + clen:
        raise ProtocolError("payload overruns packet")
    if any(data[end : 20 + clen]):
        raise ProtocolError("nonzero alignment padding")
    if any(data[28:40]) or any(data[44:52]):
        raise ProtocolError("extended header unsupported")
    payload = data[56:end]
    if payload == b"\xfa":
        return Response(comid, s0, s1, "end_session", 0, ())
    if len(payload) == 2 and payload[0] in (251, 252):
        return Response(comid, s0, s1, "transaction", payload[1], ())
    if (
        len(payload) < 5
        or payload[-5] != 240
        or payload[-1] != 241
        or (payload[-3:-1] != b"\x00\x00")
    ):
        raise ProtocolError("invalid method status trailer")
    if payload[-4] >= 64:
        raise ProtocolError("non-tiny status unsupported")
    return Response(comid, s0, s1, "method", payload[-4], tokens(payload[:-5]))


UID = {
    0: "00000000000000ff",
    1: "0000080200000001",
    3: "0000020500000002",
    6: "0000000900010001",
    13: "0000080300000001",
    15: "0000100100000000",
    32: "000000000000ff02",
    33: "0000000600000016",
    34: "0000000600000017",
}


TAIL = b"\xf0\x00\x00\x00\xf1"


def uid(index):
    return byte_atom(bytes.fromhex(UID[index]))


def method(obj, method_id, args):
    return b"\xf8" + uid(obj) + uid(method_id) + b"\xf0" + args + b"\xf1\xf9" + TAIL


def start_session(credential=None):
    args = uint(1) + uid(3) + uint(1)
    if credential is not None:
        credential = bytes(credential)
        if not 4 <= len(credential) <= 16 or any(
            (not 33 <= v <= 126 for v in credential)
        ):
            raise ValueError("only observed UI ASCII password range 4..16 supported")
        args += b"\xf2\x00" + byte_atom(credential) + b"\xf3\xf2\x03" + uid(6) + b"\xf3"
    return method(0, 32, args)


def datastore_get():
    return method(
        15, 33, b"\xf0\xf2\x01" + uint(0) + b"\xf3\xf2\x02" + uint(143) + b"\xf3\xf1"
    )


def unlock_payloads():
    """Offline reference sequence; responses must gate each next command."""
    result = [("transaction_start", b"\xfb\x00")]
    for name, obj, col, val in [
        ("mbr_done", 13, 2, 1),
        ("read_unlock", 1, 7, 0),
        ("write_unlock", 1, 8, 0),
    ]:
        result.append(
            (
                name,
                method(
                    obj,
                    34,
                    b"\xf2\x01\xf0\xf2" + uint(col) + uint(val) + b"\xf3\xf1\xf3",
                ),
            )
        )
    result.append(
        (
            "datastore_mode",
            method(
                15,
                34,
                b"\xf2\x00" + uint(2) + b"\xf3\xf2\x01" + byte_atom(b"\x03") + b"\xf3",
            ),
        )
    )
    result.extend([("transaction_end", b"\xfc\x00"), ("end_session", b"\xfa")])
    return tuple(result)


def security_cdb(opcode, protocol, specific, length):
    if (
        opcode not in (162, 181)
        or not 0 <= protocol <= 255
        or (not 0 <= specific <= 65535)
        or (not 0 < length < 2**32)
    ):
        raise ValueError("invalid Security Protocol CDB fields")
    return (
        bytes([opcode, protocol])
        + specific.to_bytes(2, "big")
        + b"\x00\x00"
        + length.to_bytes(4, "big")
        + b"\x00\x00"
    )


DISCOVERY_CDB = security_cdb(162, 1, 1, 4096)


RELINK_CDB = bytes.fromhex("e8 00 00 00 00 00")


@dataclass(frozen=True)
class Discovery:
    comid: int
    locking_supported: bool
    locking_enabled: bool
    locked: bool
    mbr_enabled: bool
    mbr_done: bool
    header_length: int


def parse_discovery(raw):
    """Bounded allocation scan like SILU07; zero tail ends the feature list.

    Header length is reported, not used to guess truncation conventions.
    Unsupported/missing required features are errors, never unlocked status.
    """
    raw = bytes(raw)
    if not 48 <= len(raw) <= 4096:
        raise ProtocolError("Discovery allocation length")
    offset = 48
    found = {}
    while offset < len(raw):
        if not any(raw[offset:]):
            break
        if offset + 4 > len(raw):
            raise ProtocolError("truncated feature header")
        code = int.from_bytes(raw[offset : offset + 2], "big")
        payload_length = raw[offset + 3]
        if code == 0 or offset + 4 + payload_length > len(raw):
            raise ProtocolError("invalid feature boundary")
        if code in found:
            raise ProtocolError("duplicate feature")
        found[code] = raw[offset + 4 : offset + 4 + payload_length]
        offset += 4 + payload_length
    lock = found.get(2, b"")
    opal = found.get(515, b"")
    if len(lock) < 1 or len(opal) < 2:
        raise ProtocolError("missing Locking/Opal2 feature")
    comid = int.from_bytes(opal[:2], "big")
    if comid in (0, 65535):
        raise ProtocolError("invalid ComID")
    flags = lock[0]
    return Discovery(
        comid,
        *(bool(flags & 1 << b) for b in (0, 1, 2, 4, 5)),
        int.from_bytes(raw[:4], "big"),
    )


def session_numbers(raw, comid):
    r = parse_response(raw, expected_comid=comid)
    c = lambda v: ("control", v)
    v = r.values
    if r.kind != "method" or r.status:
        raise ProtocolError("StartSession failed")
    if len(v) != 8 or v[0] != c(248) or v[3] != c(240) or (v[6:] != (c(241), c(249))):
        raise ProtocolError("unsupported StartSession result shape")
    if not all((isinstance(x, bytes) and len(x) == 8 for x in v[1:3])):
        raise ProtocolError("bad result UIDs")
    if not all((type(x) is int and 0 < x < 2**32 for x in v[4:6])):
        raise ProtocolError("bad session numbers")
    return (v[5], v[4])


def validate_start(raw, comid):
    response = parse_response(raw, expected_comid=comid, expected_sessions=(0, 0))
    sessions = session_numbers(raw, comid)
    if response.values[1:3] != (
        bytes.fromhex("00000000000000ff"),
        bytes.fromhex("000000000000ff03"),
    ):
        raise ProtocolError("unsupported SyncSession UIDs; inspect capture")
    if sessions[1] != 1:
        raise ProtocolError("host session mismatch")
    return sessions


def validate_get(raw, comid, sessions):
    response = parse_response(raw, expected_comid=comid, expected_sessions=sessions)
    control = lambda n: ("control", n)
    if response.kind != "method" or response.status or len(response.values) != 4:
        raise ProtocolError("unsupported DataStore response")
    if response.values[0] != control(240) or response.values[2:] != (control(241), control(249)):
        raise ProtocolError("unsupported DataStore token shape")
    data = response.values[1]
    if not isinstance(data, bytes) or len(data) != 144:
        raise ProtocolError("expected 144 DataStore bytes")
    return data


def validate_change(name, raw, comid, sessions):
    response = parse_response(raw, expected_comid=comid, expected_sessions=sessions)
    if name in ("transaction_start", "transaction_end"):
        opcode = 251 if name == "transaction_start" else 252
        if response.kind != "transaction" or response.status != 0 or raw[56] != opcode:
            raise errors.Stop("unsupported_or_failed_transaction_response")
    elif name == "end_session":
        if response.kind != "end_session":
            raise errors.Stop("end_session_not_verified")
    else:
        empty_result = (("control", 240), ("control", 241), ("control", 249))
        if response.kind != "method" or response.status != 0 or response.values != empty_result:
            raise errors.Stop("unsupported_or_failed_set_response")
    return response


def parse_state(raw, expected):
    if len(raw) != 4096 or int.from_bytes(raw[:4], "big") != 160 or any(raw[164:]):
        raise errors.Stop("discovery_layout_changed")
    discovery = parse_discovery(raw[:164])
    if (
        discovery.comid != 4100
        or not discovery.locking_supported
        or (not discovery.locking_enabled)
        or (not discovery.mbr_enabled)
    ):
        raise errors.Stop("security_configuration_changed")
    if discovery.locked != (expected == "locked") or discovery.mbr_done != (expected == "unlocked"):
        raise errors.Stop("unexpected_lock_state")
    return asdict(discovery)


def auth_failure_diagnostic(response, received):
    """Structural metadata only: never serialize token values or packet bytes."""
    shapes = []
    for token in response.values:
        if isinstance(token, bytes):
            shapes.append({"kind": "bytes", "length": len(token)})
        elif type(token) is int:
            shapes.append({"kind": "integer"})
        elif isinstance(token, tuple) and len(token) == 2 and token[0] == "control":
            shapes.append({"kind": "control"})
        else:
            shapes.append({"kind": "unsupported"})
    reasons = []
    if response.kind != "method":
        reasons.append("response_kind_not_method")
    if response.status != 1:
        reasons.append("status_not_supported_rejection")
    if response.values != () and not rejected_sync_checks_match(
        sync_session_checks(response)
    ):
        reasons.append("unsupported_return_tokens")
    if received != 2048:
        reasons.append("unexpected_receive_length")
    return {
        "response_kind": response.kind,
        "received_bytes": received,
        "token_count": len(shapes),
        "token_shapes": shapes,
        "sync_session_checks": sync_session_checks(response),
        "recovery_exclusion_reasons": reasons,
    }


def sync_session_checks(response):
    """Diagnostic comparisons only, not authorization to recover or continue."""
    v = response.values
    eight = len(v) == 8
    integers = eight and all(type(x) is int for x in v[4:6])
    return {
        "eight_tokens": eight,
        "control_tokens_match": eight
        and v[0] == ("control", 248)
        and v[3] == ("control", 240)
        and v[6:] == (("control", 241), ("control", 249)),
        "invoking_uid_match": eight and v[1] == bytes.fromhex("00000000000000ff"),
        "sync_session_uid_match": eight and v[2] == bytes.fromhex("000000000000ff03"),
        "header_sessions_zero": response.session_at20 == 0
        and response.session_at24 == 0,
        "session_values_uint32": integers and all(0 <= x < 2**32 for x in v[4:6]),
        "host_session_matches_request": integers and v[4] == 1,
        "device_session_zero": integers and v[5] == 0,
        "device_session_positive_uint32": integers and 0 < v[5] < 2**32,
    }


def rejected_sync_checks_match(checks):
    expected = {
        "eight_tokens": True,
        "control_tokens_match": True,
        "invoking_uid_match": True,
        "sync_session_uid_match": True,
        "header_sessions_zero": True,
        "session_values_uint32": True,
        "host_session_matches_request": True,
        "device_session_zero": True,
        "device_session_positive_uint32": False,
    }
    return set(checks) == set(expected) and all(
        checks[k] is v for k, v in expected.items()
    )


def supported_auth_rejection(response, received):
    return (
        response.kind == "method"
        and response.status == 1
        and received == 2048
        and response.session_at20 == 0
        and response.session_at24 == 0
        and (
            response.values == ()
            or rejected_sync_checks_match(sync_session_checks(response))
        )
    )


# ---- Experimental password change ----
def password_authentication_payload(credential, authority):
    """Build one StartSession for an explicitly supported credential authority."""
    if authority not in (6, 7):
        raise errors.Stop("unsupported_password_authority")
    start_session(credential)
    authority_uid = bytes.fromhex(
        "0000000900010001" if authority == 6 else "0000000900010002"
    )
    arguments = uint(1) + uid(3) + uint(1)
    arguments += b"\xf2\x00" + byte_atom(credential) + b"\xf3"
    arguments += b"\xf2\x03" + byte_atom(authority_uid) + b"\xf3"
    return method(0, 32, arguments)


def password_pin_set(target, credential):
    """Encode a Set of PIN column 3 for one of the two recovered targets."""
    if target not in (19, 20):
        raise errors.Stop("unsupported_password_target")
    start_session(credential)  # Reuse the observed credential format validation.
    target_uid = bytes.fromhex(
        "0000000b00010001" if target == 19 else "0000000b00010002"
    )
    return (
        b"\xf8"
        + byte_atom(target_uid)
        + uid(34)
        + b"\xf0\xf2\x01\xf0\xf2\x03"
        + byte_atom(credential)
        + b"\xf3\xf1\xf3\xf1\xf9"
        + TAIL
    )


# ---- Default credential structure probe (never logs credential bytes) ----
def admin_sp_anonymous_start():
    return method(
        0, 32, uint(1) + byte_atom(bytes.fromhex("0000020500000001")) + uint(1)
    )


def default_credential_get():
    target = byte_atom(bytes.fromhex("0000000b00008402"))
    return (
        b"\xf8"
        + target
        + uid(33)
        + b"\xf0\xf0\xf2\x03\x03\xf3\xf2\x04\x03\xf3\xf1\xf1\xf9"
        + TAIL
    )


def default_credential_structure(response):
    """Return structural facts, never a credential, hash, or token value."""
    values = response.values
    control = lambda value: ("control", value)
    shape_matches = (
        len(values) == 9
        and values[:3] == (control(240), control(240), control(242))
        and type(values[3]) is int
        and values[3] == 3
        and isinstance(values[4], bytes)
        and values[5:] == (control(243), control(241), control(241), control(249))
    )
    return {
        "token_shapes": [
            (
                {"kind": "bytes", "length": len(value)}
                if isinstance(value, bytes)
                else (
                    {"kind": "integer"}
                    if type(value) is int
                    else (
                        {"kind": "control"}
                        if isinstance(value, tuple)
                        and len(value) == 2
                        and value[0] == "control"
                        else {"kind": "unsupported"}
                    )
                )
            )
            for value in values
        ],
        "expected_column_structure": shape_matches,
        "nonempty_credential": shape_matches and len(values[4]) > 0,
        "credential_bytes_saved": False,
    }


# ---- Experimental security setup/removal ----
def security_discovery(raw):
    """Decode this Shield profile without requiring password security enabled."""
    if len(raw) != 4096 or int.from_bytes(raw[:4], "big") != 160 or any(raw[164:]):
        raise errors.Stop("discovery_layout_changed")
    decoded = parse_discovery(raw[:164])
    if decoded.comid != 4100 or not decoded.locking_supported:
        raise errors.Stop("unsupported_security_profile")
    return asdict(decoded)


# LockingEnabled remains true on the tested SSD after password removal.
# For disabled security, require unlocked/MBR-disabled here; callers also verify
# DataStore mode and credentials before declaring the operation complete.
def require_security_mode(snapshot, enabled):
    if snapshot["locked"] or (enabled and not snapshot["locking_enabled"]):
        raise errors.Stop("security_mode_precondition_failed")
    if snapshot["mbr_enabled"] != enabled:
        raise errors.Stop("security_mode_precondition_failed")
    # MBRDone is not prescribed when shadowing is disabled.
    if enabled and not snapshot["mbr_done"]:
        raise errors.Stop("security_mode_precondition_failed")


def device_credential(value):
    """Only the observed 32-byte device value, with no text conversion."""
    if not isinstance(value, bytes) or len(value) != 32:
        raise errors.Stop("unsupported_default_credential_length")
    return value


def security_auth_payload(credential, authority=6, default=False):
    if not default:
        return password_authentication_payload(credential, authority)
    device_credential(credential)
    if authority not in (6, 7):
        raise errors.Stop("unsupported_password_authority")
    authority_uid = bytes.fromhex(
        "0000000900010001" if authority == 6 else "0000000900010002"
    )
    return method(
        0,
        32,
        uint(1)
        + uid(3)
        + uint(1)
        + b"\xf2\x00"
        + byte_atom(credential)
        + b"\xf3"
        + b"\xf2\x03"
        + byte_atom(authority_uid)
        + b"\xf3",
    )


def default_pin_set(target, credential):
    device_credential(credential)
    if target not in (19, 20):
        raise errors.Stop("unsupported_password_target")
    target_uid = bytes.fromhex(
        "0000000b00010001" if target == 19 else "0000000b00010002"
    )
    return (
        b"\xf8"
        + byte_atom(target_uid)
        + uid(34)
        + b"\xf0\xf2\x01\xf0\xf2\x03"
        + byte_atom(credential)
        + b"\xf3\xf1\xf3\xf1\xf9"
        + TAIL
    )


# The order below is recovered from Samsung host code, not a generic reset.
# The caller sends one payload at a time and checks its response before advancing.
def security_mutations(action, credential):
    """Build the recovered order; callers must validate each individual reply."""

    def integer(target, column, value):
        return method(
            target,
            34,
            b"\xf2\x01\xf0\xf2" + uint(column) + uint(value) + b"\xf3\xf1\xf3",
        )

    if action == "set-password":
        pins = [
            (f"pin-{target}", password_pin_set(target, credential))
            for target in (19, 20)
        ]
        fields = [
            ("enable-read-lock", 1, 5, 1),
            ("enable-write-lock", 1, 6, 1),
            ("read-unlocked", 1, 7, 0),
            ("write-unlocked", 1, 8, 0),
            ("mbr-enabled", 13, 1, 1),
            ("mbr-done", 13, 2, 1),
        ]
        writes = pins + [
            (name, integer(target, column, value))
            for name, target, column, value in fields
        ]
        mode = b"\x03"
    elif action == "remove-password":
        fields = [
            ("mbr-disabled", 13, 1, 0),
            ("read-unlocked", 1, 7, 0),
            ("write-unlocked", 1, 8, 0),
            ("disable-read-lock", 1, 5, 0),
            ("disable-write-lock", 1, 6, 0),
        ]
        writes = [
            (name, integer(target, column, value))
            for name, target, column, value in fields
        ]
        writes += [
            (f"pin-{target}", default_pin_set(target, credential))
            for target in (19, 20)
        ]
        mode = b"\x02"
    else:
        raise errors.Stop("unsupported_security_action")
    writes.append(
        (
            "datastore-mode",
            method(15, 34, b"\xf2\x00\x02\xf3\xf2\x01" + byte_atom(mode) + b"\xf3"),
        )
    )
    return writes
