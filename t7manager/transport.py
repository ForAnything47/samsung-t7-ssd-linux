"""Linux host adapters used by operation state machines.

Operations retain their own transfer ordering, checkpoints and response rules.
Fake adapters exercise the same flows without touching a device."""

import subprocess

from t7manager import credentials as password_input, device as device_api, safety


class Host:
    usage = staticmethod(safety.usage_snapshot)
    identify = staticmethod(device_api.identity)
    gen = staticmethod(device_api.generation)
    idle = staticmethod(safety.require_idle)
    claim = staticmethod(safety.exclusive_device)
    wait = staticmethod(device_api.wait_reenumeration)
    password = staticmethod(password_input.read_password)
    partitions = staticmethod(device_api.partition_paths)
    run = staticmethod(subprocess.run)


class UnverifiedModelHost(Host):
    """Explicit per-run model opt-in; transport and response checks stay unchanged.

    Re-identification and Relink discovery must use the same scope as initial
    selection. No global model whitelist is changed by this adapter.
    """

    allow_unverified_model = True
    identify = staticmethod(lambda device: device_api.identity(device, family=True))

    @staticmethod
    def wait(before, old_generation, serial):
        return device_api.wait_reenumeration(
            before, old_generation, serial,
            finder=lambda value: device_api.find_device(value, family=True),
        )


def operation_model_allowed(model, host):
    """Only exact T7 family names can opt in, never arbitrary USB devices."""
    return device_api.is_supported_model(model) or (
        getattr(host, "allow_unverified_model", False) is True
        and device_api.is_t7_family(model)
    )


class QueryHost:
    identify = staticmethod(lambda device: device_api.identity(device, family=True))
    gen = staticmethod(device_api.generation)
    idle = staticmethod(safety.require_idle)
    claim = staticmethod(safety.exclusive_device)
    run = staticmethod(subprocess.run)


def transfer_command(host, device, cdb, record, checkpoint, *, payload=None,
                     request=None, exact_length=True):
    """Execute once after the caller's identity checks and attempt checkpoint.

    Callers own protocol ordering and uncertainty flags. Unlock historically
    permits short replies for its parser, whereas password operations require
    the requested length. Keep that policy explicit.
    """
    from t7manager import errors
    command = ['sg_raw', '--readonly', '--cmdset=1', '--timeout=30']
    if payload is not None:
        command += ['--send=' + str(len(payload))]
    elif request is not None:
        command += ['--request=' + str(request), '--outfile=-']
    command += [device, *[f'{value:02x}' for value in cdb]]
    try:
        reply = host.run(command, input=payload if payload is not None else b'',
                         capture_output=True, timeout=45, check=False)
    except subprocess.TimeoutExpired:
        record['phase'] = 'timeout'
        checkpoint()
        raise errors.Stop('transport_timeout_no_retry') from None
    record.update(phase='returned', returncode=reply.returncode)
    if request is not None:
        record['received'] = len(reply.stdout)
    checkpoint()
    if reply.returncode:
        raise errors.Stop('transport_failed_no_retry')
    if request is not None:
        if exact_length and len(reply.stdout) != request:
            raise errors.Stop('unexpected_receive_length')
        if not exact_length and len(reply.stdout) > request:
            raise errors.Stop('oversized_response')
        return reply.stdout
