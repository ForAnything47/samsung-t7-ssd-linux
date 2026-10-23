"""Terminal credential input and existing format checks.

The GUI supplies its own hidden input through the host adapter. Never log input."""

import getpass
import sys
import warnings

from t7manager import errors, protocol
from t7manager.cli import i18n


def hidden_password_prompt(prompt):
    """Keep interrupted prompts off JSON stdout and preserve cancellation."""
    try:
        return getpass.getpass(prompt, stream=sys.stderr)
    except KeyboardInterrupt:
        # Use the same stream as the prompt. Reporting failure must not replace
        # the interruption or let the caller continue with a password value.
        try:
            print(file=sys.stderr, flush=True)
        except OSError:
            pass
        raise


def read_password():
    if not sys.stdin.isatty():
        raise errors.Stop("interactive_terminal_required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        first = hidden_password_prompt(
            i18n.tr("T7 SSD password (hidden; NOT your Linux sudo password): ")
        )
    try:
        credential = first.encode("ascii")
    except UnicodeError:
        raise errors.Stop("unsupported_password_format_no_auth_sent") from None
    if not 4 <= len(credential) <= 16 or any((not 33 <= b <= 126 for b in credential)):
        raise errors.Stop("unsupported_password_format_no_auth_sent")
    return credential


def change_password_inputs():
    """Collect all inputs before opening a session or changing credentials."""
    if not sys.stdin.isatty():
        raise errors.Stop("interactive_terminal_required")
    values = []
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        for label in (
            "Current T7 password: ",
            "New T7 password: ",
            "Re-enter new T7 password: ",
        ):
            try:
                value = hidden_password_prompt(i18n.tr(label)).encode("ascii")
            except UnicodeError:
                raise errors.Stop("unsupported_password_format_no_auth_sent") from None
            try:
                protocol.start_session(value)
            except ValueError:
                raise errors.Stop("unsupported_password_format_no_auth_sent") from None
            values.append(value)
    current_password, new_password, confirmed_password = values
    if new_password != confirmed_password:
        raise errors.Stop("password_entries_differ_no_auth_sent")
    if current_password == new_password:
        raise errors.Stop("new_password_same_no_changes")
    return current_password, new_password


def new_security_password():
    if not sys.stdin.isatty():
        raise errors.Stop("interactive_terminal_required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            first = hidden_password_prompt(i18n.tr("New T7 password: ")).encode("ascii")
            second = hidden_password_prompt(i18n.tr("Re-enter new T7 password: ")).encode("ascii")
            protocol.start_session(first)
            protocol.start_session(second)
        except (UnicodeError, ValueError):
            raise errors.Stop("unsupported_password_format_no_auth_sent") from None
    if first != second:
        raise errors.Stop("password_entries_differ_no_auth_sent")
    return first
