"""Shared initial operation state. Optional operation fields remain explicit."""
from typing import TypedDict


class OperationResult(TypedDict):
    action: str
    complete: bool
    identity: dict
    commands: list
    session_may_be_open: bool
    transaction_may_be_open: bool
    changes_may_have_occurred: bool
    relink_attempted: bool


def new_operation_result(action: str, identity: dict) -> OperationResult:
    """Return independent mutable state for one operation; no I/O or inference."""
    return dict(action=action, complete=False, identity=identity, commands=[],
                session_may_be_open=False, transaction_may_be_open=False,
                changes_may_have_occurred=False, relink_attempted=False)
