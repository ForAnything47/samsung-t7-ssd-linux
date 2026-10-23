"""Deterministic demo state machine, independent of Qt and device access.

Passwords never enter this model. Scenarios select simulated outcomes; they
must not be used to infer the outcome of a real device operation.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Device:
    model: str
    serial: str
    capacity: str = "2 TB"
    verified: bool = True


DEVICES = (
    Device("PSSD T7 Shield", "DEMO-SHIELD"),
    Device("PSSD T7 Touch", "DEMO-TOUCH", verified=False),
    Device("PSSD T7", "DEMO-T7", verified=False),
)
SCENARIOS = ("Successful unlock", "Password rejected", "Disconnected")
STEPS = ("Checking simulated state", "Simulating authentication", "Simulating unlock", "Simulating reconnection")


class DemoModel:
    def __init__(self):
        self.device = DEVICES[0]
        self.scenario = SCENARIOS[0]
        self.allow_unverified = False
        self.busy = False
        self.step = 0
        self.state = "Locked"
        self.message = "Ready. Enter a dummy password to try the demo."

    def reset(self, device, scenario):
        if self.busy:
            raise ValueError("Cannot change devices during a simulation")
        self.device, self.scenario = device, scenario
        self.allow_unverified = False
        self.step = 0
        self.state = {"Disconnected": "Disconnected"}.get(scenario, "Locked")
        self.message = {
            "Disconnected": "No device connected in this simulated scenario.",
        }.get(scenario, "Ready. Enter a dummy password to try the demo.")

    @property
    def can_start(self):
        return (not self.busy and self.state == "Locked"
                and (self.device.verified or self.allow_unverified))

    def start(self):
        if not self.can_start:
            raise ValueError("Operation is blocked")
        self.busy = True
        self.step = 0
        self.message = STEPS[0]

    def advance(self):
        if not self.busy:
            return
        self.step += 1
        if self.scenario == "Password rejected" and self.step == 2:
            self.busy = False
            self.message = "Authentication rejected (simulation). Try another dummy password."
        elif self.step >= len(STEPS):
            self.busy = False
            self.state = "Unlocked"
            self.message = "Simulation complete. No SSD commands were sent."
        else:
            self.message = STEPS[self.step]

    def cancel(self):
        if self.busy:
            self.busy = False
            self.state = "Locked"
            self.step = 0
            self.message = "Simulation cancelled. No SSD commands were sent."
