"""Qt Widgets demo. QTimer simulates progress; no privileged or disk I/O occurs."""
import json
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import QTimer, QSaveFile, QIODevice, Signal
from PySide6.QtWidgets import (
    QCheckBox, QFormLayout, QFileDialog, QListView, QPlainTextEdit,
    QStyleFactory, QHBoxLayout, QLabel, QLineEdit,
    QApplication, QToolButton, QListWidget, QMainWindow, QProgressBar, QPushButton, QVBoxLayout, QWidget,
)
from . import theme, preferences
from .details import summary
from .model import DEVICES, SCENARIOS, STEPS, DemoModel


from .base_window import BaseWindow


class Window(BaseWindow):
    def __init__(self):
        self.model = DemoModel()
        super().__init__()
        self.setWindowTitle("T7 · GUI demo")
        self.banner.setText("DEMO MODE   ·   Simulated devices only   ·   Use a dummy password")
        self.devices_label.setText("SIMULATED DEVICES")
        self.footer.setText("The demo sends no SSD commands. Real-device operations appear in Device status mode.")
        for device in DEVICES:
            self.devices.addItem(f"{device.model}\n{device.serial} · {device.capacity}")
        self.devices.setCurrentRow(0)
        self.progress.setRange(0, len(STEPS))
        self.set_detail_text("DEMO MODE — no SSD commands are sent.\nReady to simulate an operation.")
        self.timer = QTimer(self)
        self.timer.setInterval(650)
        self.timer.timeout.connect(self.tick)
        self.devices.currentRowChanged.connect(self.reset_demo)
        self.scenario.currentIndexChanged.connect(self.reset_demo)
        self.reset_button.clicked.connect(self.reset_demo)
        self.unverified.toggled.connect(self.set_unverified)
        self.password.textChanged.connect(self.update_start)
        self.password.returnPressed.connect(self.start)
        self.show_password.toggled.connect(lambda show: self.password.setEchoMode(QLineEdit.EchoMode.Normal if show else QLineEdit.EchoMode.Password))
        self.unlock.clicked.connect(self.start)
        self.cancel.clicked.connect(self.cancel_demo)
        self.render()

    def build_controls(self, right):
        form = QFormLayout()
        self.scenario = theme.ScenarioCombo()
        # Fusion's list popup avoids platform menu scroller margins (black
        # strips on some KDE themes). Style the viewport explicitly as well.
        self.popup_style = theme.ComboListStyle(QStyleFactory.create("Fusion"))
        self.scenario.setStyle(self.popup_style)
        self.scenario.setView(QListView())
        self.popup_style.setParent(self.scenario)
        self.scenario.addItems(SCENARIOS)
        form.addRow("Demo scenario", self.scenario)
        right.addLayout(form)
        self.unverified = QCheckBox("Allow unverified model in this simulation")
        right.addWidget(self.unverified)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Dummy password only")
        self.password.setAccessibleName("Dummy password")
        self.password.setMaxLength(128)
        right.addWidget(self.password)
        self.show_password = QCheckBox("Show dummy password")
        right.addWidget(self.show_password)
        buttons = self.action_row = QHBoxLayout()
        self.unlock = QPushButton("Simulate unlock")
        self.unlock.setObjectName("primary")
        self.cancel = QPushButton("Cancel simulation")
        buttons.addWidget(self.unlock)
        buttons.addWidget(self.cancel)
        right.addLayout(buttons)

    def reset_demo(self, *_):
        self.timer.stop()
        self.password.clear()
        self.show_password.setChecked(False)
        self.unverified.setChecked(False)
        self.model.reset(DEVICES[self.devices.currentRow()], self.scenario.currentText())
        self.detail_entries.clear()
        self.append_detail(f"Demo reset: {self.model.device.model} / {self.model.scenario}")
        self.append_detail(self.model.message)
        self.render()

    def set_unverified(self, enabled):
        self.model.allow_unverified = enabled
        self.update_start()

    def update_start(self):
        self.unlock.setEnabled(self.model.can_start and bool(self.password.text()))

    def start(self):
        if not self.model.can_start or not self.password.text():
            return
        # Clear the field before progressing. The demo never forwards the value.
        self.password.clear()
        self.show_password.setChecked(False)
        self.model.start()
        self.append_detail("Starting unlock simulation (no SSD commands)")
        self.append_detail(self.model.message)
        self.render()
        self.timer.start()

    def tick(self):
        self.model.advance()
        self.append_detail(self.model.message)
        if not self.model.busy:
            self.timer.stop()
        self.render()

    def cancel_demo(self):
        self.timer.stop()
        self.password.clear()
        was_busy = self.model.busy
        self.model.cancel()
        if was_busy:
            self.append_detail(self.model.message)
        self.render()

    def render(self):
        model = self.model
        self.heading.setText(model.state)
        self.details.setText(f"{model.device.model} · {model.device.capacity}\nSerial: {model.device.serial} · Simulated USB connection")
        self.message.setText(model.message)
        self.progress.setValue(model.step)
        for control in (self.devices, self.scenario, self.reset_button, self.unverified):
            control.setEnabled(not model.busy)
        self.unverified.setVisible(not model.device.verified)
        editable = not model.busy and model.state == "Locked"
        self.password.setEnabled(editable)
        self.show_password.setEnabled(editable)
        self.cancel.setEnabled(model.busy)
        self.update_start()

    def closeEvent(self, event):
        # Safe only because this is a simulation. Real cancellation needs a
        # protocol-aware worker and must preserve uncertain-operation records.
        if self._details_window is not None:
            self._details_window.close()
        self.cancel_demo()
        event.accept()
