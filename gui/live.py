"""Real-device operations reuse the CLI safety and transaction flows."""
import json
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QLabel, QPushButton, QInputDialog, QLineEdit, QMessageBox, QHBoxLayout
from .backend import CliRunner
from .window import Window
from .explanations import failure_explanation
from .log_viewer import LogViewer


class LiveWindow(Window):
    def __init__(self, runner=None, auto_refresh=True):
        self.live_ready = False
        super().__init__()
        self.setWindowTitle('T7 · Device status')
        self.runner = runner or CliRunner(self)
        self.runner.completed.connect(self.received)
        self.runner.password_required.connect(self.ask_password)
        self.log_viewer = None
        self.candidates = []
        self.live_busy = False
        self.selected = None
        self.live_ready = True
        self.findChild(QLabel, 'banner').setText('DEVICE STATUS   ·   List: host only   ·   Status: explicit administrator authorization')
        for label in self.findChildren(QLabel):
            if label.text() == 'SIMULATED DEVICES':
                label.setText('DEVICES')
            elif label.text() == 'Demo scenario':
                label.hide()
            elif label.text().startswith('No SSD commands are sent.'):
                label.setText('Status sends a Discovery query. Password operations use the existing CLI checks and operation logs.\nDisplayed states are last observations.')
            # Device strings are untrusted data, never rich text.
            label.setTextFormat(Qt.TextFormat.PlainText)
        for control in (self.scenario, self.password, self.show_password, self.cancel):
            control.hide()
        self.reset_button.setText('Refresh devices')
        self.logs_button = QPushButton('Operation logs')
        self.logs_button.setAccessibleName('View operation logs for selected device')
        self.logs_button.clicked.connect(self.open_logs)
        title_row = self.centralWidget().layout().itemAt(0).layout()
        title_row.insertWidget(title_row.indexOf(self.settings_button), self.logs_button)
        self.unlock.setText('Refresh status')
        self.real_unlock = QPushButton('Unlock device')
        self.real_unlock.setObjectName('primary')
        self.real_unlock.clicked.connect(self.unlock_device)
        self.unlock_row().addWidget(self.real_unlock)
        self.password_buttons = {}
        row = QHBoxLayout()
        for action, title in (('change-password', 'Change password'), ('set-password', 'Set password'), ('remove-password', 'Remove password')):
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, operation=action: self.password_operation(operation))
            row.addWidget(button)
            self.password_buttons[action] = button
        # Keep password controls on their own row at narrow window widths.
        buttons = self.unlock_row()
        parent = buttons.parent()
        parent.insertLayout(parent.indexOf(buttons) + 1, row)
        self.unverified.setText('Allow operations for this unverified model')
        self.unverified.toggled.connect(self.render)
        self.devices.blockSignals(True)
        self.devices.clear()
        self.devices.blockSignals(False)
        self.set_detail_text('Select a device and choose Refresh status. Listing alone sends no SSD commands.')
        self.heading.setText('No device selected')
        self.details.setText('Refresh the device list to begin.')
        self.message.setText('Ready')
        self.render()
        if auto_refresh:
            QTimer.singleShot(0, self.refresh_devices)

    def unlock_row(self):
        def find(layout):
            for index in range(layout.count()):
                item = layout.itemAt(index)
                if item.widget() is self.unlock:
                    return layout
                if item.layout():
                    result = find(item.layout())
                    if result is not None:
                        return result
            return None
        return find(self.centralWidget().layout())

    def unlock_device(self):
        if self.live_busy or not self.selected or not self.real_unlock.isEnabled():
            return
        self.heading.setText('Unlock in progress')
        self.run('unlock', self.selected['serials'][0], self.unverified.isChecked())

    def password_operation(self, action):
        if self.live_busy or not self.selected or not self.password_buttons[action].isEnabled():
            return
        if action == 'remove-password':
            answer = QMessageBox.question(self, 'Remove password security',
                'Remove password protection from the selected SSD? Its data will become accessible without a password. The current password is required.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.run(action, self.selected['serials'][0], self.unverified.isChecked())

    def ask_password(self):
        dialog = QInputDialog(self)
        dialog.setWindowTitle('T7 SSD password')
        prompt = getattr(self.runner, 'prompt', 'current')
        current_label = 'Current T7 SSD password (not your administrator password):'
        dialog.setLabelText({'current': current_label,
                             'new': 'New T7 SSD password:',
                             'confirm': 'Re-enter the new T7 SSD password:'}[prompt])
        dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
        accepted = dialog.exec()
        password = dialog.textValue() if accepted else None
        dialog.setTextValue('')
        dialog.deleteLater()
        self.runner.provide_password(password)
        password = None
        self.message.setText('Waiting for CLI completion. Do not disconnect the SSD.' if accepted else 'Cancelling before authentication…')
        self.append_detail('Password submitted through private pipe; waiting for operation result.' if accepted else 'Password input cancelled before authentication.')

    def reset_demo(self, *args):
        if not self.live_ready:
            return super().reset_demo(*args)
        # Both the list selection signal and refresh button use this slot.
        if self.sender() is self.devices:
            self.select_device()
        else:
            self.refresh_devices()

    def refresh_devices(self):
        if self.live_busy:
            return
        if self.log_viewer is not None:
            self.log_viewer.close()
        self.selected = None
        self.heading.setText('Refreshing device list')
        self.details.setText('Host-only enumeration')
        self.run('list')

    def select_device(self):
        self.runner.end_session()
        if self.log_viewer is not None:
            self.log_viewer.close()
        row = self.devices.currentRow()
        self.selected = self.candidates[row] if 0 <= row < len(self.candidates) else None
        self.unverified.setChecked(False)
        self.heading.setText('Status not queried')
        if self.selected:
            info = self.selected
            self.details.setText(f"{info['model']} · {info['device']}\nSerial: {', '.join(info['serials'])}")
        else:
            self.details.setText('No device selected')
        self.render()

    def start(self):
        if not self.live_ready:
            return
        if self.live_busy or not self.selected or not self.unlock.isEnabled():
            return
        self.heading.setText('Querying status')
        self.run('status', self.selected['serials'][0], self.unverified.isChecked())

    def run(self, action, serial=None, allow=False):
        self.live_busy = True
        self.message.setText('Waiting for system authorization and CLI response…' if action != 'list' else 'Reading host device list…')
        self.append_detail('Requested ' + action + (' for serial ' + serial if serial else ''))
        self.render()
        self.runner.authorization_seconds = self.authorization_seconds
        self.runner.start(action, serial, allow)

    def open_logs(self):
        if self.live_busy or not self.selected:
            return
        if self.log_viewer is None:
            self.log_viewer = LogViewer(self.request_logs, self)
            self.log_viewer.finished.connect(lambda _: setattr(self, 'log_viewer', None))
            self.log_viewer.setStyleSheet(self.styleSheet())
            self.log_viewer.show()
            self.request_logs(None)
        else:
            self.log_viewer.raise_()
            self.log_viewer.activateWindow()

    def request_logs(self, day):
        if self.live_busy or not self.selected:
            return
        self.live_busy = True
        if self.log_viewer is not None:
            self.log_viewer.notice.setText('Loading operation logs…')
            self.log_viewer.days.setEnabled(False)
            self.log_viewer.refresh_button.setEnabled(False)
        self.render()
        self.runner.authorization_seconds = self.authorization_seconds
        self.runner.start('logs', self.selected['serials'][0], False, day)

    def received(self, action, report):
        self.live_busy = False
        if action == 'logs':
            if self.log_viewer is not None:
                self.log_viewer.days.setEnabled(True)
                self.log_viewer.refresh_button.setEnabled(True)
                self.log_viewer.show_report(report)
            self.render()
            return
        self.append_report(action, report)
        if action == 'list':
            values = report.get('candidates', [])
            self.candidates = [v for v in values if isinstance(v, dict)
                and isinstance(v.get('model'), str) and isinstance(v.get('device'), str)
                and isinstance(v.get('serials'), list) and v['serials']
                and all(isinstance(s, str) and s for s in v['serials'])] if isinstance(values, list) else []
            self.devices.blockSignals(True)
            self.devices.clear()
            for v in self.candidates:
                self.devices.addItem(f"{v['model']}\n{v['device']} · {v['serials'][0]}")
            self.devices.blockSignals(False)
            self.select_device()
            if len(self.candidates) == 1:
                self.devices.setCurrentRow(0)
            if not self.candidates:
                self.heading.setText('No supported device found')
        elif report.get('complete') is True:
            state = report.get('after', report.get('before', {}))
            locked = state.get('locked') if isinstance(state, dict) else None
            self.heading.setText('Locked (last observed)' if locked is True else 'Unlocked (last observed)' if locked is False else 'Unknown state')
        else:
            self.heading.setText('Operation not completed')
        if report.get('complete') is True:
            if action == 'status':
                self.message.setText('Status received. Discovery alone does not establish password-security mode.')
            else:
                self.message.setText('Host list updated. Select a device to query its status.' if action == 'list' else 'Unlock completed; partitions are shown in the details. No automatic mount.' if action == 'unlock' else 'Password operation completed. Review the verification results below.' if action in self.password_buttons else 'Status received. Discovery alone does not establish password-security mode.')
        else:
            cause, guidance, _ = failure_explanation(action, report)
            self.message.setText(cause + '\n' + guidance)
        if report.get('result_save_error'):
            self.message.setText(self.message.text() + '\nWarning: Log/result saving failed. Preserve Operation details; do not repeat a change just to save its result.')
        self.render()

    def render(self, *_):
        if not getattr(self, 'live_ready', False):
            return super().render()
        unknown = bool(self.selected and self.selected['model'] != 'PSSD T7 Shield')
        self.unverified.setVisible(unknown)
        self.unverified.setEnabled(not self.live_busy)
        self.unlock.setEnabled(bool(self.selected) and not self.live_busy and (not unknown or self.unverified.isChecked()))
        self.real_unlock.setEnabled(self.unlock.isEnabled())
        for button in self.password_buttons.values():
            button.setEnabled(self.real_unlock.isEnabled())
        for control in (self.devices, self.reset_button):
            control.setEnabled(not self.live_busy)
        self.settings_button.setEnabled(not self.live_busy)
        self.logs_button.setEnabled(bool(self.selected) and not self.live_busy)
        self.progress.setRange(0, 0 if self.live_busy else 1)
        if not self.live_busy:
            self.progress.setValue(0)

    def closeEvent(self, event):
        if self.live_busy:
            self.statusBar().showMessage('Wait for the active query or cancel the system authorization dialog before closing.', 6000)
            event.ignore()
            return
        if self._details_window is not None:
            self._details_window.close()
        if self.log_viewer is not None:
            self.log_viewer.close()
        self.runner.end_session()
        event.accept()
