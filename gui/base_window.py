"""Shared window layout, preferences and operation-detail presentation."""
import json
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import QSaveFile, QIODevice, Signal
from PySide6.QtWidgets import (
    QFileDialog, QPlainTextEdit,
    QHBoxLayout, QLabel,
    QApplication, QToolButton, QListWidget, QMainWindow, QProgressBar, QPushButton, QVBoxLayout, QWidget,
)
from . import theme, preferences
from .details import summary


class BaseWindow(QMainWindow):
    details_updated = Signal()

    def __init__(self):
        super().__init__()
        self._details_window = None
        self.resize(960, 640)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(30, 24, 30, 24)
        layout.setSpacing(18)
        title = QLabel("Samsung T7")
        title.setObjectName("title")
        title_row = self.title_row = QHBoxLayout()
        title_row.addWidget(title)
        title_row.addStretch()
        self.settings_button = QPushButton('Settings')
        self.settings_button.clicked.connect(self.open_settings)
        title_row.addWidget(self.settings_button)
        layout.addLayout(title_row)
        banner = self.banner = QLabel()
        banner.setObjectName("banner")
        layout.addWidget(banner)
        body = QHBoxLayout()
        layout.addLayout(body, 1)
        left = QVBoxLayout()
        self.devices_label = QLabel()
        left.addWidget(self.devices_label)
        self.devices = QListWidget()
        self.devices.setMaximumWidth(270)
        left.addWidget(self.devices)
        self.reset_button = QPushButton("Reset demo")
        left.addWidget(self.reset_button)
        body.addLayout(left)
        right = QVBoxLayout()
        right.setSpacing(16)
        body.addLayout(right, 1)
        self.heading = QLabel()
        self.heading.setObjectName("heading")
        right.addWidget(self.heading)
        self.details = QLabel()
        right.addWidget(self.details)
        self.build_controls(right)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setTextVisible(False)
        right.addWidget(self.progress)
        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.setMinimumHeight(76)
        right.addWidget(self.message)
        detail_header = QHBoxLayout()
        detail_header.addWidget(QLabel("Operation details"))
        detail_header.addStretch()
        self.detail_mode = theme.ScenarioCombo()
        self.detail_mode.setObjectName("detailMode")
        self.detail_mode.addItems(["Summary", "JSON"])
        self.detail_mode.setAccessibleName("Operation details display mode")
        detail_header.addWidget(self.detail_mode)
        self.detail_entries = []
        self.detail_mode.currentIndexChanged.connect(self.render_details)
        self.copy_details = QToolButton()
        self.copy_details.setIcon(theme.detail_icon("copy"))
        self.copy_details.setToolTip("Copy displayed details")
        self.copy_details.setAccessibleName("Copy displayed details")
        self.copy_details.clicked.connect(self.copy_detail_text)
        self.save_details = QToolButton()
        self.save_details.setIcon(theme.detail_icon("save"))
        self.save_details.setToolTip("Save displayed details as text")
        self.save_details.setAccessibleName("Save displayed details as text")
        self.save_details.clicked.connect(self.save_detail_text)
        detail_header.addWidget(self.copy_details)
        detail_header.addWidget(self.save_details)
        self.open_details = QToolButton()
        self.open_details.setText("Open window")
        self.open_details.setToolTip("Open operation details in a resizable window")
        self.open_details.setAccessibleName("Open operation details window")
        self.open_details.clicked.connect(self.open_details_window)
        detail_header.addWidget(self.open_details)
        right.addLayout(detail_header)
        self.operation_text = QPlainTextEdit()
        self.operation_text.setReadOnly(True)
        self.operation_text.setMinimumHeight(210)
        self.operation_text.setAccessibleName("Operation details")
        self.operation_text.setMaximumBlockCount(0)
        self.set_detail_text("")
        # Give spare vertical space to the details editor, not an empty spacer.
        right.addWidget(self.operation_text, 1)
        footer = self.footer = QLabel()
        footer.setWordWrap(True)
        layout.addWidget(footer)
        selected_theme, self.authorization_seconds = preferences.load()
        self.apply_theme(selected_theme == 'dark')

    def apply_settings(self, selected_theme, seconds):
        if hasattr(self, 'runner') and seconds != self.authorization_seconds:
            self.runner.end_session()
        self.authorization_seconds = seconds
        self.apply_theme(selected_theme == 'dark')

    def open_settings(self):
        dialog = preferences.SettingsDialog(self, 'dark' if self.is_dark else 'light',
                                            self.authorization_seconds, self.apply_settings)
        dialog.exec()
        dialog.deleteLater()

    def apply_theme(self, dark):
        """Apply palette to the main window and separate popup windows."""
        self.is_dark = dark
        self.setStyleSheet(theme.stylesheet(dark))
        if hasattr(self, "scenario"):
            self.scenario.setProperty("darkMode", dark)
        self.detail_mode.setProperty("darkMode", dark)
        icon_color = "#e3eaf3" if dark else "#243e58"
        self.copy_details.setIcon(theme.detail_icon("copy", icon_color))
        self.save_details.setIcon(theme.detail_icon("save", icon_color))
        if self._details_window is not None:
            self._details_window.apply_theme(dark)
        if getattr(self, 'log_viewer', None) is not None:
            self.log_viewer.setStyleSheet(self.styleSheet())
            self.log_viewer.days.setProperty('darkMode', dark)

    def set_detail_text(self, text):
        self.detail_entries = [("", "Note", text, text)]
        self.render_details()

    def append_detail(self, message):
        self.detail_entries.append((datetime.now().strftime('%H:%M:%S'), "Event", message, message))
        self.render_details()

    def append_report(self, action, report):
        self.detail_entries.append((datetime.now().strftime('%H:%M:%S'), action,
                                    summary(action, report), json.dumps(report, indent=2, ensure_ascii=False)))
        self.render_details()

    def render_details(self, *_):
        if not hasattr(self, 'operation_text'):
            return
        # Keep whole entries; JSON objects are never truncated in the middle.
        self.detail_entries = self.detail_entries[-100:]
        raw = self.detail_mode.currentText() == "JSON"
        blocks = []
        for timestamp, title, human, machine in self.detail_entries:
            blocks.append(f"{'─' * 12} {title.upper()} {timestamp} {'─' * 12}\n" + (machine if raw else human))
        self.operation_text.setPlainText('\n\n'.join(blocks))
        self.operation_text.verticalScrollBar().setValue(self.operation_text.verticalScrollBar().maximum())
        self.details_updated.emit()

    def open_details_window(self):
        if self._details_window is None:
            from .details_window import DetailsWindow
            self._details_window = DetailsWindow(self)
            self._details_window.show()
        else:
            self._details_window.raise_()
            self._details_window.activateWindow()

    def copy_text(self, text, target):
        QApplication.clipboard().setText(text)
        target.statusBar().showMessage("Displayed details copied", 3500)

    def copy_detail_text(self):
        self.copy_text(self.operation_text.toPlainText(), self)

    def save_detail_text(self):
        self.export_detail_text(self.operation_text.toPlainText(), self)

    def export_detail_text(self, text, window):
        path, _ = QFileDialog.getSaveFileName(window, "Save displayed details", "t7-details.txt", "Text files (*.txt)")
        if not path:
            return
        if Path(path).suffix.lower() != ".txt":
            window.statusBar().showMessage("Choose a .txt file for the details export.", 6000)
            return
        output = QSaveFile(path)
        data = text.encode("utf-8")
        if not output.open(QIODevice.OpenModeFlag.WriteOnly):
            window.statusBar().showMessage("Unable to open export destination", 6000)
            return
        if output.write(data) != len(data):
            output.cancelWriting()
            window.statusBar().showMessage("Unable to write details; export cancelled", 6000)
            return
        if not output.commit():
            window.statusBar().showMessage("Unable to save details", 6000)
            return
        window.statusBar().showMessage("Displayed details saved", 3500)

