"""Resizable, read-only viewer for the selected device's operation logs."""

import json
from datetime import datetime

from PySide6.QtCore import Qt, QSignalBlocker
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QListView, QListWidget, QPlainTextEdit,
    QPushButton, QSizePolicy, QSplitter, QStyleFactory, QTabWidget, QVBoxLayout,
)

from . import theme
from .details import summary


class LogViewer(QDialog):
    def __init__(self, request_day, parent=None):
        super().__init__(parent)
        self.request_day = request_day
        self.setWindowTitle('T7 · Operation logs')
        self.resize(900, 600)
        self.setMinimumSize(640, 360)
        self.entries = []
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        controls.addWidget(QLabel('Date (local time)'))
        self.days = theme.ScenarioCombo()
        self.days.setObjectName('logDate')
        self.days.setView(QListView())
        self.popup_style = theme.ComboListStyle(QStyleFactory.create('Fusion'))
        self.days.setStyle(self.popup_style)
        self.popup_style.setParent(self.days)
        self.days.setProperty('darkMode', getattr(parent, 'is_dark', False))
        self.days.setAccessibleName('Operation log date')
        # Reserve room for YYYY-MM-DD and the arrow even on narrow windows.
        self.days.setMinimumWidth(180)
        self.days.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.days.currentIndexChanged.connect(self.day_changed)
        controls.addWidget(self.days)
        self.refresh_button = QPushButton('Refresh logs')
        self.refresh_button.clicked.connect(lambda: self.request_day(None))
        controls.addWidget(self.refresh_button)
        controls.addStretch()
        layout.addLayout(controls)
        self.notice = QLabel('Choose a date to read its operation logs.')
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.runs = QListWidget()
        self.runs.setAccessibleName('Operations on selected date')
        self.runs.currentRowChanged.connect(self.show_entry)
        splitter.addWidget(self.runs)
        self.tabs = QTabWidget()
        self.human = QPlainTextEdit()
        self.raw = QPlainTextEdit()
        for editor in (self.human, self.raw):
            editor.setReadOnly(True)
        self.tabs.addTab(self.human, 'Summary')
        self.tabs.addTab(self.raw, 'JSON')
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

    def show_report(self, report):
        if not report.get('complete'):
            self.entries = []
            self.runs.clear()
            self.show_entry(-1)
            self.notice.setText('Unable to read operation logs. Check administrator authorization and the log directory.')
            return
        dates = report.get('dates', [])
        selected = report.get('day')
        skipped = report.get('skipped_count', 0)
        warning = f' · {skipped} unreadable log(s) skipped; files preserved.' if skipped else ''
        self.notice.setToolTip('\n'.join(f"{item['file']}: {item['reason']}" for item in report.get('warnings', [])))
        with QSignalBlocker(self.days):
            self.days.clear()
            self.days.addItems(dates)
            if selected in dates:
                self.days.setCurrentText(selected)
        if selected is None:
            if dates:
                self.request_day(dates[0])
            else:
                self.entries = []
                self.runs.clear()
                self.show_entry(-1)
                self.notice.setText('No readable operation logs for this device.' + warning)
            return
        self.entries = report.get('entries', [])
        with QSignalBlocker(self.runs):
            self.runs.clear()
            for entry in self.entries:
                try:
                    when = datetime.fromisoformat(entry['started_at']).astimezone().strftime('%H:%M:%S')
                except (KeyError, ValueError, TypeError):
                    when = '?'
                outcome = 'Completed' if entry.get('complete') else entry.get('error') or 'Incomplete'
                self.runs.addItem(f"{when}  {entry.get('action', '?')}  ·  {outcome}")
        self.notice.setText(f"{len(self.entries)} operation(s) on {selected}"
                            + (' · Showing the latest 100' if report.get('truncated') else '')
                            + '. Read-only; no SSD commands sent.' + warning)
        self.show_entry(0 if self.entries else -1)
        if self.entries:
            self.runs.setCurrentRow(0)

    def day_changed(self, *_):
        day = self.days.currentText()
        if day:
            self.request_day(day)

    def show_entry(self, row):
        if row < 0 or row >= len(self.entries):
            self.human.clear()
            self.raw.clear()
            return
        entry = self.entries[row]
        text = summary(entry.get('action', ''), entry)
        self.human.setPlainText(text + '\n\nLog ID: ' + entry.get('run_id', '?')
                                + '\nStarted: ' + entry.get('started_at', '?')
                                + '\nLast update: ' + entry.get('updated_at', '?'))
        self.raw.setPlainText(json.dumps(entry, indent=2, ensure_ascii=False))
