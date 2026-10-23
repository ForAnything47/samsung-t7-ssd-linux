# Offline tests

Run from the repository root:

```bash
QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -p 'test_*.py'
```

Mocks use fabricated serials and credentials. The binary fixture contains a bounded Discovery profile, no identity or credential data. Tests patch the owning core modules and send no SSD commands. GUI tests require PySide6 and are skipped when it is unavailable.

Distribution tests copy the launcher and core package to a temporary directory,
check execution from an unrelated working directory, and verify that imports
and help do not create state. Tests also confirm that legacy `pending.json`
files remain untouched.
