#!/usr/bin/env python3
"""Launch device-status GUI; --demo selects the hardware-free simulation."""
import sys
import argparse
import resource
from pathlib import Path

# Isolated launch loads only the colocated application modules.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def main():
    parser = argparse.ArgumentParser(description="Unofficial T7 SSD Password Manager")
    parser.add_argument('--demo', action='store_true', help='Use simulated devices; send no SSD commands')
    args = parser.parse_args()
    try:
        from PySide6.QtWidgets import QApplication
        from gui.window import Window
    except ModuleNotFoundError as exc:
        if exc.name != "PySide6":
            raise
        print("GUI dependency missing. Install requirements-gui.txt in a virtual environment.", file=sys.stderr)
        return 1
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    app = QApplication(sys.argv)
    app.setApplicationName("T7 SSD Password Manager")
    if args.demo:
        window = Window()
    else:
        from gui.live import LiveWindow
        window = LiveWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
