#!/usr/bin/env python3
"""CLI launcher. Keep the complete t7manager package beside this file."""
import sys
from pathlib import Path

# Support isolated Python (-I) without trusting cwd, user site or PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from t7manager.cli.main import main


if __name__ == "__main__":
    raise SystemExit(main())
