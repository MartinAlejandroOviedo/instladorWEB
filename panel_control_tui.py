#!/usr/bin/env python3
"""Launcher for post-install control panel TUI."""

import sys

from panel_control import run_control_panel


if __name__ == "__main__":
    try:
        run_control_panel()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
