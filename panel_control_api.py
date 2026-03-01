#!/usr/bin/env python3
"""Launcher for panel control REST API."""

import sys

from panel_control import run_panel_api


if __name__ == "__main__":
    try:
        run_panel_api()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
