#!/usr/bin/env python3
"""Unified launcher for NicePanel entrypoints."""

from __future__ import annotations

import os
import sys


MENU_OPTIONS = {
    "1": ("Instalador", ["python3", "installer_tui.py"]),
    "2": ("Panel TUI", ["python3", "panel_control_tui.py"]),
    "3": ("Panel Web/API", ["python3", "panel_control_api.py"]),
}

ALIASES = {
    "install": "1",
    "installer": "1",
    "tui": "2",
    "panel": "2",
    "web": "3",
    "api": "3",
}


def _run_command(command: list[str]) -> None:
    os.execvp(command[0], command)


def _resolve_choice(raw: str) -> str | None:
    choice = raw.strip().lower()
    if choice in MENU_OPTIONS:
        return choice
    return ALIASES.get(choice)


def _print_menu() -> None:
    print(
        "\n".join(
            [
                "    _  ___         ___                __",
                "   / |/ (_)______ / _ \\___ ____  ___ / /",
                "  /    / / __/ -_) ___/ _ `/ _ \\/ -_) /",
                " /_/|_/_/\\__/\\__/_/   \\_,_/_//_/\\__/_/",
                "",
                "Selecciona una opcion:",
                "  1. Instalador",
                "  2. Panel TUI",
                "  3. Panel Web/API",
                "  q. Salir",
            ]
        )
    )


def main() -> int:
    if len(sys.argv) > 1:
        choice = _resolve_choice(sys.argv[1])
        if not choice:
            print("Uso: python3 start.py [install|tui|web]", file=sys.stderr)
            return 2
        _run_command(MENU_OPTIONS[choice][1])
        return 0

    while True:
        _print_menu()
        selected = input("> ").strip().lower()
        if selected in {"q", "quit", "exit"}:
            return 0
        choice = _resolve_choice(selected)
        if choice:
            _run_command(MENU_OPTIONS[choice][1])
            return 0
        print("Opcion invalida.\n")


if __name__ == "__main__":
    raise SystemExit(main())
