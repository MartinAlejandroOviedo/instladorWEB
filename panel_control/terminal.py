"""Terminal validation helpers for curses applications."""

from __future__ import annotations

import curses
import os
import sys


def ensure_curses_terminal(app_label: str) -> None:
    """Validate that the current process has a usable terminal for curses."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError(
            f"{app_label} requiere una terminal interactiva. "
            "Ejecutalo desde una sesion TTY/SSH real."
        )

    term = os.environ.get("TERM", "").strip()
    if not term or term in {"dumb", "unknown"}:
        raise RuntimeError(
            f"{app_label} requiere la variable TERM configurada "
            "(por ejemplo: export TERM=xterm-256color)."
        )

    stream = sys.__stdout__ or sys.stdout
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError) as exc:
        raise RuntimeError(
            f"{app_label} no pudo obtener el descriptor de la terminal actual."
        ) from exc

    try:
        curses.setupterm(term=term, fd=fd)
    except curses.error as exc:
        raise RuntimeError(
            f"{app_label} no pudo inicializar curses con TERM={term!r}. "
            "Proba export TERM=xterm-256color y volve a ejecutar."
        ) from exc
