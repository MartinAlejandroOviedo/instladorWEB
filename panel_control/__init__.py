"""Panel control package for post-install administration."""


def run_control_panel() -> None:
    from .app import run_control_panel as _run_control_panel

    _run_control_panel()


def run_panel_api() -> None:
    from .api import run_api as _run_api

    _run_api()


__all__ = ["run_control_panel", "run_panel_api"]
