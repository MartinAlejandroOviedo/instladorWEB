"""Panel control package for post-install administration."""


def run_control_panel() -> None:
    from .app import run_control_panel as _run_control_panel

    _run_control_panel()


__all__ = ["run_control_panel"]
