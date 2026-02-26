"""Service integration layer for future real provisioning.

This module currently returns command previews. It is intentionally conservative
until each service integration is fully validated in production.
"""

from __future__ import annotations

from typing import List


def dns_apply_preview() -> List[str]:
    return [
        "# TODO: render named zone files from DB records",
        "named-checkconf",
        "named-checkzone <zone> /etc/bind/db.<zone>",
        "systemctl reload bind9",
    ]


def ftp_apply_preview() -> List[str]:
    return [
        "# TODO: provision virtual FTP users from DB",
        "systemctl reload vsftpd",
    ]


def mail_apply_preview() -> List[str]:
    return [
        "# TODO: provision virtual mailbox users from DB",
        "systemctl reload postfix",
        "systemctl reload dovecot",
    ]
