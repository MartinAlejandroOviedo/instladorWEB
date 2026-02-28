"""Validation helpers for control panel entities."""

from __future__ import annotations

import re

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HOST_LABEL_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain.strip()))


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email.strip()))


def is_valid_hostname_label(value: str) -> bool:
    if value == "@":
        return True
    return bool(HOST_LABEL_RE.match(value.strip()))


def is_valid_record_type(record_type: str) -> bool:
    return record_type.upper() in {"A", "AAAA", "CNAME", "MX", "TXT"}


def is_valid_ipv4(value: str) -> bool:
    raw = value.strip()
    if not IPV4_RE.match(raw):
        return False
    parts = raw.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def is_valid_ipv4_list(value: str) -> bool:
    raw = value.strip()
    if not raw:
        return True
    items = [item.strip() for item in raw.split(",")]
    return all(item and is_valid_ipv4(item) for item in items)


def is_valid_fqdn_or_label(value: str) -> bool:
    raw = value.strip().rstrip(".")
    return is_valid_domain(raw) or is_valid_hostname_label(raw)
