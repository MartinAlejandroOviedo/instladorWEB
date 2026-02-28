"""Authentication helpers for panel access."""

from __future__ import annotations

import hashlib
import re

import bcrypt

LEGACY_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def hash_panel_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_panel_password(password: str, stored_hash: str) -> bool:
    raw = stored_hash.strip()
    if not raw:
        return False
    if is_legacy_sha256_hash(raw):
        return hashlib.sha256(password.encode("utf-8")).hexdigest() == raw
    try:
        return bcrypt.checkpw(password.encode("utf-8"), raw.encode("utf-8"))
    except ValueError:
        return False


def is_legacy_sha256_hash(stored_hash: str) -> bool:
    return bool(LEGACY_SHA256_RE.fullmatch(stored_hash.strip().lower()))
