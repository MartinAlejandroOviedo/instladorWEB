"""Small secret encryption helpers for local panel data."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

DEFAULT_KEY_PATH = "/etc/panelctl/panel.key"
FALLBACK_KEY_PATH = os.path.expanduser("~/.local/share/nicepanel/.panel.key")


def _key_path() -> str:
    return DEFAULT_KEY_PATH if os.access(os.path.dirname(DEFAULT_KEY_PATH), os.W_OK) else FALLBACK_KEY_PATH


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def _load_or_create_key() -> bytes:
    path = _key_path()
    _ensure_parent_dir(path)
    if os.path.exists(path):
        return open(path, "rb").read()
    key = secrets.token_bytes(32)
    with open(path, "wb") as handle:
        handle.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _xor_keystream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    chunks: list[bytes] = []
    counter = 0
    while len(b"".join(chunks)) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        chunks.append(block)
        counter += 1
    stream = b"".join(chunks)[: len(data)]
    return bytes(a ^ b for a, b in zip(data, stream))


def encrypt_string(plaintext: str) -> str:
    raw = plaintext.encode("utf-8")
    key = _load_or_create_key()
    nonce = secrets.token_bytes(16)
    ciphertext = _xor_keystream(key, nonce, raw)
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    payload = b"np1:" + nonce + tag + ciphertext
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_string(encoded: str) -> str:
    payload = base64.urlsafe_b64decode(encoded.encode("ascii"))
    if not payload.startswith(b"np1:"):
        raise ValueError("secret_format_invalid")
    blob = payload[4:]
    if len(blob) < 48:
        raise ValueError("secret_payload_invalid")
    nonce = blob[:16]
    tag = blob[16:48]
    ciphertext = blob[48:]
    key = _load_or_create_key()
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("secret_tag_invalid")
    return _xor_keystream(key, nonce, ciphertext).decode("utf-8")
