"""Minimal REST API for panel control."""

from __future__ import annotations

import base64
import hmac
import json
import secrets
import time
from dataclasses import asdict
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .auth import is_legacy_sha256_hash, verify_panel_password
from .services import DNSConfig, list_apache_modules
from .storage import PanelStore
from .validators import is_valid_email, is_valid_ipv4, is_valid_ipv4_list

DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8088
TOKEN_TTL_SECONDS = 8 * 60 * 60


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


class PanelAPI:
    def __init__(self, store: PanelStore | None = None) -> None:
        self.store = store or PanelStore()

    def get_dns_config(self) -> DNSConfig:
        return DNSConfig(
            ns1_hostname=self.store.get_setting("dns_ns1_hostname", "ns1.localdomain"),
            ns1_ipv4=self.store.get_setting("dns_ns1_ipv4", "127.0.0.1"),
            ns2_hostname=self.store.get_setting("dns_ns2_hostname", ""),
            ns2_ipv4=self.store.get_setting("dns_ns2_ipv4", ""),
            listen_on=self.store.get_setting("dns_listen_on", "any"),
            forwarders=self.store.get_setting("dns_forwarders", "1.1.1.1,8.8.8.8"),
            allow_recursion=self.store.get_setting("dns_allow_recursion", "1") == "1",
        )

    def set_dns_config(self, config: DNSConfig) -> None:
        self.store.set_setting("dns_ns1_hostname", config.ns1_hostname)
        self.store.set_setting("dns_ns1_ipv4", config.ns1_ipv4)
        self.store.set_setting("dns_ns2_hostname", config.ns2_hostname)
        self.store.set_setting("dns_ns2_ipv4", config.ns2_ipv4)
        self.store.set_setting("dns_listen_on", config.listen_on)
        self.store.set_setting("dns_forwarders", config.forwarders)
        self.store.set_setting("dns_allow_recursion", "1" if config.allow_recursion else "0")

    def get_public_settings(self) -> dict[str, Any]:
        return {
            "dns": asdict(self.get_dns_config()),
            "recovery_email": self.store.get_setting("recovery_email", ""),
            "recovery_whatsapp": self.store.get_setting("recovery_whatsapp", ""),
        }

    def update_public_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        dns_payload = payload.get("dns", {})
        current = self.get_dns_config()
        ns1_hostname = str(dns_payload.get("ns1_hostname", current.ns1_hostname)).strip().lower().rstrip(".")
        ns1_ipv4 = str(dns_payload.get("ns1_ipv4", current.ns1_ipv4)).strip()
        ns2_hostname = str(dns_payload.get("ns2_hostname", current.ns2_hostname)).strip().lower().rstrip(".")
        ns2_ipv4 = str(dns_payload.get("ns2_ipv4", current.ns2_ipv4)).strip()
        listen_on = str(dns_payload.get("listen_on", current.listen_on)).strip()
        forwarders = str(dns_payload.get("forwarders", current.forwarders)).strip()
        allow_recursion = bool(dns_payload.get("allow_recursion", current.allow_recursion))
        recovery_email = str(payload.get("recovery_email", self.store.get_setting("recovery_email", ""))).strip().lower()
        recovery_whatsapp = str(payload.get("recovery_whatsapp", self.store.get_setting("recovery_whatsapp", ""))).strip()

        if not ns1_hostname:
            raise ValueError("ns1_hostname es obligatorio")
        if "." not in ns1_hostname:
            raise ValueError("ns1_hostname debe ser FQDN")
        if not is_valid_ipv4(ns1_ipv4):
            raise ValueError("ns1_ipv4 invalido")
        if ns2_hostname and "." not in ns2_hostname:
            raise ValueError("ns2_hostname debe ser FQDN")
        if ns2_ipv4 and not is_valid_ipv4(ns2_ipv4):
            raise ValueError("ns2_ipv4 invalido")
        if ns2_hostname and not ns2_ipv4:
            raise ValueError("falta ns2_ipv4")
        if ns2_ipv4 and not ns2_hostname:
            raise ValueError("falta ns2_hostname")
        if listen_on.lower() != "any" and not is_valid_ipv4_list(listen_on):
            raise ValueError("listen_on invalido")
        if not is_valid_ipv4_list(forwarders):
            raise ValueError("forwarders invalidos")
        if recovery_email and not is_valid_email(recovery_email):
            raise ValueError("recovery_email invalido")

        self.set_dns_config(
            DNSConfig(
                ns1_hostname=ns1_hostname,
                ns1_ipv4=ns1_ipv4,
                ns2_hostname=ns2_hostname,
                ns2_ipv4=ns2_ipv4,
                listen_on=listen_on or "any",
                forwarders=forwarders,
                allow_recursion=allow_recursion,
            )
        )
        self.store.set_setting("recovery_email", recovery_email)
        self.store.set_setting("recovery_whatsapp", recovery_whatsapp)
        return self.get_public_settings()

    def _get_api_secret(self) -> str:
        secret = self.store.get_setting("api_secret")
        if secret:
            return secret
        secret = secrets.token_urlsafe(32)
        self.store.set_setting("api_secret", secret)
        return secret

    def issue_token(self, username: str) -> str:
        payload = {"u": username, "exp": int(time.time()) + TOKEN_TTL_SECONDS}
        encoded = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signature = hmac.new(self._get_api_secret().encode("utf-8"), encoded.encode("utf-8"), sha256).digest()
        return f"{encoded}.{_b64url_encode(signature)}"

    def verify_token(self, token: str) -> dict[str, Any] | None:
        try:
            encoded, raw_signature = token.split(".", 1)
        except ValueError:
            return None
        expected = hmac.new(self._get_api_secret().encode("utf-8"), encoded.encode("utf-8"), sha256).digest()
        try:
            actual = _b64url_decode(raw_signature)
        except Exception:
            return None
        if not hmac.compare_digest(expected, actual):
            return None
        try:
            payload = json.loads(_b64url_decode(encoded).decode("utf-8"))
        except Exception:
            return None
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload

    def authenticate(self, username: str, password: str) -> str | None:
        expected_user = self.store.get_setting("panel_username")
        expected_hash = self.store.get_setting("panel_password_hash")
        if username != expected_user or not verify_panel_password(password, expected_hash):
            return None
        if is_legacy_sha256_hash(expected_hash):
            from .auth import hash_panel_password

            self.store.set_setting("panel_password_hash", hash_panel_password(password))
        return self.issue_token(username)


class PanelAPIHandler(BaseHTTPRequestHandler):
    server_version = "PanelAPI/0.1"

    @property
    def api(self) -> PanelAPI:
        return self.server.api  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        if not raw.strip():
            return {}
        return json.loads(raw.decode("utf-8"))

    def _bearer_token(self) -> str:
        value = self.headers.get("Authorization", "")
        prefix = "Bearer "
        return value[len(prefix) :].strip() if value.startswith(prefix) else ""

    def _require_auth(self) -> dict[str, Any] | None:
        token = self._bearer_token()
        payload = self.api.verify_token(token)
        if payload is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "unauthorized"})
            return None
        return payload

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "panel-api"})
            return

        auth = self._require_auth()
        if auth is None:
            return

        if path == "/api/me":
            self._send_json(HTTPStatus.OK, {"ok": True, "user": {"username": auth["u"]}})
            return
        if path == "/api/domains":
            self._send_json(HTTPStatus.OK, {"ok": True, "items": [dict(row) for row in self.api.store.list_domains()]})
            return
        if path == "/api/dns":
            self._send_json(HTTPStatus.OK, {"ok": True, "items": [dict(row) for row in self.api.store.list_dns()]})
            return
        if path == "/api/apache/modules":
            self._send_json(HTTPStatus.OK, {"ok": True, "items": list_apache_modules()})
            return
        if path == "/api/settings":
            self._send_json(HTTPStatus.OK, {"ok": True, "settings": self.api.get_public_settings()})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/login":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_json"})
            return

        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        token = self.api.authenticate(username, password)
        if not token:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "invalid_credentials"})
            return
        self._send_json(
            HTTPStatus.OK,
            {"ok": True, "token": token, "user": {"username": username}, "expires_in": TOKEN_TTL_SECONDS},
        )

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        auth = self._require_auth()
        if auth is None:
            return
        if path != "/api/settings":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return
        try:
            payload = self._read_json()
            settings = self.api.update_public_settings(payload)
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_json"})
            return
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        self._send_json(HTTPStatus.OK, {"ok": True, "settings": settings})


def run_api(host: str = DEFAULT_API_HOST, port: int = DEFAULT_API_PORT) -> None:
    server = ThreadingHTTPServer((host, port), PanelAPIHandler)
    server.api = PanelAPI()  # type: ignore[attr-defined]
    print(f"Panel API escuchando en http://{host}:{port}")
    server.serve_forever()
