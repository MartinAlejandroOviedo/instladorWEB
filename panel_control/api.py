"""Minimal REST API for panel control."""

from __future__ import annotations

import base64
import hmac
import json
import mimetypes
import secrets
import time
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .core import PanelManager
from .services import (
    apply_ftp,
    apply_mail,
    apply_dns,
    apply_optimization,
    dns_apply_preview,
    ftp_apply_preview,
    import_bind_zones,
    list_apache_confs,
    list_apache_modules,
    list_apache_sites,
    mail_apply_preview,
    optimization_preview,
    send_recovery_secret,
    set_apache_conf,
    set_apache_module,
    set_apache_site,
)
from .storage import PanelStore

DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8088
TOKEN_TTL_SECONDS = 8 * 60 * 60
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def _split_resource_id(path: str, prefix: str) -> tuple[bool, int | None]:
    if path == prefix:
        return True, None
    if not path.startswith(prefix + "/"):
        return False, None
    tail = path[len(prefix) + 1 :]
    if not tail.isdigit():
        return False, None
    return True, int(tail)


class PanelAPI:
    def __init__(self, store: PanelStore | None = None) -> None:
        self.manager = PanelManager(store or PanelStore())
        self.store = self.manager.store

    def _get_api_secret(self) -> str:
        secret = self.store.get_secret_setting("api_secret")
        if secret:
            return secret
        secret = secrets.token_urlsafe(32)
        self.store.set_secret_setting("api_secret", secret)
        return secret

    def issue_token(self, username: str) -> str:
        payload = {
            "u": username,
            "r": self.manager.get_panel_role(),
            "exp": int(time.time()) + TOKEN_TTL_SECONDS,
            "ver": self.manager.get_token_version(username),
            "jti": self.manager.issue_token_id(),
        }
        encoded = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signature = hmac.new(self._get_api_secret().encode("utf-8"), encoded.encode("utf-8"), sha256).digest()
        return f"{encoded}.{_b64url_encode(signature)}"

    def verify_token(self, token: str) -> dict[str, Any] | None:
        self.store.purge_expired_revoked_tokens(int(time.time()))
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
        now_ts = int(time.time())
        if int(payload.get("exp", 0)) < now_ts:
            return None
        username = str(payload.get("u", ""))
        if not username:
            return None
        payload["r"] = self.manager.get_panel_role()
        if int(payload.get("ver", 0)) != self.manager.get_token_version(username):
            return None
        jti = str(payload.get("jti", ""))
        if not jti or self.store.is_token_revoked(jti):
            return None
        return payload

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        auth = self.manager.authenticate_panel(username, password)
        if not auth.get("ok"):
            return None
        return {
            "token": self.issue_token(username),
            "user": {"username": username, "role": auth["role"]},
            "force_password_change": bool(auth.get("force_password_change")),
        }

    def revoke_token(self, payload: dict[str, Any]) -> None:
        self.store.revoke_token(str(payload["jti"]), int(payload["exp"]))

    def revoke_all_tokens(self, username: str) -> int:
        return self.manager.bump_token_version(username)


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

    def _send_bytes(self, status: int, raw: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _serve_static(self, path: str) -> bool:
        if path == "/":
            file_path = STATIC_DIR / "index.html"
        elif path.startswith("/assets/"):
            file_path = STATIC_DIR / path.removeprefix("/assets/")
        else:
            return False
        try:
            resolved = file_path.resolve()
        except FileNotFoundError:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return True
        if STATIC_DIR not in resolved.parents and resolved != STATIC_DIR / "index.html":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return True
        if not resolved.exists() or not resolved.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return True
        content_type, _ = mimetypes.guess_type(str(resolved))
        self._send_bytes(HTTPStatus.OK, resolved.read_bytes(), content_type or "application/octet-stream")
        return True

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

    def _guard_force_password_change(self, path: str) -> bool:
        allowed = {"/api/me", "/api/change-password", "/api/logout", "/api/logout-all"}
        if not self.api.manager.get_force_password_change() or path in allowed:
            return True
        self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "password_change_required"})
        return False

    def _require_permission(self, auth: dict[str, Any], permission: str) -> bool:
        role = str(auth.get("r", ""))
        if self.api.manager.has_permission(role, permission):
            return True
        self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "forbidden", "required": permission})
        return False

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if self._serve_static(path):
            return
        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "panel-api"})
            return

        auth = self._require_auth()
        if auth is None:
            return
        if not self._guard_force_password_change(path):
            return

        if path == "/api/me":
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "user": {
                        "username": auth["u"],
                        "role": auth["r"],
                        "force_password_change": self.api.manager.get_force_password_change(),
                    },
                },
            )
            return
        if path == "/api/domains":
            if not self._require_permission(auth, "domains.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "items": [dict(row) for row in self.api.store.list_domains()]})
            return
        if path == "/api/dns":
            if not self._require_permission(auth, "dns.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "items": [dict(row) for row in self.api.store.list_dns()]})
            return
        if path == "/api/ftp":
            if not self._require_permission(auth, "accounts.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "items": self.api.manager.list_ftp_accounts()})
            return
        if path == "/api/mail":
            if not self._require_permission(auth, "accounts.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "items": self.api.manager.list_mail_accounts()})
            return
        if path == "/api/apache/modules":
            if not self._require_permission(auth, "apache.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "items": list_apache_modules()})
            return
        if path == "/api/apache/sites":
            if not self._require_permission(auth, "apache.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "items": list_apache_sites()})
            return
        if path == "/api/apache/confs":
            if not self._require_permission(auth, "apache.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "items": list_apache_confs()})
            return
        if path == "/api/settings":
            if not self._require_permission(auth, "settings.read"):
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "settings": self.api.manager.get_public_settings()})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_json"})
            return

        if path == "/api/login":
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            result = self.api.authenticate(username, password)
            if not result:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "invalid_credentials"})
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "token": result["token"],
                    "user": result["user"],
                    "force_password_change": result["force_password_change"],
                    "expires_in": TOKEN_TTL_SECONDS,
                },
            )
            return

        if path == "/api/recover/start":
            username = str(payload.get("username", "")).strip()
            whatsapp = str(payload.get("whatsapp", "")).strip()
            if username != self.api.manager.get_panel_username(""):
                self.api.manager.record_recovery_event(username or "(unknown)", "whatsapp", "rejected", "web", "invalid_username")
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_recovery_request"})
                return
            if not self.api.manager.recovery_whatsapp_matches(whatsapp):
                self.api.manager.record_recovery_event(username, "whatsapp", "rejected", "web", "invalid_whatsapp")
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_recovery_request"})
                return
            limit = self.api.manager.recovery_rate_limit_status(username, "whatsapp")
            if not bool(limit["allowed"]):
                self.api.manager.record_recovery_event(username, "whatsapp", "blocked", "web", "rate_limit")
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"ok": False, "error": "recovery_rate_limited", "remaining": limit["remaining"]},
                )
                return
            email, stored_whatsapp = self.api.manager.get_recovery_settings()
            temp_password = self.api.manager.issue_temporary_password(username)
            result = send_recovery_secret(email, stored_whatsapp, temp_password, label="Clave temporal NicePanel")
            if not result.ok:
                self.api.manager.cancel_temporary_password(username)
            self.api.manager.record_recovery_event(
                username,
                "whatsapp",
                "sent" if result.ok else "failed",
                "web",
                self.api.manager.mask_phone(stored_whatsapp),
            )
            status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
            self._send_json(status, {"ok": result.ok, "logs": result.logs, "force_password_change": True})
            return

        auth = self._require_auth()
        if auth is None:
            return
        if not self._guard_force_password_change(path):
            return

        try:
            if path == "/api/change-password":
                new_password = str(payload.get("new_password", ""))
                confirm_password = str(payload.get("confirm_password", ""))
                if len(new_password) < 8:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "password_too_short"})
                    return
                if new_password != confirm_password:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "password_mismatch"})
                    return
                self.api.manager.set_panel_credentials(str(auth["u"]), new_password, role=str(auth["r"]))
                token = self.api.issue_token(str(auth["u"]))
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "token": token,
                        "user": {"username": auth["u"], "role": auth["r"]},
                        "force_password_change": False,
                    },
                )
                return
            if path == "/api/domains":
                if not self._require_permission(auth, "domains.write"):
                    return
                item = self.api.manager.create_domain(payload)
                self._send_json(HTTPStatus.CREATED, {"ok": True, "item": item})
                return
            if path == "/api/dns":
                if not self._require_permission(auth, "dns.write"):
                    return
                item = self.api.manager.create_dns(payload)
                self._send_json(HTTPStatus.CREATED, {"ok": True, "item": item})
                return
            if path == "/api/ftp":
                if not self._require_permission(auth, "accounts.write"):
                    return
                item = self.api.manager.create_ftp_account(payload)
                self._send_json(HTTPStatus.CREATED, {"ok": True, "item": item})
                return
            if path == "/api/mail":
                if not self._require_permission(auth, "accounts.write"):
                    return
                item = self.api.manager.create_mail_account(payload)
                self._send_json(HTTPStatus.CREATED, {"ok": True, "item": item})
                return
            if path == "/api/ops/import-bind":
                if not self._require_permission(auth, "ops.execute"):
                    return
                persist = bool(payload.get("persist", True))
                result = import_bind_zones()
                if not result.ok:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {"ok": False, "error": "import_bind_failed", "logs": result.logs},
                    )
                    return
                if persist:
                    domain_rows = [
                        (
                            str(item.get("domain", "")),
                            str(item.get("ns1_hostname", "")),
                            str(item.get("ns1_ipv4", "")),
                            str(item.get("ns2_hostname", "")),
                            str(item.get("ns2_ipv4", "")),
                        )
                        for item in result.domains
                    ]
                    record_rows = [
                        (
                            str(item.get("zone", "")),
                            str(item.get("name", "")),
                            str(item.get("type", "")),
                            str(item.get("value", "")),
                            int(item.get("ttl", 300)),
                        )
                        for item in result.records
                    ]
                    self.api.store.replace_domains(domain_rows)
                    self.api.store.replace_dns_records(record_rows)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "persisted": persist,
                        "domains": result.domains,
                        "records": result.records,
                        "logs": result.logs,
                    },
                )
                return
            if path == "/api/ops/dns/preview":
                if not self._require_permission(auth, "ops.preview"):
                    return
                self._send_json(HTTPStatus.OK, {"ok": True, "logs": dns_apply_preview()})
                return
            if path == "/api/ops/ftp/preview":
                if not self._require_permission(auth, "ops.preview"):
                    return
                self._send_json(HTTPStatus.OK, {"ok": True, "logs": ftp_apply_preview()})
                return
            if path == "/api/ops/mail/preview":
                if not self._require_permission(auth, "ops.preview"):
                    return
                self._send_json(HTTPStatus.OK, {"ok": True, "logs": mail_apply_preview()})
                return
            if path == "/api/ops/dns/apply":
                if not self._require_permission(auth, "ops.execute"):
                    return
                result = apply_dns(
                    [dict(row) for row in self.api.store.list_dns()],
                    [dict(row) for row in self.api.store.list_domains()],
                    self.api.manager.get_dns_config(),
                )
                status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"ok": result.ok, "logs": result.logs})
                return
            if path == "/api/ops/ftp/apply":
                if not self._require_permission(auth, "ops.execute"):
                    return
                result = apply_ftp([dict(row) for row in self.api.store.list_ftp()])
                status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"ok": result.ok, "logs": result.logs})
                return
            if path == "/api/ops/mail/apply":
                if not self._require_permission(auth, "ops.execute"):
                    return
                result = apply_mail([dict(row) for row in self.api.store.list_mail()])
                status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"ok": result.ok, "logs": result.logs})
                return
            if path == "/api/ops/optimization/preview":
                if not self._require_permission(auth, "ops.preview"):
                    return
                self._send_json(HTTPStatus.OK, {"ok": True, "logs": optimization_preview()})
                return
            if path == "/api/ops/optimization/apply":
                if not self._require_permission(auth, "ops.execute"):
                    return
                result = apply_optimization()
                status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"ok": result.ok, "logs": result.logs})
                return
            if path == "/api/ops/apache/module":
                if not self._require_permission(auth, "apache.write"):
                    return
                module = str(payload.get("name", "")).strip()
                enabled = bool(payload.get("enabled", False))
                if not module:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "missing_module_name"})
                    return
                result = set_apache_module(module, enabled)
                status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"ok": result.ok, "logs": result.logs})
                return
            if path == "/api/ops/apache/site":
                if not self._require_permission(auth, "apache.write"):
                    return
                site = str(payload.get("name", "")).strip()
                enabled = bool(payload.get("enabled", False))
                if not site:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "missing_site_name"})
                    return
                result = set_apache_site(site, enabled)
                status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"ok": result.ok, "logs": result.logs})
                return
            if path == "/api/ops/apache/conf":
                if not self._require_permission(auth, "apache.write"):
                    return
                conf = str(payload.get("name", "")).strip()
                enabled = bool(payload.get("enabled", False))
                if not conf:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "missing_conf_name"})
                    return
                result = set_apache_conf(conf, enabled)
                status = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"ok": result.ok, "logs": result.logs})
                return
            if path == "/api/logout":
                self.api.revoke_token(auth)
                self._send_json(HTTPStatus.OK, {"ok": True})
                return
            if path == "/api/logout-all":
                version = self.api.revoke_all_tokens(str(auth["u"]))
                self._send_json(HTTPStatus.OK, {"ok": True, "token_version": version})
                return
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        auth = self._require_auth()
        if auth is None:
            return
        if not self._guard_force_password_change(path):
            return
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_json"})
            return

        match, item_id = _split_resource_id(path, "/api/domains")
        if match and item_id is not None:
            if not self._require_permission(auth, "domains.write"):
                return
            try:
                item = self.api.manager.update_domain(item_id, payload)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "domain_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "item": item})
            return

        match, item_id = _split_resource_id(path, "/api/dns")
        if match and item_id is not None:
            if not self._require_permission(auth, "dns.write"):
                return
            try:
                item = self.api.manager.update_dns(item_id, payload)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "dns_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "item": item})
            return

        match, item_id = _split_resource_id(path, "/api/ftp")
        if match and item_id is not None:
            if not self._require_permission(auth, "accounts.write"):
                return
            try:
                item = self.api.manager.update_ftp_account(item_id, payload)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "ftp_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "item": item})
            return

        match, item_id = _split_resource_id(path, "/api/mail")
        if match and item_id is not None:
            if not self._require_permission(auth, "accounts.write"):
                return
            try:
                item = self.api.manager.update_mail_account(item_id, payload)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "mail_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "item": item})
            return

        if path != "/api/settings":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return

        if not self._require_permission(auth, "settings.write"):
            return
        try:
            settings = self.api.manager.update_public_settings(payload)
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        self._send_json(HTTPStatus.OK, {"ok": True, "settings": settings})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        auth = self._require_auth()
        if auth is None:
            return
        if not self._guard_force_password_change(path):
            return

        match, item_id = _split_resource_id(path, "/api/domains")
        if match and item_id is not None:
            if not self._require_permission(auth, "domains.write"):
                return
            try:
                self.api.manager.delete_domain(item_id)
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "domain_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        match, item_id = _split_resource_id(path, "/api/dns")
        if match and item_id is not None:
            if not self._require_permission(auth, "dns.write"):
                return
            try:
                self.api.manager.delete_dns(item_id)
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "dns_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        match, item_id = _split_resource_id(path, "/api/ftp")
        if match and item_id is not None:
            if not self._require_permission(auth, "accounts.write"):
                return
            try:
                self.api.manager.delete_ftp_account(item_id)
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "ftp_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        match, item_id = _split_resource_id(path, "/api/mail")
        if match and item_id is not None:
            if not self._require_permission(auth, "accounts.write"):
                return
            try:
                self.api.manager.delete_mail_account(item_id)
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "mail_not_found"})
                return
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})


def run_api(host: str = DEFAULT_API_HOST, port: int = DEFAULT_API_PORT) -> None:
    server = ThreadingHTTPServer((host, port), PanelAPIHandler)
    server.api = PanelAPI()  # type: ignore[attr-defined]
    base_url = f"http://{host}:{port}"
    print(
        "\n".join(
            [
                "    _  ___         ___                __",
                "   / |/ (_)______ / _ \\___ ____  ___ / /",
                "  /    / / __/ -_) ___/ _ `/ _ \\/ -_) /",
                " /_/|_/_/\\__/\\__/_/   \\_,_/_//_/\\__/_/",
                "",
                f"NicePanel API escuchando en {base_url}",
                f"Web UI: {base_url}/",
                f"Health: {base_url}/api/health",
            ]
        )
    )
    server.serve_forever()
