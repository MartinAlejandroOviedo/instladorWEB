"""Shared business logic for TUI and REST API."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
import re
import secrets
import time

from .auth import hash_panel_password, is_legacy_sha256_hash, verify_panel_password
from .crypto import decrypt_string, encrypt_string
from .services import DNSConfig, hash_password_for_mailbox, hash_password_for_system
from .storage import PanelStore
from .validators import (
    is_valid_domain,
    is_valid_email,
    is_valid_hostname_label,
    is_valid_ipv4,
    is_valid_ipv4_list,
    is_valid_record_type,
)

ROLE_SUPERADMIN = "superadmin"
ROLE_OPERATOR = "operator"
PANEL_ROLES = {ROLE_SUPERADMIN, ROLE_OPERATOR}

ROLE_PERMISSIONS = {
    ROLE_SUPERADMIN: {
        "accounts.read",
        "accounts.write",
        "domains.read",
        "domains.write",
        "dns.read",
        "dns.write",
        "settings.read",
        "settings.write",
        "apache.read",
        "apache.write",
        "services.read",
        "services.write",
        "ops.preview",
        "ops.execute",
        "security.read",
        "security.write",
        "web.read",
        "web.write",
    },
    ROLE_OPERATOR: {
        "domains.read",
        "domains.write",
        "dns.read",
        "dns.write",
        "settings.read",
        "settings.write",
        "apache.read",
        "services.read",
        "ops.preview",
        "security.read",
        "web.read",
    },
}

RECOVERY_RATE_LIMIT = 5
RECOVERY_RATE_WINDOW_SECONDS = 60 * 60
ACCOUNT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
MAIL_LOCAL_RE = re.compile(r"^[a-z0-9][a-z0-9._%+-]{0,63}$", re.IGNORECASE)


class PanelManager:
    def __init__(self, store: PanelStore | None = None) -> None:
        self.store = store or PanelStore()

    def hash_panel_password(self, password: str) -> str:
        return hash_panel_password(password)

    def has_panel_credentials(self) -> bool:
        return bool(self.store.get_secret_setting("panel_username") and self.store.get_secret_setting("panel_password_hash"))

    def get_panel_username(self, default: str = "admin") -> str:
        return self.store.get_secret_setting("panel_username", default)

    def normalize_role(self, role: str | None) -> str:
        normalized = str(role or "").strip().lower()
        return normalized if normalized in PANEL_ROLES else ROLE_SUPERADMIN

    def get_panel_role(self, default: str = ROLE_SUPERADMIN) -> str:
        return self.normalize_role(self.store.get_secret_setting("panel_role", default))

    def list_panel_roles(self) -> list[str]:
        return sorted(PANEL_ROLES)

    def has_permission(self, role: str, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.normalize_role(role), set())

    def assert_permission(self, role: str, permission: str) -> None:
        if not self.has_permission(role, permission):
            raise PermissionError("forbidden")

    def verify_panel_login(self, username: str, password: str) -> bool:
        return self.authenticate_panel(username, password)["ok"]

    def get_force_password_change(self) -> bool:
        return self.store.get_secret_setting("force_password_change", "0") == "1"

    def _set_force_password_change(self, enabled: bool) -> None:
        self.store.set_secret_setting("force_password_change", "1" if enabled else "0")

    def _clear_temporary_password(self) -> None:
        self.store.set_secret_setting("temporary_password_hash", "")
        self.store.set_secret_setting("temporary_password_expires", "")

    def _temporary_password_active(self) -> bool:
        raw_hash = self.store.get_secret_setting("temporary_password_hash", "")
        raw_exp = self.store.get_secret_setting("temporary_password_expires", "0").strip()
        if not raw_hash:
            return False
        try:
            expires_at = int(raw_exp or "0")
        except ValueError:
            expires_at = 0
        if expires_at <= int(time.time()):
            self._clear_temporary_password()
            self._set_force_password_change(False)
            return False
        return True

    def authenticate_panel(self, username: str, password: str) -> dict[str, Any]:
        expected_user = self.store.get_secret_setting("panel_username")
        expected_hash = self.store.get_secret_setting("panel_password_hash")
        if username != expected_user:
            return {"ok": False}

        if self.get_force_password_change() and self._temporary_password_active():
            temp_hash = self.store.get_secret_setting("temporary_password_hash", "")
            if verify_panel_password(password, temp_hash):
                return {
                    "ok": True,
                    "username": username,
                    "role": self.get_panel_role(),
                    "force_password_change": True,
                    "auth_method": "temporary",
                }
            return {"ok": False}

        if not verify_panel_password(password, expected_hash):
            return {"ok": False}
        if is_legacy_sha256_hash(expected_hash):
            self.store.set_secret_setting("panel_password_hash", self.hash_panel_password(password))
        return {
            "ok": True,
            "username": username,
            "role": self.get_panel_role(),
            "force_password_change": self.get_force_password_change(),
            "auth_method": "permanent",
        }

    def set_panel_role(self, role: str) -> str:
        normalized = self.normalize_role(role)
        self.store.set_secret_setting("panel_role", normalized)
        username = self.get_panel_username("")
        if username:
            self.bump_token_version(username)
        return normalized

    def set_panel_credentials(self, username: str, password: str, role: str | None = None) -> None:
        self.store.set_secret_setting("panel_username", username)
        self.store.set_secret_setting("panel_password_hash", self.hash_panel_password(password))
        self.store.set_secret_setting("panel_role", self.normalize_role(role or self.get_panel_role()))
        self._clear_temporary_password()
        self._set_force_password_change(False)
        self.bump_token_version(username)

    def issue_temporary_password(self, username: str, ttl_seconds: int = 900) -> str:
        if username != self.get_panel_username(""):
            raise ValueError("invalid_username")
        temp_password = f"NP-{secrets.token_urlsafe(9)}"
        self.store.set_secret_setting("temporary_password_hash", self.hash_panel_password(temp_password))
        self.store.set_secret_setting("temporary_password_expires", str(int(time.time()) + ttl_seconds))
        self._set_force_password_change(True)
        self.bump_token_version(username)
        return temp_password

    def cancel_temporary_password(self, username: str) -> None:
        if username != self.get_panel_username(""):
            return
        self._clear_temporary_password()
        self._set_force_password_change(False)

    def get_security_profile(self) -> dict[str, str]:
        recovery_email, recovery_whatsapp = self.get_recovery_settings()
        return {
            "username": self.get_panel_username("admin"),
            "role": self.get_panel_role(),
            "recovery_email": recovery_email,
            "recovery_whatsapp": recovery_whatsapp,
        }

    def get_token_version(self, username: str) -> int:
        raw = self.store.get_secret_setting(f"token_version:{username}", "1").strip()
        try:
            return max(1, int(raw))
        except ValueError:
            return 1

    def bump_token_version(self, username: str) -> int:
        version = self.get_token_version(username) + 1
        self.store.set_secret_setting(f"token_version:{username}", str(version))
        return version

    def issue_token_id(self) -> str:
        return secrets.token_urlsafe(12)

    def get_dns_config(self) -> DNSConfig:
        return DNSConfig(
            ns1_hostname=self.store.get_public_setting("dns_ns1_hostname", "ns1.localdomain"),
            ns1_ipv4=self.store.get_public_setting("dns_ns1_ipv4", "127.0.0.1"),
            ns2_hostname=self.store.get_public_setting("dns_ns2_hostname", ""),
            ns2_ipv4=self.store.get_public_setting("dns_ns2_ipv4", ""),
            listen_on=self.store.get_public_setting("dns_listen_on", "any"),
            forwarders=self.store.get_public_setting("dns_forwarders", "1.1.1.1,8.8.8.8"),
            allow_recursion=self.store.get_public_setting("dns_allow_recursion", "1") == "1",
        )

    def save_dns_config(self, config: DNSConfig) -> None:
        self.store.set_public_setting("dns_ns1_hostname", config.ns1_hostname)
        self.store.set_public_setting("dns_ns1_ipv4", config.ns1_ipv4)
        self.store.set_public_setting("dns_ns2_hostname", config.ns2_hostname)
        self.store.set_public_setting("dns_ns2_ipv4", config.ns2_ipv4)
        self.store.set_public_setting("dns_listen_on", config.listen_on)
        self.store.set_public_setting("dns_forwarders", config.forwarders)
        self.store.set_public_setting("dns_allow_recursion", "1" if config.allow_recursion else "0")

    def normalize_phone(self, phone: str) -> str:
        return "".join(ch for ch in phone if ch.isdigit())

    def mask_phone(self, phone: str) -> str:
        raw = self.normalize_phone(phone)
        if not raw:
            return ""
        if len(raw) <= 2:
            return "*" * len(raw)
        return "*" * max(0, len(raw) - 2) + raw[-2:]

    def _get_recovery_whatsapp_plain(self) -> str:
        encrypted = self.store.get_secret_setting("recovery_whatsapp_encrypted", "")
        if encrypted:
            try:
                return decrypt_string(encrypted)
            except ValueError:
                pass
        legacy = self.store.get_public_setting("recovery_whatsapp", "")
        if legacy:
            self.store.set_secret_setting("recovery_whatsapp_encrypted", encrypt_string(legacy))
            self.store.set_public_setting("recovery_whatsapp", "")
            return legacy
        return ""

    def get_recovery_settings(self) -> tuple[str, str]:
        return (
            self.store.get_public_setting("recovery_email", ""),
            self._get_recovery_whatsapp_plain(),
        )

    def save_recovery_settings(self, email: str, whatsapp: str) -> None:
        self.store.set_public_setting("recovery_email", email)
        normalized = self.normalize_phone(whatsapp)
        if normalized:
            self.store.set_secret_setting("recovery_whatsapp_encrypted", encrypt_string(normalized))
        else:
            self.store.set_secret_setting("recovery_whatsapp_encrypted", "")
        self.store.set_public_setting("recovery_whatsapp", "")

    def recovery_whatsapp_matches(self, candidate: str) -> bool:
        stored = self._get_recovery_whatsapp_plain()
        return bool(stored and self.normalize_phone(candidate) == self.normalize_phone(stored))

    def recovery_rate_limit_status(self, username: str, channel: str = "whatsapp") -> dict[str, int | bool]:
        now_ts = int(time.time())
        since_ts = now_ts - RECOVERY_RATE_WINDOW_SECONDS
        used = self.store.count_recent_recovery_events(username, channel, since_ts)
        remaining = max(0, RECOVERY_RATE_LIMIT - used)
        return {
            "allowed": used < RECOVERY_RATE_LIMIT,
            "used": used,
            "remaining": remaining,
            "window_seconds": RECOVERY_RATE_WINDOW_SECONDS,
        }

    def record_recovery_event(
        self,
        username: str,
        channel: str,
        status: str,
        requester: str = "",
        detail: str = "",
    ) -> None:
        self.store.add_recovery_event(
            actor=username,
            channel=channel,
            status=status,
            requester=requester,
            detail=detail,
            created_at=int(time.time()),
        )

    def get_public_settings(self) -> dict[str, Any]:
        email, whatsapp = self.get_recovery_settings()
        return {
            "dns": asdict(self.get_dns_config()),
            "recovery_email": email,
            "recovery_whatsapp": whatsapp,
            "recovery_whatsapp_masked": self.mask_phone(whatsapp),
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
        recovery_email = str(payload.get("recovery_email", self.store.get_public_setting("recovery_email", ""))).strip().lower()
        recovery_whatsapp = str(payload.get("recovery_whatsapp", self._get_recovery_whatsapp_plain())).strip()

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

        self.save_dns_config(
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
        self.save_recovery_settings(recovery_email, recovery_whatsapp)
        return self.get_public_settings()

    def validate_domain_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        domain = str(payload.get("domain", "")).strip().lower()
        ns1_hostname = str(payload.get("ns1_hostname", "")).strip().lower().rstrip(".")
        ns1_ipv4 = str(payload.get("ns1_ipv4", "")).strip()
        ns2_hostname = str(payload.get("ns2_hostname", "")).strip().lower().rstrip(".")
        ns2_ipv4 = str(payload.get("ns2_ipv4", "")).strip()
        if not is_valid_domain(domain):
            raise ValueError("domain invalido")
        if ns1_hostname and not is_valid_domain(ns1_hostname):
            raise ValueError("ns1_hostname invalido")
        if ns1_ipv4 and not is_valid_ipv4(ns1_ipv4):
            raise ValueError("ns1_ipv4 invalido")
        if ns2_hostname and not is_valid_domain(ns2_hostname):
            raise ValueError("ns2_hostname invalido")
        if ns2_ipv4 and not is_valid_ipv4(ns2_ipv4):
            raise ValueError("ns2_ipv4 invalido")
        if ns2_hostname and not ns2_ipv4:
            raise ValueError("falta ns2_ipv4")
        if ns2_ipv4 and not ns2_hostname:
            raise ValueError("falta ns2_hostname")
        return {
            "domain": domain,
            "ns1_hostname": ns1_hostname,
            "ns1_ipv4": ns1_ipv4,
            "ns2_hostname": ns2_hostname,
            "ns2_ipv4": ns2_ipv4,
        }

    def create_domain(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_domain_payload(payload)
        self.store.upsert_domain(**normalized)
        row = self.store.get_domain_by_name(normalized["domain"])
        return dict(row) if row else normalized

    def update_domain(self, item_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_domain_payload(payload)
        updated = self.store.update_domain_dns(
            item_id,
            normalized["domain"],
            normalized["ns1_hostname"],
            normalized["ns1_ipv4"],
            normalized["ns2_hostname"],
            normalized["ns2_ipv4"],
        )
        if not updated:
            raise KeyError("domain_not_found")
        row = self.store.get_domain(item_id)
        return dict(row) if row else normalized

    def delete_domain(self, item_id: int) -> None:
        if not self.store.delete_domain(item_id):
            raise KeyError("domain_not_found")

    def validate_dns_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        zone = str(payload.get("zone", "")).strip().lower()
        name = str(payload.get("name", "")).strip()
        rtype = str(payload.get("type", "")).strip().upper()
        value = str(payload.get("value", "")).strip()
        ttl_raw = payload.get("ttl", 300)
        if not is_valid_domain(zone):
            raise ValueError("zone invalida")
        if not is_valid_hostname_label(name):
            raise ValueError("name invalido")
        if not is_valid_record_type(rtype):
            raise ValueError("type invalido")
        if not value:
            raise ValueError("value obligatorio")
        try:
            ttl = int(ttl_raw)
        except (TypeError, ValueError):
            raise ValueError("ttl invalido") from None
        if ttl < 60:
            raise ValueError("ttl invalido")
        return {"zone": zone, "name": name, "type": rtype, "value": value, "ttl": ttl}

    def create_dns(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_dns_payload(payload)
        self.store.add_dns(
            normalized["zone"],
            normalized["name"],
            normalized["type"],
            normalized["value"],
            normalized["ttl"],
        )
        rows = self.store.list_dns()
        for row in reversed(rows):
            if (
                row["zone"] == normalized["zone"]
                and row["name"] == normalized["name"]
                and row["type"] == normalized["type"]
                and row["value"] == normalized["value"]
                and row["ttl"] == normalized["ttl"]
            ):
                return dict(row)
        return normalized

    def update_dns(self, item_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_dns_payload(payload)
        updated = self.store.update_dns(
            item_id,
            normalized["zone"],
            normalized["name"],
            normalized["type"],
            normalized["value"],
            normalized["ttl"],
        )
        if not updated:
            raise KeyError("dns_not_found")
        row = self.store.get_dns(item_id)
        return dict(row) if row else normalized

    def delete_dns(self, item_id: int) -> None:
        if not self.store.delete_dns(item_id):
            raise KeyError("dns_not_found")

    def sanitize_ftp_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "domain": str(row["domain"]),
            "home_dir": str(row["home_dir"]),
            "enabled": bool(row["enabled"]),
        }

    def sanitize_mail_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "address": str(row["address"]),
            "local_part": str(row["local_part"]),
            "domain": str(row["domain"]),
            "enabled": bool(row["enabled"]),
        }

    def list_ftp_accounts(self) -> list[dict[str, Any]]:
        return [self.sanitize_ftp_row(row) for row in self.store.list_ftp()]

    def list_mail_accounts(self) -> list[dict[str, Any]]:
        return [self.sanitize_mail_row(row) for row in self.store.list_mail()]

    def _domain_must_exist(self, domain: str) -> None:
        if not self.store.get_domain_by_name(domain):
            raise ValueError("domain_not_found")

    def _hash_mail_password(self, password: str) -> str:
        return hash_password_for_mailbox(password)

    def validate_ftp_payload(self, payload: dict[str, Any], *, require_password: bool) -> dict[str, str]:
        username = str(payload.get("username", "")).strip().lower()
        domain = str(payload.get("domain", "")).strip().lower()
        home_dir = str(payload.get("home_dir", "")).strip()
        password = str(payload.get("password", ""))
        if not ACCOUNT_NAME_RE.match(username):
            raise ValueError("ftp_username_invalido")
        if not is_valid_domain(domain):
            raise ValueError("ftp_domain_invalido")
        self._domain_must_exist(domain)
        if not home_dir:
            home_dir = f"/var/www/{domain}/{username}"
        if require_password and len(password) < 8:
            raise ValueError("ftp_password_too_short")
        password_hash = ""
        if password:
            password_hash = hash_password_for_system(password)
        elif require_password:
            raise ValueError("ftp_password_too_short")
        return {
            "username": username,
            "domain": domain,
            "home_dir": home_dir,
            "password_hash": password_hash,
        }

    def create_ftp_account(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_ftp_payload(payload, require_password=True)
        self.store.add_ftp(
            normalized["username"],
            normalized["domain"],
            normalized["home_dir"],
            normalized["password_hash"],
        )
        row = self.store.get_ftp_by_username(normalized["username"])
        return self.sanitize_ftp_row(row) if row else normalized

    def update_ftp_account(self, item_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        current = self.store.get_ftp(item_id)
        if not current:
            raise KeyError("ftp_not_found")
        merged = {
            "username": payload.get("username", current["username"]),
            "domain": payload.get("domain", current["domain"]),
            "home_dir": payload.get("home_dir", current["home_dir"]),
            "password": payload.get("password", ""),
        }
        normalized = self.validate_ftp_payload(merged, require_password=False)
        updated = self.store.update_ftp(
            item_id,
            normalized["username"],
            normalized["domain"],
            normalized["home_dir"],
            normalized["password_hash"] or None,
        )
        if not updated:
            raise KeyError("ftp_not_found")
        row = self.store.get_ftp(item_id)
        return self.sanitize_ftp_row(row) if row else normalized

    def delete_ftp_account(self, item_id: int) -> None:
        if not self.store.delete_ftp(item_id):
            raise KeyError("ftp_not_found")

    def validate_mail_payload(self, payload: dict[str, Any], *, require_password: bool) -> dict[str, str]:
        local_part = str(payload.get("local_part", "")).strip()
        domain = str(payload.get("domain", "")).strip().lower()
        password = str(payload.get("password", ""))
        if not MAIL_LOCAL_RE.match(local_part):
            raise ValueError("mail_local_part_invalido")
        if not is_valid_domain(domain):
            raise ValueError("mail_domain_invalido")
        self._domain_must_exist(domain)
        address = f"{local_part}@{domain}".lower()
        if not is_valid_email(address):
            raise ValueError("mail_address_invalida")
        if require_password and len(password) < 8:
            raise ValueError("mail_password_too_short")
        password_hash = self._hash_mail_password(password) if password else ""
        return {
            "local_part": local_part,
            "domain": domain,
            "address": address,
            "password_hash": password_hash,
        }

    def create_mail_account(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_mail_payload(payload, require_password=True)
        self.store.add_mail(
            normalized["local_part"],
            normalized["domain"],
            normalized["address"],
            normalized["password_hash"],
        )
        row = self.store.get_mail_by_address(normalized["address"])
        return self.sanitize_mail_row(row) if row else normalized

    def update_mail_account(self, item_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        current = self.store.get_mail(item_id)
        if not current:
            raise KeyError("mail_not_found")
        merged = {
            "local_part": payload.get("local_part", current["local_part"] or current["address"].split("@", 1)[0]),
            "domain": payload.get("domain", current["domain"] or current["address"].split("@", 1)[-1]),
            "password": payload.get("password", ""),
        }
        normalized = self.validate_mail_payload(merged, require_password=False)
        updated = self.store.update_mail(
            item_id,
            normalized["local_part"],
            normalized["domain"],
            normalized["address"],
            normalized["password_hash"] or None,
        )
        if not updated:
            raise KeyError("mail_not_found")
        row = self.store.get_mail(item_id)
        return self.sanitize_mail_row(row) if row else normalized

    def delete_mail_account(self, item_id: int) -> None:
        if not self.store.delete_mail(item_id):
            raise KeyError("mail_not_found")
