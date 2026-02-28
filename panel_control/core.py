"""Shared business logic for TUI and REST API."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
import secrets

from .auth import hash_panel_password, is_legacy_sha256_hash, verify_panel_password
from .services import DNSConfig
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
        "ops.preview",
        "security.read",
        "web.read",
    },
}


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
        expected_user = self.store.get_secret_setting("panel_username")
        expected_hash = self.store.get_secret_setting("panel_password_hash")
        if username != expected_user or not verify_panel_password(password, expected_hash):
            return False
        if is_legacy_sha256_hash(expected_hash):
            self.store.set_secret_setting("panel_password_hash", self.hash_panel_password(password))
        return True

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
        self.bump_token_version(username)

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

    def get_recovery_settings(self) -> tuple[str, str]:
        return (
            self.store.get_public_setting("recovery_email", ""),
            self.store.get_public_setting("recovery_whatsapp", ""),
        )

    def save_recovery_settings(self, email: str, whatsapp: str) -> None:
        self.store.set_public_setting("recovery_email", email)
        self.store.set_public_setting("recovery_whatsapp", whatsapp)

    def get_public_settings(self) -> dict[str, Any]:
        email, whatsapp = self.get_recovery_settings()
        return {
            "dns": asdict(self.get_dns_config()),
            "recovery_email": email,
            "recovery_whatsapp": whatsapp,
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
        recovery_whatsapp = str(payload.get("recovery_whatsapp", self.store.get_public_setting("recovery_whatsapp", ""))).strip()

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
