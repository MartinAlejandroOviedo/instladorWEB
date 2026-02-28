"""Service integration layer for real provisioning tasks."""

from __future__ import annotations

import base64
import os
import re
import shlex
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import List


@dataclass
class ApplyResult:
    ok: bool
    logs: List[str]


@dataclass
class DNSConfig:
    ns1_hostname: str = "ns1.localdomain"
    ns1_ipv4: str = "127.0.0.1"
    ns2_hostname: str = ""
    ns2_ipv4: str = ""
    listen_on: str = "any"
    forwarders: str = "1.1.1.1,8.8.8.8"
    allow_recursion: bool = True


@dataclass
class WebUpdateConfig:
    repo_url: str
    branch: str = "main"
    project_dir: str = "/var/www/carthtml"
    service_name: str = "carthtml"
    backup_dir: str = "/var/backups/carthtml"
    temp_dir: str = "/tmp/carthtml-update"


@dataclass
class WebUpdateResult:
    ok: bool
    logs: List[str]
    downloaded: bool = False
    commit: str = ""


@dataclass
class APIProxyConfig:
    server_name: str
    project_dir: str
    api_host: str = "127.0.0.1"
    api_port: int = 8088
    public_path: str = "/api/"
    auth_user: str = "nicepanel"
    auth_password: str = ""
    service_name: str = "nicepanel-api"
    site_name: str = "nicepanel-api"


@dataclass
class DNSImportResult:
    ok: bool
    logs: List[str]
    domains: List[dict]
    records: List[dict]


@dataclass
class RecoveryResult:
    ok: bool
    logs: List[str]
    code: str = ""


@dataclass
class OptimizationResult:
    ok: bool
    logs: List[str]


APACHE_COMMON_MODULES = [
    ("rewrite", "URLs amigables y redirecciones"),
    ("ssl", "HTTPS en Apache"),
    ("headers", "headers HTTP y cache"),
    ("expires", "expiracion de estaticos"),
    ("deflate", "compresion gzip/deflate"),
    ("http2", "HTTP/2"),
    ("proxy", "reverse proxy base"),
    ("proxy_http", "reverse proxy HTTP"),
]

WHATSAPP_PROVIDER_ENV = "NICEPANEL_WHATSAPP_PROVIDER"
TWILIO_ACCOUNT_SID_ENV = "NICEPANEL_TWILIO_ACCOUNT_SID"
TWILIO_AUTH_TOKEN_ENV = "NICEPANEL_TWILIO_AUTH_TOKEN"
TWILIO_FROM_ENV = "NICEPANEL_TWILIO_WHATSAPP_FROM"
TWILIO_CONTENT_SID_ENV = "NICEPANEL_TWILIO_CONTENT_SID"


def _run(raw: List[str]) -> tuple[int, str, str]:
    cmd = raw if os.geteuid() == 0 else ["sudo", "-n"] + raw
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _command_exists(binary: str) -> bool:
    proc = subprocess.run(["bash", "-lc", f"command -v {binary} >/dev/null 2>&1"], check=False)
    return proc.returncode == 0


def _normalize_whatsapp_target(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    return f"whatsapp:+{digits}" if digits else ""


def _send_whatsapp_via_twilio(phone: str, body: str) -> tuple[bool, str]:
    account_sid = os.environ.get(TWILIO_ACCOUNT_SID_ENV, "").strip()
    auth_token = os.environ.get(TWILIO_AUTH_TOKEN_ENV, "").strip()
    from_number = os.environ.get(TWILIO_FROM_ENV, "").strip()
    if not account_sid or not auth_token or not from_number:
        return False, "Twilio no configurado"

    payload = {
        "To": _normalize_whatsapp_target(phone),
        "From": from_number if from_number.startswith("whatsapp:") else f"whatsapp:{from_number}",
    }
    content_sid = os.environ.get(TWILIO_CONTENT_SID_ENV, "").strip()
    if content_sid:
        payload["ContentSid"] = content_sid
        payload["ContentVariables"] = json_escape({"1": body})
    else:
        payload["Body"] = body

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    request = urllib.request.Request(url, data=encoded, method="POST")
    auth_bytes = f"{account_sid}:{auth_token}".encode("utf-8")
    request.add_header("Authorization", "Basic " + base64.b64encode(auth_bytes).decode("ascii"))
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if 200 <= response.status < 300:
                return True, "Twilio WhatsApp enviado"
            return False, f"Twilio status inesperado: {response.status}"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore").strip()
        return False, f"Twilio HTTP {exc.code}: {detail or exc.reason}"
    except urllib.error.URLError as exc:
        return False, f"Twilio network error: {exc.reason}"


def json_escape(payload: dict[str, str]) -> str:
    import json

    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def send_whatsapp_message(phone: str, body: str) -> tuple[bool, str]:
    provider = os.environ.get(WHATSAPP_PROVIDER_ENV, "").strip().lower()
    if provider == "twilio":
        return _send_whatsapp_via_twilio(phone, body)
    return False, "WhatsApp provider no configurado"


def hash_password_for_system(password: str) -> str:
    proc = subprocess.run(
        ["openssl", "passwd", "-6", password],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "No se pudo generar hash de password con openssl.")
    return proc.stdout.strip()


def hash_password_for_mailbox(password: str) -> str:
    try:
        proc = subprocess.run(
            ["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password],
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except FileNotFoundError:
        pass
    crypt_hash = hash_password_for_system(password)
    return f"{{CRYPT}}{crypt_hash}"


def _build_named_block(zones: List[str]) -> str:
    lines = ["# BEGIN PANELCTL MANAGED ZONES"]
    for zone in zones:
        lines.append(f'zone "{zone}" {{ type master; file "/etc/bind/panel-zones/db.{zone}"; }};')
    lines.append("# END PANELCTL MANAGED ZONES")
    return "\n".join(lines) + "\n"


def _strip_zone_comments(line: str) -> str:
    return line.split(";", 1)[0].strip()


def _normalize_zone_name(name: str, zone: str) -> str:
    raw = name.strip().rstrip(".")
    if raw in {"@", zone}:
        return "@"
    suffix = f".{zone}"
    if raw.endswith(suffix):
        label = raw[: -len(suffix)].rstrip(".")
        return label or "@"
    return raw


def _extract_ns_config(zone: str, records: List[dict]) -> dict[str, str]:
    apex_ns = [record["value"].rstrip(".") for record in records if record["type"] == "NS" and record["name"] == "@"]
    a_map = {
        record["name"]: record["value"]
        for record in records
        if record["type"] == "A"
    }
    ns1 = apex_ns[0] if apex_ns else ""
    ns2 = apex_ns[1] if len(apex_ns) > 1 else ""
    ns1_label = _normalize_zone_name(ns1, zone) if ns1 else ""
    ns2_label = _normalize_zone_name(ns2, zone) if ns2 else ""
    return {
        "ns1_hostname": ns1,
        "ns1_ipv4": a_map.get(ns1_label, ""),
        "ns2_hostname": ns2,
        "ns2_ipv4": a_map.get(ns2_label, ""),
    }


def _effective_zone_config(zone: str, base_config: DNSConfig, domain_config: dict[str, str] | None) -> DNSConfig:
    if not domain_config:
        return base_config
    return DNSConfig(
        ns1_hostname=domain_config.get("ns1_hostname") or base_config.ns1_hostname,
        ns1_ipv4=domain_config.get("ns1_ipv4") or base_config.ns1_ipv4,
        ns2_hostname=domain_config.get("ns2_hostname") or base_config.ns2_hostname,
        ns2_ipv4=domain_config.get("ns2_ipv4") or base_config.ns2_ipv4,
        listen_on=base_config.listen_on,
        forwarders=base_config.forwarders,
        allow_recursion=base_config.allow_recursion,
    )


def import_bind_zones() -> DNSImportResult:
    logs: List[str] = []
    named_local = "/etc/bind/named.conf.local"
    if not os.path.exists(named_local):
        return DNSImportResult(False, [f"[DNS] no existe {named_local}"], [], [])

    zone_defs: list[tuple[str, str]] = []
    zone_re = re.compile(r'zone\s+"([^"]+)"\s*\{[^}]*file\s+"([^"]+)"', re.IGNORECASE)
    try:
        with open(named_local, "r", encoding="utf-8") as handle:
            for line in handle:
                match = zone_re.search(line)
                if match:
                    zone_defs.append((match.group(1).strip().lower(), match.group(2).strip()))
    except OSError as exc:
        return DNSImportResult(False, [f"[DNS] no se pudo leer {named_local}: {exc}"], [], [])

    if not zone_defs:
        return DNSImportResult(False, ["[DNS] no se encontraron zonas en named.conf.local"], [], [])

    domains: List[dict] = []
    records: List[dict] = []
    for zone, path in zone_defs:
        if not os.path.exists(path):
            logs.append(f"[DNS] zona omitida sin archivo: {zone} -> {path}")
            continue

        zone_records: List[dict] = []
        current_ttl = 300
        in_soa = False
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = _strip_zone_comments(raw_line)
                    if not line:
                        continue
                    if line.startswith("$TTL"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            current_ttl = int(parts[1])
                        continue
                    if " SOA " in f" {line} ":
                        in_soa = "(" in line and ")" not in line
                        continue
                    if in_soa:
                        if ")" in line:
                            in_soa = False
                        continue

                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    idx = 0
                    name = parts[idx]
                    idx += 1
                    ttl = current_ttl
                    if idx < len(parts) and parts[idx].isdigit():
                        ttl = int(parts[idx])
                        idx += 1
                    if idx < len(parts) and parts[idx].upper() == "IN":
                        idx += 1
                    if idx >= len(parts):
                        continue
                    rtype = parts[idx].upper()
                    idx += 1
                    if idx >= len(parts):
                        continue
                    value = " ".join(parts[idx:]).strip()
                    if rtype not in {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}:
                        continue
                    if rtype == "TXT":
                        value = value.strip()
                    normalized_name = _normalize_zone_name(name, zone)
                    zone_records.append(
                        {
                            "zone": zone,
                            "name": normalized_name,
                            "type": rtype,
                            "value": value,
                            "ttl": ttl,
                        }
                    )
        except OSError as exc:
            logs.append(f"[DNS] no se pudo leer {path}: {exc}")
            continue

        records.extend(zone_records)
        domain = {"domain": zone}
        domain.update(_extract_ns_config(zone, zone_records))
        domains.append(domain)
        logs.append(f"[DNS] zona importada: {zone} ({len(zone_records)} records)")

    if not domains:
        return DNSImportResult(False, logs or ["[DNS] no se pudieron importar zonas"], [], [])
    return DNSImportResult(True, logs, domains, records)


def send_recovery_code(email: str, whatsapp: str) -> RecoveryResult:
    code = str(int(time.time()))[-6:]
    return send_recovery_secret(email, whatsapp, code, label="Codigo de recuperacion")


def send_recovery_secret(email: str, whatsapp: str, secret: str, label: str = "Codigo de recuperacion") -> RecoveryResult:
    logs: List[str] = []
    if email.strip():
        if _command_exists("mail"):
            subject = "Recuperacion acceso panel"
            body = f"{label}: {secret}"
            cmd = f"printf '%s\n' {shlex.quote(body)} | mail -s {shlex.quote(subject)} {shlex.quote(email)}"
            rc, _, err = _run(["bash", "-lc", cmd])
            if rc == 0:
                logs.append(f"[RECOVERY] email enviado a {email}")
            else:
                logs.append(f"[RECOVERY] no se pudo enviar email a {email}: {err}")
        else:
            logs.append("[RECOVERY] comando 'mail' no disponible para enviar email")
    if whatsapp.strip():
        ok, detail = send_whatsapp_message(whatsapp, f"{label}: {secret}")
        if ok:
            logs.append(f"[RECOVERY] WhatsApp enviado a {whatsapp}")
        else:
            logs.append(f"[RECOVERY] no se pudo enviar WhatsApp a {whatsapp}: {detail}")
    if not email.strip() and not whatsapp.strip():
        logs.append("[RECOVERY] sin email ni WhatsApp configurados")
        return RecoveryResult(False, logs)
    success = any("enviado" in line for line in logs)
    return RecoveryResult(success, logs, code=secret)


def api_proxy_preview() -> List[str]:
    return [
        "crear /etc/systemd/system/nicepanel-api.service",
        "crear /etc/panelctl/api.htpasswd",
        "crear /etc/apache2/sites-available/nicepanel-api.conf",
        "a2enmod proxy proxy_http headers auth_basic authn_file",
        "a2ensite nicepanel-api.conf",
        "systemctl enable --now nicepanel-api",
        "apache2ctl configtest",
        "systemctl reload apache2",
    ]


def setup_api_proxy(config: APIProxyConfig) -> OptimizationResult:
    logs: List[str] = []
    if not config.server_name.strip():
        return OptimizationResult(False, ["[API] falta server_name"])
    if not config.auth_password.strip():
        return OptimizationResult(False, ["[API] falta auth_password"])

    service_path = f"/etc/systemd/system/{config.service_name}.service"
    site_path = f"/etc/apache2/sites-available/{config.site_name}.conf"
    auth_path = "/etc/panelctl/api.htpasswd"
    launcher_path = os.path.join(config.project_dir, "panel_control_api.py")
    public_path = config.public_path if config.public_path.endswith("/") else config.public_path + "/"
    public_path_root = public_path[:-1]

    if not os.path.exists(launcher_path):
        return OptimizationResult(False, [f"[API] no existe launcher API: {launcher_path}"])

    service_body = f"""
[Unit]
Description=NicePanel API
After=network.target

[Service]
Type=simple
WorkingDirectory={config.project_dir}
ExecStart=/usr/bin/python3 {launcher_path}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""".strip()
    rc, _, err = _run(["bash", "-lc", f"cat > {shlex.quote(service_path)} <<'EOF'\n{service_body}\nEOF"])
    if rc != 0:
        return OptimizationResult(False, [f"[API] no se pudo escribir {service_path}: {err}"])
    logs.append(f"[API] service escrita: {service_path}")

    rc, _, err = _run(["mkdir", "-p", "/etc/panelctl"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo crear /etc/panelctl: {err}"])

    htpasswd_hash = subprocess.run(
        ["openssl", "passwd", "-apr1", config.auth_password],
        text=True,
        capture_output=True,
        check=False,
    )
    if htpasswd_hash.returncode != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo generar hash htpasswd: {htpasswd_hash.stderr.strip()}"])
    auth_body = f"{config.auth_user}:{htpasswd_hash.stdout.strip()}\n"
    rc, _, err = _run(["bash", "-lc", f"cat > {shlex.quote(auth_path)} <<'EOF'\n{auth_body}EOF"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo escribir {auth_path}: {err}"])
    logs.append(f"[API] auth file escrita: {auth_path}")

    site_body = f"""
<VirtualHost *:80>
    ServerName {config.server_name}

    ProxyPreserveHost On
    ProxyRequests Off

    <Location />
        AuthType Basic
        AuthName "NicePanel"
        AuthUserFile {auth_path}
        Require valid-user
    </Location>

    ProxyPass / http://{config.api_host}:{config.api_port}/
    ProxyPassReverse / http://{config.api_host}:{config.api_port}/

    ProxyPass {public_path} http://{config.api_host}:{config.api_port}/api/
    ProxyPassReverse {public_path} http://{config.api_host}:{config.api_port}/api/

    ErrorLog ${{APACHE_LOG_DIR}}/{config.site_name}_error.log
    CustomLog ${{APACHE_LOG_DIR}}/{config.site_name}_access.log combined
</VirtualHost>
""".strip()
    rc, _, err = _run(["bash", "-lc", f"cat > {shlex.quote(site_path)} <<'EOF'\n{site_body}\nEOF"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo escribir {site_path}: {err}"])
    logs.append(f"[API] site escrita: {site_path}")

    rc, _, err = _run(["bash", "-lc", "a2enmod proxy proxy_http headers auth_basic authn_file"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudieron habilitar modulos Apache: {err}"])
    logs.append("[API] modulos Apache habilitados para reverse proxy")

    rc, _, err = _run(["a2ensite", f"{config.site_name}.conf"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo habilitar sitio Apache: {err}"])
    logs.append(f"[API] sitio Apache habilitado: {config.site_name}.conf")

    rc, _, err = _run(["systemctl", "daemon-reload"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo hacer daemon-reload: {err}"])
    rc, _, err = _run(["systemctl", "enable", "--now", config.service_name])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo habilitar/iniciar servicio {config.service_name}: {err}"])
    logs.append(f"[API] servicio habilitado: {config.service_name}")

    rc, out, err = _run(["apache2ctl", "configtest"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] apache2ctl configtest fallo: {err or out}"])
    logs.append("[API] apache2ctl configtest OK")

    rc, _, err = _run(["systemctl", "reload", "apache2"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[API] no se pudo recargar apache2: {err}"])
    logs.append("[API] apache2 recargado")
    logs.append(f"[API] Web UI activa en http://{config.server_name}/")
    logs.append(f"[API] API publica activa en http://{config.server_name}{public_path}")
    return OptimizationResult(True, logs)


def optimization_preview() -> List[str]:
    return [
        "a2enmod deflate expires headers http2",
        "escribir /etc/apache2/conf-available/panelctl-optimization.conf",
        "a2enconf panelctl-optimization",
        "apache2ctl configtest",
        "systemctl reload apache2",
        "nota: balanceo/hilos/colas no se aplican en un VPS unico sin arquitectura multi-nodo",
    ]


def list_apache_modules() -> List[dict[str, str | bool]]:
    items: List[dict[str, str | bool]] = []
    for module, description in APACHE_COMMON_MODULES:
        enabled = os.path.exists(f"/etc/apache2/mods-enabled/{module}.load") or os.path.exists(
            f"/etc/apache2/mods-enabled/{module}.conf"
        )
        items.append(
            {
                "module": module,
                "description": description,
                "enabled": enabled,
            }
        )
    return items


def _list_apache_entries(kind: str) -> List[dict[str, str | bool]]:
    available_dir = f"/etc/apache2/{kind}-available"
    enabled_dir = f"/etc/apache2/{kind}-enabled"
    if not os.path.isdir(available_dir):
        return []

    items: List[dict[str, str | bool]] = []
    for entry in sorted(os.listdir(available_dir)):
        if not entry.endswith(".conf"):
            continue
        enabled = os.path.exists(os.path.join(enabled_dir, entry))
        items.append(
            {
                "name": entry,
                "enabled": enabled,
            }
        )
    return items


def list_apache_sites() -> List[dict[str, str | bool]]:
    return _list_apache_entries("sites")


def list_apache_confs() -> List[dict[str, str | bool]]:
    return _list_apache_entries("conf")


def _normalize_apache_entry(name: str) -> str:
    return name if name.endswith(".conf") else f"{name}.conf"


def set_apache_site(name: str, enabled: bool) -> OptimizationResult:
    target = _normalize_apache_entry(name)
    command = ["a2ensite", target] if enabled else ["a2dissite", "-f", target]
    rc, out, err = _run(command)
    if rc != 0:
        action = "habilitar" if enabled else "deshabilitar"
        return OptimizationResult(False, [f"[SITE] no se pudo {action} {target}: {err or out}"])
    logs = [f"[SITE] sitio {'habilitado' if enabled else 'deshabilitado'}: {target}"]
    rc, out, err = _run(["apache2ctl", "configtest"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[SITE] configtest fallo tras cambiar {target}: {err or out}"])
    logs.append("[SITE] apache2ctl configtest OK")
    rc, _, err = _run(["systemctl", "reload", "apache2"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[SITE] no se pudo recargar apache2: {err}"])
    logs.append("[SITE] apache2 recargado")
    return OptimizationResult(True, logs)


def set_apache_conf(name: str, enabled: bool) -> OptimizationResult:
    target = _normalize_apache_entry(name)
    command = ["a2enconf", target] if enabled else ["a2disconf", "-f", target]
    rc, out, err = _run(command)
    if rc != 0:
        action = "habilitar" if enabled else "deshabilitar"
        return OptimizationResult(False, [f"[CONF] no se pudo {action} {target}: {err or out}"])
    logs = [f"[CONF] conf {'habilitada' if enabled else 'deshabilitada'}: {target}"]
    rc, out, err = _run(["apache2ctl", "configtest"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[CONF] configtest fallo tras cambiar {target}: {err or out}"])
    logs.append("[CONF] apache2ctl configtest OK")
    rc, _, err = _run(["systemctl", "reload", "apache2"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[CONF] no se pudo recargar apache2: {err}"])
    logs.append("[CONF] apache2 recargado")
    return OptimizationResult(True, logs)


def recommend_apache_profile() -> List[str]:
    recommendations: List[str] = []
    enabled_modules = {item["module"] for item in list_apache_modules() if item["enabled"]}
    enabled_sites = [item["name"] for item in list_apache_sites() if item["enabled"]]

    if enabled_sites:
        recommendations.append("Base recomendada: headers, rewrite, deflate, expires")
    if os.path.isdir("/etc/letsencrypt/live") and os.listdir("/etc/letsencrypt/live"):
        recommendations.append("HTTPS detectado: conviene ssl + http2")

    proxy_detected = False
    for site in enabled_sites:
        path = os.path.join("/etc/apache2/sites-available", site)
        try:
            text = open(path, "r", encoding="utf-8").read()
        except OSError:
            continue
        if "ProxyPass" in text or "ProxyPassReverse" in text:
            proxy_detected = True
            break
    if proxy_detected:
        recommendations.append("Reverse proxy detectado: conviene proxy + proxy_http + headers")

    node_detected = False
    if os.path.isdir("/var/www"):
        for entry in os.listdir("/var/www"):
            base = os.path.join("/var/www", entry)
            if os.path.exists(os.path.join(base, "server.js")) or os.path.exists(os.path.join(base, "package.json")):
                node_detected = True
                break
    if node_detected:
        recommendations.append("App Node detectada: revisar proxy, proxy_http, rewrite y headers")

    if "http2" not in enabled_modules and "ssl" in enabled_modules:
        recommendations.append("Tenes ssl activo sin http2: vale la pena habilitar http2")
    if "deflate" not in enabled_modules:
        recommendations.append("Falta deflate: recomendado para reducir trafico")
    if "expires" not in enabled_modules:
        recommendations.append("Falta expires: recomendado para cache de estaticos")

    return recommendations or ["Sin recomendaciones nuevas. Configuracion actual razonable."]


def set_apache_module(module: str, enabled: bool) -> OptimizationResult:
    allowed = {name for name, _ in APACHE_COMMON_MODULES}
    if module not in allowed:
        return OptimizationResult(False, [f"[APACHE] modulo no permitido: {module}"])

    command = ["a2enmod", module] if enabled else ["a2dismod", "-f", module]
    rc, out, err = _run(command)
    if rc != 0:
        action = "habilitar" if enabled else "deshabilitar"
        return OptimizationResult(False, [f"[APACHE] no se pudo {action} {module}: {err or out}"])

    logs = [f"[APACHE] modulo {'habilitado' if enabled else 'deshabilitado'}: {module}"]
    rc, out, err = _run(["apache2ctl", "configtest"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[APACHE] configtest fallo tras cambiar {module}: {err or out}"])
    logs.append("[APACHE] apache2ctl configtest OK")

    rc, _, err = _run(["systemctl", "reload", "apache2"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[APACHE] no se pudo recargar apache2: {err}"])
    logs.append("[APACHE] apache2 recargado")
    return OptimizationResult(True, logs)


def apply_optimization() -> OptimizationResult:
    logs: List[str] = []
    rc, _, err = _run(["bash", "-lc", "a2enmod deflate expires headers http2"])
    if rc != 0:
        return OptimizationResult(False, [f"[OPT] no se pudieron habilitar modulos Apache: {err}"])
    logs.append("[OPT] modulos Apache habilitados: deflate expires headers http2")

    config_path = "/etc/apache2/conf-available/panelctl-optimization.conf"
    config_body = """
KeepAlive On
MaxKeepAliveRequests 200
KeepAliveTimeout 2

<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain text/html text/css text/javascript application/javascript application/json application/xml image/svg+xml
</IfModule>

<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css "access plus 7 days"
    ExpiresByType application/javascript "access plus 7 days"
    ExpiresByType image/jpeg "access plus 30 days"
    ExpiresByType image/png "access plus 30 days"
    ExpiresByType image/webp "access plus 30 days"
    ExpiresByType image/svg+xml "access plus 30 days"
    ExpiresByType font/woff2 "access plus 30 days"
</IfModule>

<IfModule mod_headers.c>
    <FilesMatch "\\.(css|js|jpg|jpeg|png|webp|svg|woff2)$">
        Header set Cache-Control "public, max-age=604800, immutable"
    </FilesMatch>
</IfModule>
""".strip()
    rc, _, err = _run(["bash", "-lc", f"cat > {config_path} <<'EOF'\n{config_body}\nEOF"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[OPT] no se pudo escribir {config_path}: {err}"])
    logs.append(f"[OPT] config escrita: {config_path}")

    rc, _, err = _run(["a2enconf", "panelctl-optimization"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[OPT] no se pudo habilitar panelctl-optimization: {err}"])
    logs.append("[OPT] conf Apache habilitada: panelctl-optimization")

    rc, out, err = _run(["apache2ctl", "configtest"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[OPT] apache2ctl configtest fallo: {err or out}"])
    logs.append("[OPT] apache2ctl configtest OK")

    rc, _, err = _run(["systemctl", "reload", "apache2"])
    if rc != 0:
        return OptimizationResult(False, logs + [f"[OPT] no se pudo recargar apache2: {err}"])
    logs.append("[OPT] apache2 recargado")
    logs.append("[OPT] no se aplico balanceo: el proyecto sigue en un solo server")
    return OptimizationResult(True, logs)


def _render_zone_file(zone: str, records: List[dict]) -> str:
    return _render_zone_file_with_config(zone, records, DNSConfig())


def _render_zone_file_with_config(zone: str, records: List[dict], config: DNSConfig) -> str:
    serial = int(time.strftime("%Y%m%d%H"))
    ttl = min((int(r["ttl"]) for r in records), default=300)
    ns1 = config.ns1_hostname.rstrip(".")
    ns2 = config.ns2_hostname.rstrip(".")
    lines = [
        f"$TTL {ttl}",
        f"@ IN SOA {ns1}. hostmaster.{zone}. (",
        f"    {serial} ; serial",
        "    3600 ; refresh",
        "    900 ; retry",
        "    1209600 ; expire",
        "    300 ; negative cache TTL",
        ")",
        f"@ IN NS {ns1}.",
    ]
    if ns2:
        lines.append(f"@ IN NS {ns2}.")
    ns1_suffix = f".{zone}"
    autogenerated_hosts: set[str] = set()
    if ns1.endswith(ns1_suffix):
        ns1_label = ns1[: -len(ns1_suffix)]
        if ns1_label and "." not in ns1_label:
            lines.append(f"{ns1_label} IN A {config.ns1_ipv4}")
            autogenerated_hosts.add(ns1_label)
    if ns2 and config.ns2_ipv4 and ns2.endswith(ns1_suffix):
        ns2_label = ns2[: -len(ns1_suffix)]
        if ns2_label and "." not in ns2_label:
            lines.append(f"{ns2_label} IN A {config.ns2_ipv4}")
            autogenerated_hosts.add(ns2_label)
    for r in records:
        host = "@" if r["name"] == "@" else r["name"]
        rtype = str(r["type"]).upper()
        value = str(r["value"])
        if rtype == "NS":
            continue
        if rtype == "A" and host in autogenerated_hosts:
            continue
        lines.append(f"{host} IN {rtype} {value}")
    return "\n".join(lines) + "\n"


def _build_named_options_block(config: DNSConfig) -> str:
    lines = ["    // BEGIN PANELCTL MANAGED OPTIONS"]
    if config.listen_on.strip().lower() == "any":
        lines.append("    listen-on { any; };")
    else:
        values = [item.strip() for item in config.listen_on.split(",") if item.strip()]
        rendered = " ".join(f"{item};" for item in values) or "any;"
        lines.append(f"    listen-on {{ {rendered} }};")
    lines.append("    listen-on-v6 { any; };")
    lines.append(f"    recursion {'yes' if config.allow_recursion else 'no'};")
    if config.forwarders.strip():
        forwarders = [item.strip() for item in config.forwarders.split(",") if item.strip()]
        rendered = " ".join(f"{item};" for item in forwarders)
        lines.append(f"    forwarders {{ {rendered} }};")
    lines.append("    // END PANELCTL MANAGED OPTIONS")
    return "\n".join(lines) + "\n"


def _upsert_managed_block(path: str, start: str, end: str, block: str) -> tuple[bool, str]:
    script = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"path=Path({path!r})\n"
        "text=path.read_text(encoding='utf-8') if path.exists() else ''\n"
        f"start={start!r}\n"
        f"end={end!r}\n"
        f"block={block!r}\n"
        "if start in text and end in text:\n"
        "    pre=text.split(start,1)[0]\n"
        "    post=text.split(end,1)[1]\n"
        "    new=pre+block+post.lstrip('\\n')\n"
        "else:\n"
        "    sep='\\n' if text and not text.endswith('\\n') else ''\n"
        "    new=text+sep+block\n"
        "path.write_text(new, encoding='utf-8')\n"
        "PY"
    )
    rc, _, err = _run(["bash", "-lc", script])
    return rc == 0, err


def _upsert_named_options(path: str, block: str) -> tuple[bool, str]:
    script = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"path=Path({path!r})\n"
        "text=path.read_text(encoding='utf-8') if path.exists() else ''\n"
        "start='// BEGIN PANELCTL MANAGED OPTIONS'\n"
        "end='// END PANELCTL MANAGED OPTIONS'\n"
        f"block={block!r}\n"
        "if start in text and end in text:\n"
        "    pre=text.split(start,1)[0]\n"
        "    post=text.split(end,1)[1]\n"
        "    new=pre+block+post.lstrip('\\n')\n"
        "elif 'options' in text and '};' in text:\n"
        "    idx=text.find('options')\n"
        "    end_idx=text.rfind('};')\n"
        "    if end_idx == -1:\n"
        "        new=text\n"
        "    else:\n"
        "        new=text[:end_idx]+block+text[end_idx:]\n"
        "else:\n"
        "    new='options {\\n'+block+'};\\n'\n"
        "path.write_text(new, encoding='utf-8')\n"
        "PY"
    )
    rc, _, err = _run(["bash", "-lc", script])
    return rc == 0, err


def dns_apply_preview() -> List[str]:
    return [
        "mkdir -p /etc/bind/panel-zones",
        "actualizar /etc/bind/named.conf.options",
        "escribir /etc/bind/panel-zones/db.<zone>",
        "actualizar bloque managed en /etc/bind/named.conf.local",
        "named-checkconf",
        "named-checkzone <zone> /etc/bind/panel-zones/db.<zone>",
        "systemctl reload bind9",
    ]


def ftp_apply_preview() -> List[str]:
    return [
        "useradd/usermod usuarios del sistema",
        "usermod -p <hash> <usuario>",
        "mkdir/chown home FTP",
        "systemctl restart vsftpd",
    ]


def mail_apply_preview() -> List[str]:
    return [
        "crear usuario/grupo virtual vmail si faltan",
        "mkdir -p /var/mail/vhosts/<dominio>/<usuario>/Maildir/{cur,new,tmp}",
        "escribir /etc/postfix/vmailbox y /etc/postfix/vmail-domains",
        "postmap /etc/postfix/vmailbox y /etc/postfix/vmail-domains",
        "actualizar bloque managed en /etc/postfix/main.cf",
        "escribir /etc/dovecot/passwd y /etc/dovecot/conf.d/99-nicepanel-mail.conf",
        "postfix check",
        "dovecot reload + postfix reload",
    ]


def _write_text_file(path: str, content: str) -> tuple[bool, str]:
    script = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"path=Path({path!r})\n"
        f"content={content!r}\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        "path.write_text(content, encoding='utf-8')\n"
        "PY"
    )
    rc, _, err = _run(["bash", "-lc", script])
    return rc == 0, err


def _ensure_virtual_mail_user() -> ApplyResult:
    logs: List[str] = []
    rc, _, err = _run(["groupadd", "-f", "vmail"])
    if rc != 0:
        return ApplyResult(False, [f"[MAIL] no se pudo asegurar grupo vmail: {err}"])
    logs.append("[MAIL] grupo vmail OK")

    rc, out, err = _run(["id", "-u", "vmail"])
    if rc != 0:
        rc, _, err = _run(
            ["useradd", "-r", "-g", "vmail", "-d", "/var/mail/vhosts", "-s", "/usr/sbin/nologin", "vmail"]
        )
        if rc != 0:
            return ApplyResult(False, [f"[MAIL] no se pudo crear usuario vmail: {err}"])
        rc, out, err = _run(["id", "-u", "vmail"])
        if rc != 0:
            return ApplyResult(False, [f"[MAIL] no se pudo leer uid de vmail: {err or out}"])
        logs.append("[MAIL] usuario vmail creado")
    else:
        logs.append("[MAIL] usuario vmail OK")
    uid = out.strip()
    rc, out, err = _run(["id", "-g", "vmail"])
    if rc != 0:
        return ApplyResult(False, [f"[MAIL] no se pudo leer gid de vmail: {err or out}"])
    gid = out.strip()
    return ApplyResult(True, logs + [uid, gid])


def _render_postfix_mail_domains(accounts: List[dict]) -> str:
    domains = sorted({str(acc.get("domain", "")).strip().lower() for acc in accounts if str(acc.get("domain", "")).strip()})
    return "".join(f"{domain} OK\n" for domain in domains)


def _render_postfix_mailboxes(accounts: List[dict]) -> str:
    lines = []
    for acc in sorted(accounts, key=lambda item: (str(item.get("domain", "")), str(item.get("address", "")))):
        address = str(acc.get("address", "")).strip().lower()
        domain = str(acc.get("domain", "")).strip().lower()
        local_part = str(acc.get("local_part", "") or address.split("@", 1)[0]).strip()
        if not address or not domain or not local_part:
            continue
        lines.append(f"{address} {domain}/{local_part}/Maildir/")
    return "\n".join(lines) + ("\n" if lines else "")


def _render_dovecot_passwd(accounts: List[dict], uid: str, gid: str) -> str:
    lines = []
    for acc in sorted(accounts, key=lambda item: (str(item.get("domain", "")), str(item.get("address", "")))):
        address = str(acc.get("address", "")).strip().lower()
        domain = str(acc.get("domain", "")).strip().lower()
        local_part = str(acc.get("local_part", "") or address.split("@", 1)[0]).strip()
        password_hash = str(acc.get("password_hash", "")).strip()
        if not address or not domain or not local_part:
            continue
        if not password_hash.startswith("{") and not password_hash.startswith("$6$"):
            raise RuntimeError(f"hash_mail_invalido:{address}")
        home = f"/var/mail/vhosts/{domain}/{local_part}"
        lines.append(
            f"{address}:{password_hash}:{uid}:{gid}::{home}::userdb_mail=maildir:{home}/Maildir"
        )
    return "\n".join(lines) + ("\n" if lines else "")


def _render_postfix_main_cf_block(uid: str, gid: str) -> str:
    lines = [
        "# BEGIN PANELCTL MANAGED MAIL",
        "virtual_mailbox_base = /var/mail/vhosts",
        "virtual_mailbox_domains = hash:/etc/postfix/vmail-domains",
        "virtual_mailbox_maps = hash:/etc/postfix/vmailbox",
        "virtual_minimum_uid = 100",
        f"virtual_uid_maps = static:{uid}",
        f"virtual_gid_maps = static:{gid}",
        "virtual_transport = lmtp:unix:private/dovecot-lmtp",
        "smtpd_sasl_type = dovecot",
        "smtpd_sasl_path = private/auth",
        "smtpd_sasl_auth_enable = yes",
        "smtpd_tls_auth_only = no",
        "smtpd_recipient_restrictions = permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination",
        "# END PANELCTL MANAGED MAIL",
    ]
    return "\n".join(lines) + "\n"


def _render_dovecot_nicepanel_conf() -> str:
    return "\n".join(
        [
            "# BEGIN PANELCTL MANAGED MAIL",
            "passdb {",
            "  driver = passwd-file",
            "  args = username_format=%u /etc/dovecot/passwd",
            "}",
            "userdb {",
            "  driver = passwd-file",
            "  args = username_format=%u /etc/dovecot/passwd",
            "}",
            "service auth {",
            "  unix_listener /var/spool/postfix/private/auth {",
            "    mode = 0660",
            "    user = postfix",
            "    group = postfix",
            "  }",
            "}",
            "service lmtp {",
            "  unix_listener /var/spool/postfix/private/dovecot-lmtp {",
            "    mode = 0600",
            "    user = postfix",
            "    group = postfix",
            "  }",
            "}",
            "mail_location = maildir:/var/mail/vhosts/%d/%n/Maildir",
            "# END PANELCTL MANAGED MAIL",
            "",
        ]
    )


def apply_dns(records: List[dict], domains: List[dict] | List[str] | None = None, config: DNSConfig | None = None) -> ApplyResult:
    logs: List[str] = []
    config = config or DNSConfig()
    domain_list: List[str] = []
    domain_config_map: dict[str, dict[str, str]] = {}
    for domain in domains or []:
        if isinstance(domain, dict):
            name = str(domain.get("domain", "")).lower().strip()
            if not name:
                continue
            domain_list.append(name)
            domain_config_map[name] = {
                "ns1_hostname": str(domain.get("ns1_hostname", "")).strip(),
                "ns1_ipv4": str(domain.get("ns1_ipv4", "")).strip(),
                "ns2_hostname": str(domain.get("ns2_hostname", "")).strip(),
                "ns2_ipv4": str(domain.get("ns2_ipv4", "")).strip(),
            }
        else:
            name = str(domain).lower().strip()
            if name:
                domain_list.append(name)
    if not records and not domain_list:
        return ApplyResult(True, ["[DNS] sin registros para aplicar."])

    zones = sorted(set(domain_list) | {str(r["zone"]).lower() for r in records})
    zone_map: dict[str, List[dict]] = {z: [] for z in zones}
    for rec in records:
        zone_map[str(rec["zone"]).lower()].append(rec)

    rc, _, err = _run(["mkdir", "-p", "/etc/bind/panel-zones"])
    if rc != 0:
        return ApplyResult(False, [f"[DNS] no se pudo crear /etc/bind/panel-zones: {err}"])

    for zone in zones:
        zone_config = _effective_zone_config(zone, config, domain_config_map.get(zone))
        content = _render_zone_file_with_config(zone, zone_map[zone], zone_config)
        path = f"/etc/bind/panel-zones/db.{zone}"
        rc, _, err = _run(["bash", "-lc", f"cat > {path} <<'EOF'\n{content}EOF"])
        if rc != 0:
            return ApplyResult(False, [f"[DNS] no se pudo escribir {path}: {err}"])
        logs.append(f"[DNS] zone file actualizado: {path} ({zone_config.ns1_hostname})")

    named_options = "/etc/bind/named.conf.options"
    ok, err = _upsert_named_options(named_options, _build_named_options_block(config))
    if not ok:
        return ApplyResult(False, [f"[DNS] no se pudo actualizar {named_options}: {err}"])
    logs.append(f"[DNS] config actualizada: {named_options}")

    named_local = "/etc/bind/named.conf.local"
    ok, err = _upsert_managed_block(
        named_local,
        "# BEGIN PANELCTL MANAGED ZONES",
        "# END PANELCTL MANAGED ZONES",
        _build_named_block(zones),
    )
    if not ok:
        return ApplyResult(False, [f"[DNS] no se pudo actualizar {named_local}: {err}"])
    logs.append(f"[DNS] config actualizada: {named_local}")

    rc, out, err = _run(["named-checkconf"])
    if rc != 0:
        return ApplyResult(False, [f"[DNS] named-checkconf fallo: {err or out}"])
    logs.append("[DNS] named-checkconf OK")

    for zone in zones:
        path = f"/etc/bind/panel-zones/db.{zone}"
        rc, out, err = _run(["named-checkzone", zone, path])
        if rc != 0:
            return ApplyResult(False, [f"[DNS] named-checkzone {zone} fallo: {err or out}"])
        logs.append(f"[DNS] named-checkzone OK: {zone}")

    rc, _, err = _run(["systemctl", "reload", "bind9"])
    if rc != 0:
        return ApplyResult(False, [f"[DNS] no se pudo recargar bind9: {err}"])
    logs.append("[DNS] bind9 recargado.")
    return ApplyResult(True, logs)


def apply_ftp(accounts: List[dict]) -> ApplyResult:
    logs: List[str] = []
    if not accounts:
        return ApplyResult(True, ["[FTP] sin cuentas para aplicar."])

    for acc in accounts:
        username = str(acc["username"])
        home_dir = str(acc["home_dir"])
        password_hash = str(acc["password_hash"] or "")
        if not password_hash:
            return ApplyResult(False, [f"[FTP] la cuenta {username} no tiene password hash."])

        rc, _, _ = _run(["id", "-u", username])
        if rc == 0:
            rc, _, err = _run(["usermod", "-d", home_dir, "-s", "/usr/sbin/nologin", username])
            if rc != 0:
                return ApplyResult(False, [f"[FTP] no se pudo actualizar usuario {username}: {err}"])
            logs.append(f"[FTP] usuario existente actualizado: {username}")
        else:
            rc, _, err = _run(["useradd", "-m", "-d", home_dir, "-s", "/usr/sbin/nologin", username])
            if rc != 0:
                return ApplyResult(False, [f"[FTP] no se pudo crear usuario {username}: {err}"])
            logs.append(f"[FTP] usuario creado: {username}")

        rc, _, err = _run(["usermod", "-p", password_hash, username])
        if rc != 0:
            return ApplyResult(False, [f"[FTP] no se pudo establecer password para {username}: {err}"])

        rc, _, err = _run(["mkdir", "-p", home_dir])
        if rc != 0:
            return ApplyResult(False, [f"[FTP] no se pudo crear home {home_dir}: {err}"])
        rc, _, err = _run(["chown", "-R", f"{username}:{username}", home_dir])
        if rc != 0:
            return ApplyResult(False, [f"[FTP] no se pudo asignar ownership en {home_dir}: {err}"])

    rc, _, err = _run(["systemctl", "restart", "vsftpd"])
    if rc != 0:
        return ApplyResult(False, [f"[FTP] no se pudo reiniciar vsftpd: {err}"])
    logs.append("[FTP] vsftpd reiniciado.")
    return ApplyResult(True, logs)


def apply_mail(accounts: List[dict]) -> ApplyResult:
    logs: List[str] = []
    if not accounts:
        return ApplyResult(True, ["[MAIL] sin cuentas para aplicar."])

    vmail_result = _ensure_virtual_mail_user()
    if not vmail_result.ok:
        return vmail_result
    uid, gid = vmail_result.logs[-2], vmail_result.logs[-1]
    logs.extend(vmail_result.logs[:-2])

    rc, _, err = _run(["mkdir", "-p", "/var/mail/vhosts"])
    if rc != 0:
        return ApplyResult(False, [f"[MAIL] no se pudo crear /var/mail/vhosts: {err}"])

    domain_content = _render_postfix_mail_domains(accounts)
    mailbox_content = _render_postfix_mailboxes(accounts)
    try:
        dovecot_passwd = _render_dovecot_passwd(accounts, uid, gid)
    except RuntimeError as exc:
        marker, _, address = str(exc).partition(":")
        if marker == "hash_mail_invalido":
            return ApplyResult(False, [f"[MAIL] hash invalido para {address}. Edita la cuenta y rota su password."])
        raise

    files = [
        ("/etc/postfix/vmail-domains", domain_content),
        ("/etc/postfix/vmailbox", mailbox_content),
        ("/etc/dovecot/passwd", dovecot_passwd),
        ("/etc/dovecot/conf.d/99-nicepanel-mail.conf", _render_dovecot_nicepanel_conf()),
    ]
    for path, content in files:
        ok, err = _write_text_file(path, content)
        if not ok:
            return ApplyResult(False, [f"[MAIL] no se pudo escribir {path}: {err}"])
        logs.append(f"[MAIL] archivo actualizado: {path}")

    for acc in accounts:
        domain = str(acc.get("domain", "")).strip().lower()
        local_part = str(acc.get("local_part", "") or str(acc.get("address", "")).split("@", 1)[0]).strip()
        if not domain or not local_part:
            continue
        base = f"/var/mail/vhosts/{domain}/{local_part}/Maildir"
        for folder in [base, f"{base}/cur", f"{base}/new", f"{base}/tmp"]:
            rc, _, err = _run(["mkdir", "-p", folder])
            if rc != 0:
                return ApplyResult(False, [f"[MAIL] no se pudo crear {folder}: {err}"])
        rc, _, err = _run(["chown", "-R", "vmail:vmail", f"/var/mail/vhosts/{domain}/{local_part}"])
        if rc != 0:
            return ApplyResult(False, [f"[MAIL] no se pudo asignar ownership para {domain}/{local_part}: {err}"])

    for map_path in ["/etc/postfix/vmail-domains", "/etc/postfix/vmailbox"]:
        rc, _, err = _run(["postmap", map_path])
        if rc != 0:
            return ApplyResult(False, [f"[MAIL] postmap fallo para {map_path}: {err}"])
        logs.append(f"[MAIL] postmap OK: {map_path}")

    ok, err = _upsert_managed_block(
        "/etc/postfix/main.cf",
        "# BEGIN PANELCTL MANAGED MAIL",
        "# END PANELCTL MANAGED MAIL",
        _render_postfix_main_cf_block(uid, gid),
    )
    if not ok:
        return ApplyResult(False, [f"[MAIL] no se pudo actualizar /etc/postfix/main.cf: {err}"])
    logs.append("[MAIL] config actualizada: /etc/postfix/main.cf")

    rc, out, err = _run(["postfix", "check"])
    if rc != 0:
        return ApplyResult(False, [f"[MAIL] postfix check fallo: {err or out}"])
    logs.append("[MAIL] postfix check OK")

    rc, out, err = _run(["dovecot", "-n"])
    if rc != 0:
        return ApplyResult(False, [f"[MAIL] dovecot config invalida: {err or out}"])
    logs.append("[MAIL] dovecot config OK")

    for service in ["dovecot", "postfix"]:
        rc, _, err = _run(["systemctl", "reload", service])
        if rc != 0:
            rc, _, err = _run(["systemctl", "restart", service])
            if rc != 0:
                return ApplyResult(False, [f"[MAIL] no se pudo recargar {service}: {err}"])
        logs.append(f"[MAIL] {service} recargado.")

    return ApplyResult(True, logs)


def _validate_web_update_structure(path: str) -> List[str]:
    required = ["package.json", "server.js", "public", "src"]
    missing = [entry for entry in required if not os.path.exists(os.path.join(path, entry))]
    return missing


def web_update_preflight(config: WebUpdateConfig) -> WebUpdateResult:
    logs: List[str] = []
    if not config.repo_url.strip():
        return WebUpdateResult(False, ["[UPDATE] falta repo_url."])

    for binary in ["git", "npm", "tar", "sqlite3"]:
        if not _command_exists(binary):
            return WebUpdateResult(False, [f"[UPDATE] falta dependencia requerida: {binary}"])
        logs.append(f"[UPDATE] dependencia OK: {binary}")

    if config.service_name.strip():
        if _command_exists("systemctl"):
            logs.append(f"[UPDATE] systemctl detectado. Servicio objetivo: {config.service_name}")
        else:
            logs.append("[UPDATE] systemctl no disponible. Se omitira restart automatico.")

    logs.append(f"[UPDATE] destino: {config.project_dir}")
    logs.append(f"[UPDATE] repo: {config.repo_url} ({config.branch})")
    logs.append(f"[UPDATE] temp: {config.temp_dir}")
    logs.append(f"[UPDATE] backups: {config.backup_dir}")
    return WebUpdateResult(True, logs)


def download_web_update(config: WebUpdateConfig) -> WebUpdateResult:
    logs: List[str] = []
    rc, _, err = _run(["mkdir", "-p", os.path.dirname(config.temp_dir) or "/tmp"])
    if rc != 0:
      return WebUpdateResult(False, [f"[UPDATE] no se pudo preparar directorio temporal: {err}"])

    rc, _, err = _run(["rm", "-rf", config.temp_dir])
    if rc != 0:
        return WebUpdateResult(False, [f"[UPDATE] no se pudo limpiar temporal previo: {err}"])

    clone_cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        config.branch,
        config.repo_url,
        config.temp_dir,
    ]
    rc, out, err = _run(clone_cmd)
    if rc != 0:
        return WebUpdateResult(False, [f"[UPDATE] git clone fallo: {err or out}"])
    logs.append("[UPDATE] repositorio descargado en temporal.")

    missing = _validate_web_update_structure(config.temp_dir)
    if missing:
        return WebUpdateResult(False, [f"[UPDATE] estructura invalida. Faltan: {', '.join(missing)}"])

    temp_dir_q = shlex.quote(config.temp_dir)
    rc, out, err = _run(["bash", "-lc", f"cd {temp_dir_q} && git rev-parse --short HEAD"])
    commit = out.strip() if rc == 0 else ""
    if commit:
        logs.append(f"[UPDATE] commit descargado: {commit}")
    else:
        logs.append(f"[UPDATE] no se pudo leer commit: {err or 'sin detalle'}")

    return WebUpdateResult(True, logs, downloaded=True, commit=commit)


def create_web_backup(config: WebUpdateConfig) -> WebUpdateResult:
    logs: List[str] = []
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_root = os.path.join(config.backup_dir, stamp)

    rc, _, err = _run(["mkdir", "-p", backup_root])
    if rc != 0:
        return WebUpdateResult(False, [f"[UPDATE] no se pudo crear backup root: {err}"])

    db_path = os.path.join(config.project_dir, "data", "store.sqlite")
    if os.path.exists(db_path):
        rc, out, err = _run(["sqlite3", db_path, f".backup '{os.path.join(backup_root, 'store.sqlite')}'"])
        if rc != 0:
            return WebUpdateResult(False, [f"[UPDATE] backup DB fallo: {err or out}"])
        logs.append(f"[UPDATE] backup DB OK: {backup_root}/store.sqlite")
    else:
        logs.append("[UPDATE] sin DB para respaldar.")

    uploads_dir = os.path.join(config.project_dir, "public", "uploads")
    if os.path.isdir(uploads_dir):
        rc, _, err = _run(["tar", "-czf", os.path.join(backup_root, "uploads.tar.gz"), "-C", uploads_dir, "."])
        if rc != 0:
            return WebUpdateResult(False, [f"[UPDATE] backup uploads fallo: {err}"])
        logs.append(f"[UPDATE] backup uploads OK: {backup_root}/uploads.tar.gz")
    else:
        logs.append("[UPDATE] sin uploads para respaldar.")

    if os.path.isdir(config.project_dir):
        code_archive = os.path.join(backup_root, "code.tar.gz")
        project_dir_q = shlex.quote(config.project_dir)
        code_archive_q = shlex.quote(code_archive)
        rc, _, err = _run([
            "bash",
            "-lc",
            f"cd {project_dir_q} && tar --exclude='./node_modules' --exclude='./data/store.sqlite' --exclude='./public/uploads' -czf {code_archive_q} .",
        ])
        if rc != 0:
            return WebUpdateResult(False, [f"[UPDATE] backup codigo fallo: {err}"])
        logs.append(f"[UPDATE] backup codigo OK: {code_archive}")
    else:
        logs.append("[UPDATE] proyecto destino aun no existe. No hay codigo previo para respaldar.")

    logs.append(f"[UPDATE] backup stamp: {stamp}")
    return WebUpdateResult(True, logs)


def replace_web_update(config: WebUpdateConfig) -> WebUpdateResult:
    logs: List[str] = []
    if not os.path.isdir(config.temp_dir):
        return WebUpdateResult(False, ["[UPDATE] primero descarga una copia temporal con 'd'."])

    missing = _validate_web_update_structure(config.temp_dir)
    if missing:
        return WebUpdateResult(False, [f"[UPDATE] temporal invalido. Faltan: {', '.join(missing)}"])

    backup = create_web_backup(config)
    logs.extend(backup.logs)
    if not backup.ok:
        return WebUpdateResult(False, logs)

    rc, _, err = _run(["mkdir", "-p", config.project_dir])
    if rc != 0:
        return WebUpdateResult(False, logs + [f"[UPDATE] no se pudo crear destino: {err}"])

    temp_dir_q = shlex.quote(config.temp_dir)
    project_dir_q = shlex.quote(config.project_dir)
    rc, _, err = _run([
        "bash",
        "-lc",
        f"cd {temp_dir_q} && tar --exclude='.git' --exclude='node_modules' -cf - . | (cd {project_dir_q} && tar -xf -)",
    ])
    if rc != 0:
        return WebUpdateResult(False, logs + [f"[UPDATE] no se pudo reemplazar codigo: {err}"])
    logs.append("[UPDATE] codigo desplegado sobre destino.")

    rc, out, err = _run(["bash", "-lc", f"cd {project_dir_q} && npm install"])
    if rc != 0:
        return WebUpdateResult(False, logs + [f"[UPDATE] npm install fallo: {err or out}"])
    logs.append("[UPDATE] npm install OK.")

    rc, out, err = _run(["bash", "-lc", f"cd {project_dir_q} && npm run tw:build"])
    if rc == 0:
        logs.append("[UPDATE] tailwind build OK.")
    else:
        logs.append(f"[UPDATE] tailwind build omitido o con error: {err or out}")

    if config.service_name.strip() and _command_exists("systemctl"):
        rc, _, err = _run(["systemctl", "restart", config.service_name])
        if rc != 0:
            return WebUpdateResult(False, logs + [f"[UPDATE] no se pudo reiniciar servicio {config.service_name}: {err}"])
        logs.append(f"[UPDATE] servicio reiniciado: {config.service_name}")
    else:
        logs.append("[UPDATE] restart automatico omitido.")

    return WebUpdateResult(True, logs)
