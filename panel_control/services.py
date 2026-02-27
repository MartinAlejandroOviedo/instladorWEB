"""Service integration layer for real provisioning tasks."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import List


@dataclass
class ApplyResult:
    ok: bool
    logs: List[str]


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


def _run(raw: List[str]) -> tuple[int, str, str]:
    cmd = raw if os.geteuid() == 0 else ["sudo", "-n"] + raw
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


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


def _build_named_block(zones: List[str]) -> str:
    lines = ["# BEGIN PANELCTL MANAGED ZONES"]
    for zone in zones:
        lines.append(f'zone "{zone}" {{ type master; file "/etc/bind/panel-zones/db.{zone}"; }};')
    lines.append("# END PANELCTL MANAGED ZONES")
    return "\n".join(lines) + "\n"


def _render_zone_file(zone: str, records: List[dict]) -> str:
    serial = int(time.strftime("%Y%m%d%H"))
    ttl = min((int(r["ttl"]) for r in records), default=300)
    lines = [
        f"$TTL {ttl}",
        f"@ IN SOA ns1.{zone}. hostmaster.{zone}. (",
        f"    {serial} ; serial",
        "    3600 ; refresh",
        "    900 ; retry",
        "    1209600 ; expire",
        "    300 ; negative cache TTL",
        ")",
        f"@ IN NS ns1.{zone}.",
        f"ns1 IN A 127.0.0.1",
    ]
    for r in records:
        host = "@" if r["name"] == "@" else r["name"]
        rtype = str(r["type"]).upper()
        value = str(r["value"])
        lines.append(f"{host} IN {rtype} {value}")
    return "\n".join(lines) + "\n"


def dns_apply_preview() -> List[str]:
    return [
        "mkdir -p /etc/bind/panel-zones",
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
        "# pendiente: integrar mailbox real con postfix+dovecot",
    ]


def apply_dns(records: List[dict]) -> ApplyResult:
    logs: List[str] = []
    if not records:
        return ApplyResult(True, ["[DNS] sin registros para aplicar."])

    zones = sorted({str(r["zone"]).lower() for r in records})
    zone_map: dict[str, List[dict]] = {z: [] for z in zones}
    for rec in records:
        zone_map[str(rec["zone"]).lower()].append(rec)

    rc, _, err = _run(["mkdir", "-p", "/etc/bind/panel-zones"])
    if rc != 0:
        return ApplyResult(False, [f"[DNS] no se pudo crear /etc/bind/panel-zones: {err}"])

    for zone in zones:
        content = _render_zone_file(zone, zone_map[zone])
        path = f"/etc/bind/panel-zones/db.{zone}"
        rc, _, err = _run(["bash", "-lc", f"cat > {path} <<'EOF'\n{content}EOF"])
        if rc != 0:
            return ApplyResult(False, [f"[DNS] no se pudo escribir {path}: {err}"])
        logs.append(f"[DNS] zone file actualizado: {path}")

    named_local = "/etc/bind/named.conf.local"
    block = _build_named_block(zones)
    script = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"path=Path('{named_local}')\n"
        "text=path.read_text(encoding='utf-8') if path.exists() else ''\n"
        "start='# BEGIN PANELCTL MANAGED ZONES'\n"
        "end='# END PANELCTL MANAGED ZONES'\n"
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
    if rc != 0:
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


def _command_exists(binary: str) -> bool:
    proc = subprocess.run(["bash", "-lc", f"command -v {binary} >/dev/null 2>&1"], check=False)
    return proc.returncode == 0


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
