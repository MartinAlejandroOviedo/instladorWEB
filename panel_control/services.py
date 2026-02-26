"""Service integration layer for real provisioning tasks."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from typing import List


@dataclass
class ApplyResult:
    ok: bool
    logs: List[str]


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
