#!/usr/bin/env python3
"""Debian VPS installer TUI for web panel stack.

Flow:
- Splash
- Preflight
- Install profile
- Plan (dry-run)
- Apply
- Summary
"""

from __future__ import annotations

import curses
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class Dependency:
    label: str
    package: str
    binary: Optional[str] = None
    required: bool = True


@dataclass
class DependencyStatus:
    dependency: Dependency
    installed: bool
    source: str
    detail: str


@dataclass
class PreflightItem:
    name: str
    status: str  # OK, WARN, FAIL
    detail: str
    critical: bool = False


@dataclass
class InstallProfile:
    include_dns: bool = False
    include_ftp: bool = False
    include_email: bool = False
    include_fail2ban: bool = True
    hostname: str = ""
    admin_email: str = ""


@dataclass
class PlanAction:
    id: str
    title: str
    command: List[str]
    reversible: bool = False
    rollback_command: Optional[List[str]] = None
    critical: bool = True
    status: str = "PENDING"  # PENDING, RUNNING, OK, FAIL, SKIP, ROLLED_BACK
    output: str = ""


DEPENDENCIES: List[Dependency] = [
    Dependency("Python 3", "python3", "python3"),
    Dependency("Node.js", "nodejs", "node"),
    Dependency("npm", "npm", "npm"),
    Dependency("Apache2", "apache2", "apache2"),
    Dependency("SQLite3", "sqlite3", "sqlite3"),
    Dependency("Certbot", "certbot", "certbot"),
    Dependency("UFW", "ufw", "ufw"),
    Dependency("FTP (vsftpd)", "vsftpd", "vsftpd", required=False),
    Dependency("SMTP (Postfix)", "postfix", "postfix", required=False),
    Dependency("fail2ban", "fail2ban", "fail2ban-server", required=False),
]

BASE_PACKAGES = [
    "apache2",
    "nodejs",
    "npm",
    "sqlite3",
    "certbot",
    "ufw",
    "python3-venv",
]


def run_command(command: List[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "command not found"


def detect_debian() -> Tuple[bool, str]:
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            content = f.read().lower()
        is_debian = "debian" in content
        return is_debian, "Debian detectado" if is_debian else "Este instalador soporta Debian"
    except OSError as exc:
        return False, f"No se pudo leer /etc/os-release: {exc}"


def check_privileges() -> Tuple[str, str, bool]:
    if os.geteuid() == 0:
        return "OK", "Ejecutando como root", True
    rc, _, err = run_command(["sudo", "-n", "true"])
    if rc == 0:
        return "OK", "sudo sin password interactivo disponible", True
    if shutil.which("sudo"):
        detail = (
            "sudo requiere password interactivo. "
            "Para aplicar cambios ejecuta: sudo python3 installer_tui.py"
        )
        return "WARN", detail, False
    return "FAIL", f"Sin root/sudo ({err or 'sudo -n true fallo'})", False


def read_mem_gb() -> float:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            line = next((l for l in f if l.startswith("MemTotal:")), "")
        kb = int(re.findall(r"\d+", line)[0]) if line else 0
        return kb / 1024 / 1024
    except Exception:
        return 0.0


def disk_free_gb(path: str = "/") -> float:
    usage = shutil.disk_usage(path)
    return usage.free / 1024 / 1024 / 1024


def detect_primary_ip() -> str:
    rc, out, _ = run_command(["hostname", "-I"])
    if rc == 0 and out:
        return out.split()[0]
    return "N/A"


def check_tcp_port(port: int) -> Tuple[bool, str]:
    rc, out, err = run_command(["ss", "-lnt"])
    if rc != 0:
        return False, err or "no se pudo verificar puertos"
    token = f":{port} "
    busy = token in out or out.endswith(f":{port}")
    return busy, "ocupado" if busy else "libre"


def check_dependency(dep: Dependency) -> DependencyStatus:
    rc, stdout, stderr = run_command(["dpkg-query", "-W", "-f=${Status}", dep.package])
    if rc == 0 and "install ok installed" in stdout:
        return DependencyStatus(
            dependency=dep,
            installed=True,
            source="dpkg",
            detail=f"Paquete '{dep.package}' instalado",
        )

    if dep.binary and shutil.which(dep.binary):
        return DependencyStatus(
            dependency=dep,
            installed=True,
            source="binary",
            detail=f"Binario '{dep.binary}' detectado en PATH",
        )

    missing_detail = stderr or stdout or f"No se encontro '{dep.package}'"
    return DependencyStatus(
        dependency=dep,
        installed=False,
        source="missing",
        detail=missing_detail,
    )


def make_cmd(raw: List[str]) -> List[str]:
    if os.geteuid() == 0:
        return raw
    return ["sudo", "-n"] + raw


def profile_packages(profile: InstallProfile) -> List[str]:
    packages = list(BASE_PACKAGES)
    if profile.include_dns:
        packages.append("bind9")
    if profile.include_ftp:
        packages.append("vsftpd")
    if profile.include_email:
        packages.extend(["postfix", "opendkim", "opendkim-tools"])
    if profile.include_fail2ban:
        packages.append("fail2ban")
    return sorted(set(packages))


def build_plan(profile: InstallProfile) -> List[PlanAction]:
    packages = profile_packages(profile)
    package_str = " ".join(packages)
    actions: List[PlanAction] = [
        PlanAction("apt-update", "Actualizar indice APT", make_cmd(["apt-get", "update"])),
        PlanAction(
            "apt-install",
            "Instalar paquetes del perfil",
            make_cmd(["bash", "-lc", f"DEBIAN_FRONTEND=noninteractive apt-get install -y {package_str}"]),
        ),
        PlanAction(
            "mkdir-layout",
            "Crear estructura de panel",
            make_cmd(["mkdir", "-p", "/etc/panelctl", "/var/lib/panelctl", "/var/log/panelctl"]),
            reversible=True,
            rollback_command=make_cmd(["bash", "-lc", "rmdir /var/log/panelctl /var/lib/panelctl /etc/panelctl 2>/dev/null || true"]),
            critical=False,
        ),
        PlanAction(
            "ufw-web",
            "Reglas base UFW (22,80,443)",
            make_cmd(["bash", "-lc", "ufw allow 22 && ufw allow 80 && ufw allow 443"]),
            critical=False,
        ),
        PlanAction(
            "ufw-enable",
            "Habilitar UFW",
            make_cmd(["bash", "-lc", "ufw --force enable"]),
            reversible=True,
            rollback_command=make_cmd(["ufw", "disable"]),
            critical=False,
        ),
        PlanAction(
            "apache-mods",
            "Habilitar modulos Apache reverse proxy",
            make_cmd(["bash", "-lc", "a2enmod proxy proxy_http headers rewrite ssl"]),
            critical=False,
        ),
        PlanAction(
            "apache-test",
            "Validar configuracion Apache",
            make_cmd(["apachectl", "configtest"]),
        ),
        PlanAction(
            "apache-reload",
            "Recargar Apache",
            make_cmd(["systemctl", "reload", "apache2"]),
            critical=False,
        ),
    ]
    if profile.include_fail2ban:
        actions.append(
            PlanAction(
                "fail2ban-enable",
                "Habilitar fail2ban",
                make_cmd(["systemctl", "enable", "--now", "fail2ban"]),
                critical=False,
            )
        )
    return actions


def build_missing_deps_plan(packages: List[str]) -> List[PlanAction]:
    if not packages:
        return []
    package_str = " ".join(sorted(set(packages)))
    return [
        PlanAction(
            "apt-update-missing",
            "Actualizar indice APT",
            make_cmd(["apt-get", "update"]),
        ),
        PlanAction(
            "apt-install-missing",
            "Instalar dependencias faltantes",
            make_cmd(["bash", "-lc", f"DEBIAN_FRONTEND=noninteractive apt-get install -y {package_str}"]),
        ),
    ]


class InstallerTUI:
    def __init__(self, screen: "curses.window") -> None:
        self.screen = screen
        self.state = "splash"
        self.running = True

        self.selection = 0
        self.profile_selection = 0
        self.profile = InstallProfile()

        self.dependencies: List[DependencyStatus] = []
        self.preflight: List[PreflightItem] = []
        self.actions: List[PlanAction] = []
        self.logs: List[str] = []
        self.apply_done = False
        self.apply_ok = False

        self.message = ""
        self.can_apply_changes = False
        self.refresh_preflight()

    def refresh_preflight(self) -> None:
        debian_ok, debian_detail = detect_debian()
        priv_status, priv_detail, can_apply = check_privileges()
        ram_gb = read_mem_gb()
        disk_gb = disk_free_gb("/")
        ip = detect_primary_ip()
        p80_busy, p80_detail = check_tcp_port(80)
        p443_busy, p443_detail = check_tcp_port(443)

        self.can_apply_changes = can_apply
        self.dependencies = [check_dependency(dep) for dep in DEPENDENCIES]
        missing_required = [d.dependency.package for d in self.dependencies if d.dependency.required and not d.installed]

        self.preflight = [
            PreflightItem("SO", "OK" if debian_ok else "FAIL", debian_detail, critical=True),
            PreflightItem("Privilegios", priv_status, priv_detail, critical=priv_status == "FAIL"),
            PreflightItem("RAM", "OK" if ram_gb >= 1 else "WARN", f"{ram_gb:.2f} GB detectada"),
            PreflightItem("Disco /", "OK" if disk_gb >= 2 else "FAIL", f"{disk_gb:.2f} GB libre", critical=True),
            PreflightItem("IP primaria", "OK" if ip != "N/A" else "WARN", ip),
            PreflightItem("Puerto 80", "WARN" if p80_busy else "OK", p80_detail),
            PreflightItem("Puerto 443", "WARN" if p443_busy else "OK", p443_detail),
            PreflightItem(
                "Dependencias base",
                "OK" if not missing_required else "WARN",
                "faltan: " + ", ".join(missing_required) if missing_required else "todas detectadas",
            ),
        ]
        self.message = "Diagnostico actualizado."

    def has_critical_failures(self) -> bool:
        return any(item.critical and item.status == "FAIL" for item in self.preflight)

    def missing_required_packages(self) -> List[str]:
        return [
            dep.dependency.package
            for dep in self.dependencies
            if dep.dependency.required and not dep.installed
        ]

    def prompt_text(self, prompt: str, initial: str = "") -> str:
        h, w = self.screen.getmaxyx()
        y = h - 2
        self.screen.move(y, 1)
        self.screen.clrtoeol()
        self.screen.addnstr(y, 1, f"{prompt}: {initial}", w - 2)
        curses.echo()
        curses.curs_set(1)
        try:
            value = self.screen.getstr(y, len(prompt) + 3 + len(initial), w - len(prompt) - 5)
            decoded = value.decode("utf-8", errors="ignore").strip()
            return decoded or initial
        finally:
            curses.noecho()
            curses.curs_set(0)

    def set_profile_value(self) -> None:
        options = [
            "DNS (bind9)",
            "FTP (vsftpd)",
            "Email (postfix+dkim)",
            "Fail2ban",
            "Hostname",
            "Email admin",
        ]
        selected = options[self.profile_selection]
        if selected == "DNS (bind9)":
            self.profile.include_dns = not self.profile.include_dns
        elif selected == "FTP (vsftpd)":
            self.profile.include_ftp = not self.profile.include_ftp
        elif selected == "Email (postfix+dkim)":
            self.profile.include_email = not self.profile.include_email
        elif selected == "Fail2ban":
            self.profile.include_fail2ban = not self.profile.include_fail2ban
        elif selected == "Hostname":
            self.profile.hostname = self.prompt_text("Hostname", self.profile.hostname)
        elif selected == "Email admin":
            self.profile.admin_email = self.prompt_text("Email admin", self.profile.admin_email)

    def validate_profile(self) -> Tuple[bool, str]:
        if self.profile.admin_email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", self.profile.admin_email):
            return False, "Email admin invalido."
        if self.profile.hostname and len(self.profile.hostname) < 3:
            return False, "Hostname demasiado corto."
        return True, "Perfil valido."

    def run_plan(self) -> None:
        self.logs = []
        self.apply_done = False
        self.apply_ok = False
        applied: List[PlanAction] = []

        for action in self.actions:
            action.status = "RUNNING"
            self.draw()
            rc, out, err = run_command(action.command)
            output = (out + "\n" + err).strip()
            action.output = output

            if rc == 0:
                action.status = "OK"
                applied.append(action)
                self.logs.append(f"[OK] {action.title}")
                continue

            action.status = "FAIL"
            self.logs.append(f"[FAIL] {action.title}: {err or out or 'sin detalle'}")

            if action.reversible and action.rollback_command:
                rrc, rout, rerr = run_command(action.rollback_command)
                if rrc == 0:
                    action.status = "ROLLED_BACK"
                    self.logs.append(f"[RBK] rollback ejecutado para {action.id}")
                else:
                    self.logs.append(f"[RBK-FAIL] {action.id}: {rerr or rout}")

            if action.critical:
                for pending in self.actions:
                    if pending.status == "PENDING":
                        pending.status = "SKIP"
                break

        self.apply_done = True
        self.apply_ok = all(a.status in ("OK", "SKIP") for a in self.actions if a.critical)
        self.message = "Instalacion completada." if self.apply_ok else "Instalacion con errores."

    def draw_header(self, title: str, subtitle: str) -> None:
        h, w = self.screen.getmaxyx()
        self.screen.addnstr(0, 2, title, w - 4, curses.A_BOLD)
        self.screen.addnstr(1, 2, subtitle, w - 4, curses.A_DIM)

    def draw_splash(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Panel Debian Web Host - Instalador", "Fase 0 - Aviso")
        lines = [
            "Este instalador modifica Apache, UFW, systemd y paquetes del sistema.",
            "Recomendado: snapshot/backup antes de aplicar cambios.",
            "",
            "Teclas: c continuar | q salir",
        ]
        for idx, line in enumerate(lines):
            self.screen.addnstr(3 + idx, 2, line, w - 4)
        self.screen.refresh()

    def draw_preflight(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Fase 1 - Preflight", "Diagnostico del servidor")
        self.screen.addnstr(3, 2, "Checks:", w - 4, curses.A_UNDERLINE)

        for idx, item in enumerate(self.preflight):
            color = 1 if item.status == "OK" else (3 if item.status == "WARN" else 2)
            line = f"[{item.status:4}] {item.name:18} {item.detail}"
            self.screen.addnstr(4 + idx, 2, line, w - 4, curses.color_pair(color))

        row = 5 + len(self.preflight)
        self.screen.addnstr(row, 2, "Dependencias detectadas:", w - 4, curses.A_UNDERLINE)
        for i, dep in enumerate(self.dependencies[: min(len(self.dependencies), h - row - 5)]):
            status = "OK" if dep.installed else "MISSING"
            color = 1 if dep.installed else 2
            self.screen.addnstr(row + 1 + i, 4, f"[{status:7}] {dep.dependency.package}", w - 6, curses.color_pair(color))

        if self.message:
            self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)

        footer = "Teclas: r re-scan | i instalar faltantes | c continuar | q salir"
        self.screen.addnstr(h - 2, 2, footer, w - 4, curses.A_BOLD)
        if self.has_critical_failures():
            self.screen.addnstr(h - 4, 2, "Hay FAIL criticos; no se puede continuar.", w - 4, curses.color_pair(2))
        self.screen.refresh()

    def draw_profile(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Fase 2 - Perfil", "Selecciona modulos a instalar")

        options = [
            ("DNS (bind9)", self.profile.include_dns),
            ("FTP (vsftpd)", self.profile.include_ftp),
            ("Email (postfix+dkim)", self.profile.include_email),
            ("Fail2ban", self.profile.include_fail2ban),
            (f"Hostname: {self.profile.hostname or '-'}", None),
            (f"Email admin: {self.profile.admin_email or '-'}", None),
        ]

        for i, (label, value) in enumerate(options):
            marker = ">" if i == self.profile_selection else " "
            checkbox = "[x]" if value is True else ("[ ]" if value is False else "[*]")
            attr = curses.A_REVERSE if i == self.profile_selection else curses.A_NORMAL
            self.screen.addnstr(4 + i, 2, f"{marker} {checkbox} {label}", w - 4, attr)

        ok, msg = self.validate_profile()
        color = curses.color_pair(1) if ok else curses.color_pair(2)
        self.screen.addnstr(h - 3, 2, msg, w - 4, color)
        self.screen.addnstr(h - 2, 2, "Teclas: flechas mover | espacio/enter editar | c continuar | b atras", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_plan(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Fase 3 - Plan (dry-run)", "Acciones previstas")

        if not self.actions:
            self.actions = build_plan(self.profile)

        for idx, action in enumerate(self.actions[: h - 6]):
            line = f"{idx+1:02d}. {action.title} | rev={'SI' if action.reversible else 'NO'} | crit={'SI' if action.critical else 'NO'}"
            self.screen.addnstr(3 + idx, 2, line, w - 4)

        self.screen.addnstr(h - 2, 2, "Teclas: a aplicar | x exportar plan | b atras | q salir", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_apply(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Fase 4 - Apply", "Ejecucion del plan")

        done = len([a for a in self.actions if a.status in ("OK", "FAIL", "SKIP", "ROLLED_BACK")])
        total = len(self.actions) if self.actions else 1
        percent = int((done / total) * 100)
        bar_w = max(10, w - 20)
        fill = int(bar_w * percent / 100)
        bar = "[" + "#" * fill + "-" * (bar_w - fill) + "]"
        self.screen.addnstr(3, 2, f"Progreso: {percent}% {bar}", w - 4)

        for i, action in enumerate(self.actions[: h - 10]):
            self.screen.addnstr(5 + i, 2, f"[{action.status:11}] {action.title}", w - 4)

        self.screen.addnstr(h - 5, 2, "Logs recientes:", w - 4, curses.A_UNDERLINE)
        for i, line in enumerate(self.logs[-3:]):
            self.screen.addnstr(h - 4 + i, 4, line, w - 6)

        footer = "Teclas: r ejecutar ahora | s resumen | q salir"
        if not self.apply_done:
            footer = "Teclas: r ejecutar ahora | b atras"
        self.screen.addnstr(h - 1, 2, footer, w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_summary(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Fase 5 - Resumen", "Resultado de la instalacion")

        ok_actions = len([a for a in self.actions if a.status == "OK"])
        failed_actions = len([a for a in self.actions if a.status == "FAIL"])
        skipped = len([a for a in self.actions if a.status == "SKIP"])

        lines = [
            f"Estado final: {'OK' if self.apply_ok else 'CON ERRORES'}",
            f"Acciones OK: {ok_actions}",
            f"Acciones FAIL: {failed_actions}",
            f"Acciones SKIP: {skipped}",
            f"IP detectada: {detect_primary_ip()}",
            "",
            "Siguientes pasos:",
            "1) Configurar primer dominio y vhost",
            "2) Emitir SSL con certbot para el dominio",
            "3) Probar API REST y logs",
        ]

        for i, line in enumerate(lines):
            self.screen.addnstr(3 + i, 2, line, w - 4)

        self.screen.addnstr(h - 2, 2, "Teclas: b volver al plan | q salir", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def export_plan(self) -> None:
        if not self.actions:
            self.actions = build_plan(self.profile)
        path = os.path.abspath("install_plan.txt")
        with open(path, "w", encoding="utf-8") as f:
            for i, action in enumerate(self.actions, start=1):
                cmd = " ".join(action.command)
                f.write(f"{i:02d}. {action.title}\n")
                f.write(f"    cmd: {cmd}\n")
                f.write(f"    reversible: {action.reversible}\n\n")
        self.message = f"Plan exportado en {path}"

    def draw(self) -> None:
        if self.state == "splash":
            self.draw_splash()
        elif self.state == "preflight":
            self.draw_preflight()
        elif self.state == "profile":
            self.draw_profile()
        elif self.state == "plan":
            self.draw_plan()
        elif self.state == "apply":
            self.draw_apply()
        elif self.state == "summary":
            self.draw_summary()

    def run(self) -> None:
        curses.curs_set(0)
        self.screen.keypad(True)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)

        while self.running:
            self.draw()
            try:
                key = self.screen.getch()
            except KeyboardInterrupt:
                self.running = False
                break

            if key == 3:  # Ctrl+C
                self.running = False
                break

            if self.state == "splash":
                if key in (ord("q"), ord("Q")):
                    self.running = False
                elif key in (ord("c"), ord("C")):
                    self.state = "preflight"

            elif self.state == "preflight":
                if key in (ord("q"), ord("Q")):
                    self.running = False
                elif key in (ord("r"), ord("R")):
                    self.refresh_preflight()
                elif key in (ord("i"), ord("I")):
                    missing = self.missing_required_packages()
                    if not missing:
                        self.message = "No hay dependencias requeridas faltantes."
                    elif not self.can_apply_changes:
                        self.message = "Para instalar faltantes, ejecuta con sudo/root."
                    else:
                        self.actions = build_missing_deps_plan(missing)
                        self.apply_done = False
                        self.apply_ok = False
                        self.logs = []
                        self.state = "apply"
                elif key in (ord("c"), ord("C")) and not self.has_critical_failures():
                    self.state = "profile"

            elif self.state == "profile":
                if key in (ord("b"), ord("B")):
                    self.state = "preflight"
                elif key == curses.KEY_UP:
                    self.profile_selection = max(0, self.profile_selection - 1)
                elif key == curses.KEY_DOWN:
                    self.profile_selection = min(5, self.profile_selection + 1)
                elif key in (ord(" "), curses.KEY_ENTER, 10, 13):
                    self.set_profile_value()
                elif key in (ord("c"), ord("C")):
                    ok, msg = self.validate_profile()
                    if ok:
                        self.actions = build_plan(self.profile)
                        self.state = "plan"
                    else:
                        self.message = msg

            elif self.state == "plan":
                if key in (ord("q"), ord("Q")):
                    self.running = False
                elif key in (ord("b"), ord("B")):
                    self.state = "profile"
                elif key in (ord("x"), ord("X")):
                    self.export_plan()
                elif key in (ord("a"), ord("A")):
                    self.state = "apply"

            elif self.state == "apply":
                if not self.apply_done:
                    if key in (ord("b"), ord("B")):
                        self.state = "plan"
                    elif key in (ord("r"), ord("R")):
                        if self.can_apply_changes:
                            self.run_plan()
                        else:
                            self.logs.append(
                                "[WARN] Falta privilegio root/sudo no-interactivo para ejecutar el plan."
                            )
                            self.logs.append(
                                "[INFO] Reintenta con: sudo python3 installer_tui.py"
                            )
                            self.apply_done = True
                            self.apply_ok = False
                else:
                    if key in (ord("q"), ord("Q")):
                        self.running = False
                    elif key in (ord("s"), ord("S")):
                        self.state = "summary"

            elif self.state == "summary":
                if key in (ord("q"), ord("Q")):
                    self.running = False
                elif key in (ord("b"), ord("B")):
                    self.state = "plan"

            time.sleep(0.01)


def main() -> None:
    try:
        curses.wrapper(lambda scr: InstallerTUI(scr).run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
