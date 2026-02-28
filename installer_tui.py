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
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from panel_control.core import PanelManager
from panel_control.services import send_recovery_secret


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
    setup_domain: bool = False
    issue_ssl: bool = False
    deploy_web: bool = False
    preserve_db_on_update: bool = True
    run_node_app: bool = False
    primary_domain: str = ""
    web_source_path: str = ""
    web_git_url: str = ""
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
    Dependency("Certbot Apache plugin", "python3-certbot-apache", required=False),
    Dependency("UFW", "ufw", "ufw"),
    Dependency("FTP (vsftpd)", "vsftpd", "vsftpd", required=False),
    Dependency("SMTP (Postfix)", "postfix", "postfix", required=False),
    Dependency("fail2ban", "fail2ban", "fail2ban-server", required=False),
]

BASE_PACKAGES = [
    "apache2",
    "nodejs",
    "npm",
    "ca-certificates",
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
    if profile.issue_ssl:
        packages.append("python3-certbot-apache")
    if profile.deploy_web and profile.web_git_url.strip():
        packages.append("git")
    if profile.run_node_app:
        packages.append("build-essential")
    return sorted(set(packages))


def is_valid_domain(domain: str) -> bool:
    return bool(
        re.match(
            r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$",
            domain,
        )
    )


def is_valid_git_url(url: str) -> bool:
    return bool(re.match(r"^(https?|git)://\S+$", url))


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
    ]
    if profile.setup_domain and profile.primary_domain:
        domain = profile.primary_domain.lower().strip()
        webroot = f"/var/www/{domain}/public"
        service_name = f"panelctl-{domain}".replace(".", "-")
        service_path = f"/etc/systemd/system/{service_name}.service"
        local_source = os.path.abspath(profile.web_source_path.strip()) if profile.web_source_path else ""
        git_url = profile.web_git_url.strip()
        git_source = f"/tmp/panelctl-site-{domain}"
        source_path = git_source if git_url else local_source
        webroot_q = shlex.quote(webroot)
        source_q = shlex.quote(source_path) if source_path else ""
        git_url_q = shlex.quote(git_url) if git_url else "''"
        git_source_q = shlex.quote(git_source)
        keep_path = f"/tmp/panelctl-keep-{service_name}"
        keep_q = shlex.quote(keep_path)
        vhost_path = f"/etc/apache2/sites-available/{domain}.conf"
        if profile.run_node_app:
            vhost_conf = (
                f"cat > {vhost_path} <<'EOF'\n"
                "<VirtualHost *:80>\n"
                f"    ServerName {domain}\n"
                f"    ServerAlias www.{domain}\n"
                "    ProxyPreserveHost On\n"
                "    ProxyRequests Off\n"
                "    ProxyPass /.well-known/acme-challenge/ !\n"
                f"    Alias /.well-known/acme-challenge/ {webroot}/.well-known/acme-challenge/\n"
                "    <Directory "
                f"{webroot}/.well-known/acme-challenge/"
                ">\n"
                "        AllowOverride None\n"
                "        Require all granted\n"
                "    </Directory>\n"
                "    ProxyPass / http://127.0.0.1:3000/\n"
                "    ProxyPassReverse / http://127.0.0.1:3000/\n"
                f"    ErrorLog ${{APACHE_LOG_DIR}}/{domain}_error.log\n"
                f"    CustomLog ${{APACHE_LOG_DIR}}/{domain}_access.log combined\n"
                "</VirtualHost>\n"
                "EOF"
            )
        else:
            vhost_conf = (
                f"cat > {vhost_path} <<'EOF'\n"
                "<VirtualHost *:80>\n"
                f"    ServerName {domain}\n"
                f"    ServerAlias www.{domain}\n"
                f"    DocumentRoot {webroot}\n"
                "    <Directory "
                f"{webroot}"
                ">\n"
                "        AllowOverride All\n"
                "        Require all granted\n"
                "    </Directory>\n"
                f"    ErrorLog ${{APACHE_LOG_DIR}}/{domain}_error.log\n"
                f"    CustomLog ${{APACHE_LOG_DIR}}/{domain}_access.log combined\n"
                "</VirtualHost>\n"
                "EOF"
            )
        actions.extend(
            [
                PlanAction(
                    "domain-webroot",
                    f"Crear webroot para {domain}",
                    make_cmd(["mkdir", "-p", webroot]),
                    critical=False,
                ),
                PlanAction(
                    "domain-index",
                    f"Crear index de prueba para {domain}",
                    make_cmd(
                        [
                            "bash",
                            "-lc",
                            f"test -f {webroot}/index.html || echo '<h1>{domain} listo</h1>' > {webroot}/index.html",
                        ]
                    ),
                    critical=False,
                ),
                PlanAction(
                    "domain-vhost",
                    f"Crear vhost Apache para {domain}",
                    make_cmd(["bash", "-lc", vhost_conf]),
                ),
                PlanAction(
                    "domain-enable-site",
                    f"Habilitar sitio Apache {domain}",
                    make_cmd(["bash", "-lc", f"a2ensite {domain}.conf"]),
                    critical=False,
                ),
            ]
        )
        if profile.run_node_app:
            actions.append(
                PlanAction(
                    "domain-acme-dir",
                    f"Crear carpeta challenge ACME para {domain}",
                    make_cmd(["mkdir", "-p", f"{webroot}/.well-known/acme-challenge"]),
                    critical=False,
                )
            )
        if profile.deploy_web and source_path:
            deploy_cmd = (
                f"test -d {source_q} "
                f"&& mkdir -p {webroot_q} "
                f"&& find {webroot_q} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} + "
                f"&& cp -a {source_q}/. {webroot_q}/ "
                f"&& test -z {git_url_q} || rm -rf {git_source_q}"
            )
            if profile.preserve_db_on_update:
                deploy_cmd = (
                    f"test -d {source_q} "
                    f"&& mkdir -p {webroot_q} {webroot_q}/data "
                    f"&& rm -rf {keep_q} "
                    f"&& if [ -d {webroot_q}/public/uploads ]; then mkdir -p {keep_q}/public && cp -a {webroot_q}/public/uploads {keep_q}/public/uploads; fi "
                    f"&& find {webroot_q} -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {{}} + "
                    f"&& sh -lc 'for item in {source_q}/*; do "
                    "name=$(basename \"$item\"); "
                    "[ \"$name\" = \"data\" ] && continue; "
                    f"cp -a \"$item\" {webroot_q}/; "
                    "done' "
                    f"&& if [ -d {keep_q}/public/uploads ]; then mkdir -p {webroot_q}/public && rm -rf {webroot_q}/public/uploads && cp -a {keep_q}/public/uploads {webroot_q}/public/uploads; fi "
                    f"&& rm -rf {keep_q} "
                    f"&& test -z {git_url_q} || rm -rf {git_source_q}"
                )
            if git_url:
                actions.append(
                    PlanAction(
                        "domain-git-clone",
                        f"Clonar web desde {git_url}",
                        make_cmd(
                            [
                                "bash",
                                "-lc",
                                f"rm -rf {git_source_q} && git clone --depth 1 {git_url_q} {git_source_q}",
                            ]
                        ),
                    )
                )
            actions.append(
                PlanAction(
                    "domain-deploy",
                    f"Desplegar web desde {source_path}",
                    make_cmd(
                        [
                            "bash",
                            "-lc",
                            deploy_cmd,
                        ]
                    ),
                )
            )
        if profile.run_node_app and profile.deploy_web:
            actions.extend(
                [
                    PlanAction(
                        "node-install",
                        f"Instalar dependencias npm en {domain}",
                        make_cmd(
                            [
                                "bash",
                                "-lc",
                                f"cd {webroot_q} && npm install --include=dev",
                            ]
                        ),
                    ),
                    PlanAction(
                        "node-build",
                        f"Compilar assets frontend para {domain}",
                        make_cmd(
                            [
                                "bash",
                                "-lc",
                                f"cd {webroot_q} && npm run tw:build",
                            ]
                        ),
                    ),
                    PlanAction(
                        "node-prune",
                        f"Optimizar dependencias npm para {domain}",
                        make_cmd(
                            [
                                "bash",
                                "-lc",
                                f"cd {webroot_q} && npm prune --omit=dev",
                            ]
                        ),
                        critical=False,
                    ),
                    PlanAction(
                        "node-service-file",
                        f"Crear servicio systemd {service_name}",
                        make_cmd(
                            [
                                "bash",
                                "-lc",
                                (
                                    f"cat > {shlex.quote(service_path)} <<'EOF'\n"
                                    "[Unit]\n"
                                    f"Description=PanelCtl Node App ({domain})\n"
                                    "After=network.target\n\n"
                                    "[Service]\n"
                                    "Type=simple\n"
                                    "User=www-data\n"
                                    "Group=www-data\n"
                                    f"WorkingDirectory={webroot}\n"
                                    "Environment=NODE_ENV=production\n"
                                    "Environment=PORT=3000\n"
                                    "ExecStart=/usr/bin/node server.js\n"
                                    "Restart=always\n"
                                    "RestartSec=5\n\n"
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n"
                                    "EOF"
                                ),
                            ]
                        ),
                    ),
                    PlanAction(
                        "node-service-enable",
                        f"Habilitar servicio {service_name}",
                        make_cmd(
                            [
                                "bash",
                                "-lc",
                                f"systemctl daemon-reload && systemctl enable --now {shlex.quote(service_name)}",
                            ]
                        ),
                    ),
                ]
            )
        actions.append(
            PlanAction(
                "domain-perms",
                f"Ajustar permisos webroot {domain}",
                make_cmd(
                    [
                        "bash",
                        "-lc",
                        f"chown -R www-data:www-data {webroot_q}",
                    ]
                ),
                critical=False,
            )
        )
        if not profile.run_node_app:
            actions.append(
                PlanAction(
                    "domain-perms-static-modes",
                    f"Ajustar modos de archivos web estaticos {domain}",
                    make_cmd(
                        [
                            "bash",
                            "-lc",
                            (
                                f"find {webroot_q} -type d -exec chmod 755 {{}} + "
                                f"&& find {webroot_q} -type f -exec chmod 644 {{}} +"
                            ),
                        ]
                    ),
                    critical=False,
                )
            )
        if profile.deploy_web:
            actions = [a for a in actions if a.id != "domain-index"]
    actions.extend(
        [
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
    )
    if profile.issue_ssl and profile.primary_domain and profile.admin_email:
        domain = profile.primary_domain.lower().strip()
        actions.append(
            PlanAction(
                "certbot-domain",
                f"Emitir SSL Let's Encrypt para {domain}",
                make_cmd(
                    [
                        "bash",
                        "-lc",
                        f"certbot --apache -d {domain} --non-interactive --agree-tos --redirect -m {profile.admin_email}",
                    ]
                ),
                critical=False,
            )
        )
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
        self.auth = PanelManager()
        self.auth_store = self.auth.store
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

    def prompt_text(self, prompt: str, initial: str = "", hidden: bool = False) -> str:
        h, w = self.screen.getmaxyx()
        y = max(0, h - 1)
        prefix = f"{prompt}: "
        max_len = max(1, w - len(prefix) - 1)
        self.screen.move(y, 0)
        self.screen.clrtoeol()
        self.screen.addnstr(y, 0, prefix, w - 1, curses.A_BOLD)
        if not hidden:
            self.screen.addnstr(y, len(prefix), initial, w - len(prefix) - 1)
            self.screen.move(y, min(w - 1, len(prefix) + len(initial)))
            curses.echo()
        else:
            curses.noecho()
            self.screen.move(y, len(prefix))
        curses.curs_set(1)
        try:
            value = self.screen.getstr(y, len(prefix), max_len)
            decoded = value.decode("utf-8", errors="ignore").strip()
            return decoded or initial
        finally:
            curses.noecho()
            curses.curs_set(0)

    def panel_password_hash(self, password: str) -> str:
        return self.auth.hash_panel_password(password)

    def ensure_panel_login(self) -> bool:
        if self.auth.has_panel_credentials():
            return True

        self.screen.erase()
        self.draw_header("Configurar acceso", "Primera ejecucion: crea usuario y password del panel")
        self.screen.refresh()
        username = self.prompt_text("Usuario admin", "admin").strip()
        password = self.prompt_text("Password admin", hidden=True)
        confirm = self.prompt_text("Repetir password", hidden=True)
        if not username:
            self.message = "Usuario admin obligatorio."
            return False
        if len(password) < 8:
            self.message = "Password admin minimo 8 caracteres."
            return False
        if password != confirm:
            self.message = "Las passwords no coinciden."
            return False
        self.auth.set_panel_credentials(username, password)
        self.message = "Acceso inicial creado."
        return True

    def authenticate(self) -> bool:
        self.screen.erase()
        self.draw_header("Login instalador", "Usuario RECUPERAR para resetear acceso por email/WhatsApp")
        self.screen.refresh()
        username = self.prompt_text("Usuario")
        if username.lower() == "recuperar":
            return self.recover_panel_access()
        password = self.prompt_text("Password", hidden=True)
        auth = self.auth.authenticate_panel(username, password)
        if auth.get("ok"):
            role = self.auth.get_panel_role()
            if role != "superadmin":
                self.message = "El instalador requiere rol superadmin."
                return False
            if auth.get("force_password_change"):
                self.message = "Debes cambiar la password temporal."
                return self.force_password_change(username)
            self.message = f"Sesion iniciada: {username}"
            return True
        self.message = "Login invalido."
        return False

    def recover_panel_access(self) -> bool:
        email, whatsapp = self.auth.get_recovery_settings()
        if whatsapp:
            masked = self.auth.mask_phone(whatsapp)
            check = self.prompt_text(f"Confirmar WhatsApp ({masked})")
            if not self.auth.recovery_whatsapp_matches(check):
                self.message = "WhatsApp de recovery invalido."
                return False
        username = self.auth.get_panel_username("admin")
        temp_password = self.auth.issue_temporary_password(username)
        result = send_recovery_secret(email, whatsapp, temp_password, label="Clave temporal NicePanel")
        self.message = result.logs[-1] if result.logs else "Clave temporal enviada."
        if not result.ok:
            return False
        self.message = "Clave temporal enviada. Inicia sesion con ella y cambia tu password."
        return False

    def force_password_change(self, username: str) -> bool:
        password = self.prompt_text("Nueva password", hidden=True)
        confirm = self.prompt_text("Repetir password", hidden=True)
        if len(password) < 8:
            self.message = "Password admin minimo 8 caracteres."
            return False
        if password != confirm:
            self.message = "Las passwords no coinciden."
            return False
        self.auth.set_panel_credentials(username, password, role=self.auth.get_panel_role())
        self.message = "Password actualizada. Sesion normalizada."
        return True

    def set_profile_value(self) -> None:
        options = [
            "DNS (bind9)",
            "FTP (vsftpd)",
            "Email (postfix+dkim)",
            "Fail2ban",
            "Configurar dominio Apache",
            "Emitir SSL (certbot)",
            "Desplegar web desde carpeta",
            "Actualizar sin tocar DB/Uploads",
            "Ejecutar app Node (systemd+proxy)",
            "Dominio principal",
            "Ruta proyecto web",
            "URL Git web",
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
        elif selected == "Configurar dominio Apache":
            self.profile.setup_domain = not self.profile.setup_domain
        elif selected == "Emitir SSL (certbot)":
            self.profile.issue_ssl = not self.profile.issue_ssl
        elif selected == "Desplegar web desde carpeta":
            self.profile.deploy_web = not self.profile.deploy_web
        elif selected == "Actualizar sin tocar DB/Uploads":
            self.profile.preserve_db_on_update = not self.profile.preserve_db_on_update
        elif selected == "Ejecutar app Node (systemd+proxy)":
            self.profile.run_node_app = not self.profile.run_node_app
        elif selected == "Dominio principal":
            value = self.prompt_text("Dominio principal", self.profile.primary_domain)
            self.profile.primary_domain = value.lower().strip()
        elif selected == "Ruta proyecto web":
            self.profile.web_source_path = self.prompt_text(
                "Ruta proyecto web",
                self.profile.web_source_path,
            ).strip()
        elif selected == "URL Git web":
            self.profile.web_git_url = self.prompt_text(
                "URL Git web",
                self.profile.web_git_url,
            ).strip()
        elif selected == "Hostname":
            self.profile.hostname = self.prompt_text("Hostname", self.profile.hostname)
        elif selected == "Email admin":
            self.profile.admin_email = self.prompt_text("Email admin", self.profile.admin_email)

    def validate_profile(self) -> Tuple[bool, str]:
        if self.profile.primary_domain and not is_valid_domain(self.profile.primary_domain):
            return False, "Dominio invalido (ej: ropadesanlorenzo.com)."
        if self.profile.setup_domain and not self.profile.primary_domain:
            return False, "Define 'Dominio principal' para crear vhost."
        if self.profile.deploy_web and not self.profile.setup_domain:
            return False, "Activa 'Configurar dominio Apache' para desplegar web."
        if self.profile.run_node_app and not self.profile.setup_domain:
            return False, "Activa 'Configurar dominio Apache' para modo Node."
        if self.profile.run_node_app and not self.profile.deploy_web:
            return False, "Activa 'Desplegar web desde carpeta' para modo Node."
        if self.profile.deploy_web and not self.profile.web_source_path and not self.profile.web_git_url:
            return False, "Define 'Ruta proyecto web' o 'URL Git web'."
        if self.profile.web_source_path and not os.path.isdir(self.profile.web_source_path):
            return False, "Ruta proyecto web no existe o no es carpeta."
        if self.profile.web_git_url and not is_valid_git_url(self.profile.web_git_url):
            return False, "URL Git web invalida."
        if self.profile.issue_ssl and not self.profile.setup_domain:
            return False, "Activa 'Configurar dominio Apache' antes de SSL."
        if self.profile.issue_ssl and not self.profile.admin_email:
            return False, "Email admin requerido para certbot."
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
        self.draw_header("NicePanel - Instalador", "Fase 0 - Aviso")
        lines = [
            "    _  ___         ___                __",
            "   / |/ (_)______ / _ \\___ ____  ___ / /",
            "  /    / / __/ -_) ___/ _ `/ _ \\/ -_) /",
            " /_/|_/_/\\__/\\__/_/   \\_,_/_//_/\\__/_/",
            "",
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
            ("Configurar dominio Apache", self.profile.setup_domain),
            ("Emitir SSL (certbot)", self.profile.issue_ssl),
            ("Desplegar web desde carpeta", self.profile.deploy_web),
            ("Actualizar sin tocar DB/Uploads", self.profile.preserve_db_on_update),
            ("Ejecutar app Node (systemd+proxy)", self.profile.run_node_app),
            (f"Dominio principal: {self.profile.primary_domain or '-'}", None),
            (f"Ruta proyecto web: {self.profile.web_source_path or '-'}", None),
            (f"URL Git web: {self.profile.web_git_url or '-'}", None),
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
        else:
            footer = "Teclas: s resumen | b plan | q salir"
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

        while self.running and not self.ensure_panel_login():
            pass
        while self.running and not self.authenticate():
            pass

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
                    self.profile_selection = min(13, self.profile_selection + 1)
                elif key in (ord(" "), curses.KEY_ENTER, 10, 13):
                    self.set_profile_value()
                elif key in (ord("c"), ord("C")):
                    ok, msg = self.validate_profile()
                    if ok:
                        self.actions = build_plan(self.profile)
                        self.logs = []
                        self.apply_done = False
                        self.apply_ok = False
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
