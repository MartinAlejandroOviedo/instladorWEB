"""Post-install control panel TUI."""

from __future__ import annotations

import curses
import hashlib
from typing import List

from .core import PanelManager
from .services import (
    DNSConfig,
    WebUpdateConfig,
    apply_dns,
    apply_ftp,
    apply_optimization,
    dns_apply_preview,
    download_web_update,
    ftp_apply_preview,
    hash_password_for_system,
    import_bind_zones,
    list_apache_confs,
    list_apache_modules,
    list_apache_sites,
    mail_apply_preview,
    optimization_preview,
    recommend_apache_profile,
    replace_web_update,
    send_recovery_secret,
    set_apache_conf,
    set_apache_module,
    set_apache_site,
    web_update_preflight,
)
from .validators import (
    is_valid_domain,
    is_valid_email,
    is_valid_hostname_label,
    is_valid_ipv4,
    is_valid_ipv4_list,
    is_valid_record_type,
)


class ControlPanelTUI:
    def __init__(self, screen: "curses.window") -> None:
        self.screen = screen
        self.manager = PanelManager()
        self.store = self.manager.store
        self.running = True
        self.state = "menu"
        self.menu_index = 0
        self.message = "Panel cargado."
        self.apply_logs: List[str] = []
        self.optimization_logs: List[str] = []
        self.web_update_logs: List[str] = []
        self.web_update_config = WebUpdateConfig(repo_url="")
        self.web_update_downloaded = False
        self.web_update_commit = ""
        self.session_role = self.manager.get_panel_role()

    def prompt_text(self, prompt: str, initial: str = "", hidden: bool = False) -> str:
        h, w = self.screen.getmaxyx()
        y = h - 2
        self.screen.move(y, 1)
        self.screen.clrtoeol()
        label = f"{prompt}"
        hint = f" [{initial}]" if initial and not hidden else ""
        self.screen.addnstr(y, 1, f"{label}{hint}: ", w - 2)
        if hidden:
            curses.noecho()
        else:
            curses.echo()
        curses.curs_set(1)
        try:
            start_x = min(w - 2, len(label) + len(hint) + 4)
            max_len = max(1, w - start_x - 2)
            raw = self.screen.getstr(y, start_x, max_len)
            value = raw.decode("utf-8", errors="ignore").strip()
            return value or initial
        finally:
            curses.noecho()
            curses.curs_set(0)

    def panel_password_hash(self, password: str) -> str:
        return self.manager.hash_panel_password(password)

    def draw_header(self, title: str, subtitle: str) -> None:
        h, w = self.screen.getmaxyx()
        self.screen.addnstr(0, 2, title, w - 4, curses.A_BOLD)
        role_suffix = f" | rol: {self.session_role}"
        self.screen.addnstr(1, 2, f"{subtitle}{role_suffix}", w - 4, curses.A_DIM)

    def has_permission(self, permission: str) -> bool:
        return self.manager.has_permission(self.session_role, permission)

    def require_permission(self, permission: str, message: str = "Operacion no permitida para tu rol.") -> bool:
        if self.has_permission(permission):
            return True
        self.message = message
        return False

    def get_dns_config(self) -> DNSConfig:
        return self.manager.get_dns_config()

    def save_dns_config(self, config: DNSConfig) -> None:
        self.manager.save_dns_config(config)

    def get_recovery_settings(self) -> tuple[str, str]:
        return self.manager.get_recovery_settings()

    def save_recovery_settings(self, email: str, whatsapp: str) -> None:
        self.manager.save_recovery_settings(email, whatsapp)

    def ensure_panel_login(self) -> bool:
        if self.manager.has_panel_credentials():
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
        self.manager.set_panel_credentials(username, password)
        self.message = "Acceso inicial creado."
        return True

    def recover_panel_access(self) -> bool:
        email, whatsapp = self.get_recovery_settings()
        if whatsapp:
            masked = self.manager.mask_phone(whatsapp)
            check = self.prompt_text(f"Confirmar WhatsApp ({masked})")
            if not self.manager.recovery_whatsapp_matches(check):
                self.message = "WhatsApp de recovery invalido."
                return False
        username = self.manager.get_panel_username("admin")
        temp_password = self.manager.issue_temporary_password(username)
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
        self.manager.set_panel_credentials(username, password, role=self.session_role)
        self.message = "Password actualizada. Sesion normalizada."
        return True

    def authenticate(self) -> bool:
        self.screen.erase()
        self.draw_header("Login panel", "Usuario RECUPERAR para resetear acceso por email/WhatsApp")
        self.screen.refresh()
        username = self.prompt_text("Usuario")
        if username.lower() == "recuperar":
            return self.recover_panel_access()
        password = self.prompt_text("Password", hidden=True)
        auth = self.manager.authenticate_panel(username, password)
        if auth.get("ok"):
            self.session_role = str(auth["role"])
            if auth.get("force_password_change"):
                self.message = "Debes cambiar la password temporal."
                return self.force_password_change(username)
            self.message = f"Sesion iniciada: {username}"
            return True
        self.message = "Login invalido."
        return False

    def update_panel_login(self) -> None:
        current_user = self.manager.get_panel_username("admin")
        username = self.prompt_text("Usuario admin", current_user).strip()
        password = self.prompt_text("Nuevo password", hidden=True)
        confirm = self.prompt_text("Repetir password", hidden=True)
        if not username:
            self.message = "Usuario admin obligatorio."
            return
        if len(password) < 8:
            self.message = "Password admin minimo 8 caracteres."
            return
        if password != confirm:
            self.message = "Las passwords no coinciden."
            return
        self.manager.set_panel_credentials(username, password)
        self.message = "Credenciales del panel actualizadas."

    def draw_menu(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        domain_count = len(self.store.list_domains())
        dns_count, ftp_count, mail_count = self.store.get_counts()
        self.draw_header("NicePanel - Panel de Control", "Instalador + mini cPanel opensource")
        options = [
            f"Dominios ({domain_count})",
            f"DNS records ({dns_count})",
            "DNS server",
            "Optimizar",
            f"FTP accounts ({ftp_count})",
            f"Mail accounts ({mail_count})",
            "Seguridad panel",
            "Apply preview",
            "Apply real now",
            "Actualizar web",
            "Salir",
        ]
        for i, label in enumerate(options):
            attr = curses.A_REVERSE if i == self.menu_index else curses.A_NORMAL
            self.screen.addnstr(4 + i, 2, f"{'>' if i == self.menu_index else ' '} {label}", w - 4, attr)
        self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)
        self.screen.addnstr(h - 2, 2, "Teclas: flechas mover | enter abrir | q salir", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_table(self, title: str, rows: List[str], footer: str, subtitle: str = "a agregar | d eliminar | b volver") -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header(title, subtitle)
        max_rows = h - 7
        if not rows:
            self.screen.addnstr(4, 2, "(sin registros)", w - 4, curses.A_DIM)
        for i, row in enumerate(rows[:max_rows]):
            self.screen.addnstr(4 + i, 2, row, w - 4)
        self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)
        self.screen.addnstr(h - 2, 2, footer, w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_domains(self) -> None:
        rows = self.store.list_domains()
        lines = []
        for row in rows:
            ns1 = row["ns1_hostname"] or "(global)"
            ns2 = row["ns2_hostname"] or "-"
            lines.append(f"[{row['id']:03d}] {row['domain']} ns1={ns1} ns2={ns2}")
        self.draw_table(
            "Dominios",
            lines,
            "Teclas: a agregar | c configurar DNS dominio | d eliminar | i importar bind | b volver",
            subtitle="Dominios y nameservers por zona",
        )

    def draw_dns(self) -> None:
        rows = self.store.list_dns()
        lines = [f"[{r['id']:03d}] {r['zone']} {r['name']} {r['type']} {r['value']} ttl={r['ttl']}" for r in rows]
        self.draw_table(
            "DNS Records",
            lines,
            "Teclas: a agregar | d eliminar | i importar bind | b volver",
            subtitle="Registros actuales de las zonas",
        )

    def draw_dns_server(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        config = self.get_dns_config()
        self.draw_header("DNS Server", "Configuracion global de bind9")
        lines = [
            f"Default NS1: {config.ns1_hostname} -> {config.ns1_ipv4}",
            f"Default NS2: {config.ns2_hostname or '(sin definir)'} -> {config.ns2_ipv4 or '-'}",
            f"Listen on: {config.listen_on}",
            f"Forwarders: {config.forwarders or '(sin forwarders)'}",
            f"Recursion: {'si' if config.allow_recursion else 'no'}",
            "",
            "Los dominios pueden sobrescribir NS1/NS2 en la pantalla Dominios.",
            "",
            "c configurar valores",
            "b volver",
        ]
        for i, line in enumerate(lines[: h - 6]):
            self.screen.addnstr(4 + i, 2, line, w - 4)
        self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)
        self.screen.addnstr(h - 2, 2, "Teclas: c configurar | b volver", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_ftp(self) -> None:
        rows = self.store.list_ftp()
        lines = [f"[{r['id']:03d}] {r['username']} -> {r['home_dir']}" for r in rows]
        self.draw_table("FTP Accounts", lines, "Teclas: a agregar | d eliminar | b volver")

    def draw_mail(self) -> None:
        rows = self.store.list_mail()
        lines = [f"[{r['id']:03d}] {r['address']}" for r in rows]
        self.draw_table("Mail Accounts", lines, "Teclas: a agregar | d eliminar | b volver")

    def draw_optimization(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        modules = list_apache_modules()
        recommendations = recommend_apache_profile()
        self.draw_header("Optimizar", "Compresion, cache y ajustes seguros para Apache")
        lines = [
            "Incluye:",
            "- compresion gzip/deflate para texto",
            "- cache headers para estaticos",
            "- keepalive moderado",
            "",
            "Modulos Apache comunes:",
        ]
        for item in modules:
            status = "ON " if item["enabled"] else "OFF"
            lines.append(f"- [{status}] {item['module']}: {item['description']}")
        lines += [
            "",
            "Recomendaciones detectadas:",
        ]
        for item in recommendations:
            lines.append(f"- {item}")
        lines += [
            "",
            "No incluye:",
            "- balanceo multi-servidor",
            "- colas/hilos artificiales para requests",
            "",
            "Ultimos logs:",
        ] + (self.optimization_logs[-max(0, h - 20) :] or ["Sin ejecucion aun."])
        for i, line in enumerate(lines[: h - 6]):
            self.screen.addnstr(4 + i, 2, line, w - 4)
        self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)
        self.screen.addnstr(h - 2, 2, "Teclas: r optimizar | e/x modulo | s sitios | f confs | b volver", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_apache_sites(self) -> None:
        rows = list_apache_sites()
        lines = [f"[{'ON ' if row['enabled'] else 'OFF'}] {row['name']}" for row in rows]
        self.draw_table(
            "Apache Sites",
            lines,
            "Teclas: e habilitar sitio | x deshabilitar sitio | b volver",
            subtitle="Sites disponibles en sites-available",
        )

    def draw_apache_confs(self) -> None:
        rows = list_apache_confs()
        lines = [f"[{'ON ' if row['enabled'] else 'OFF'}] {row['name']}" for row in rows]
        self.draw_table(
            "Apache Confs",
            lines,
            "Teclas: e habilitar conf | x deshabilitar conf | b volver",
            subtitle="Confs disponibles en conf-available",
        )

    def toggle_apache_module(self, enabled: bool) -> None:
        module = self.prompt_text("Modulo Apache", "rewrite").strip()
        if not module:
            self.message = "Modulo requerido."
            return
        result = set_apache_module(module, enabled)
        self.optimization_logs = result.logs
        self.message = "Modulo actualizado." if result.ok else "Cambio de modulo con errores."

    def toggle_apache_site(self, enabled: bool) -> None:
        site = self.prompt_text("Site Apache", "000-default.conf").strip()
        if not site:
            self.message = "Site requerido."
            return
        result = set_apache_site(site, enabled)
        self.optimization_logs = result.logs
        self.message = "Site actualizado." if result.ok else "Cambio de site con errores."

    def toggle_apache_conf(self, enabled: bool) -> None:
        conf = self.prompt_text("Conf Apache", "panelctl-optimization.conf").strip()
        if not conf:
            self.message = "Conf requerida."
            return
        result = set_apache_conf(conf, enabled)
        self.optimization_logs = result.logs
        self.message = "Conf actualizada." if result.ok else "Cambio de conf con errores."

    def draw_security(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        username = self.manager.get_panel_username("admin")
        recovery_email, recovery_whatsapp = self.get_recovery_settings()
        self.draw_header("Seguridad panel", "Acceso y recuperacion")
        lines = [
            f"Usuario actual: {username}",
            f"Rol actual: {self.session_role}",
            f"Recovery email: {recovery_email or '(sin definir)'}",
            f"Recovery WhatsApp: {recovery_whatsapp or '(sin definir)'}",
            "",
            "c cambiar usuario/password",
            "p cambiar rol",
            "r configurar recovery",
            "k probar recovery ahora",
            "b volver",
        ]
        for i, line in enumerate(lines[: h - 6]):
            self.screen.addnstr(4 + i, 2, line, w - 4)
        self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)
        self.screen.addnstr(h - 2, 2, "Teclas: c credenciales | p rol | r recovery | k probar | b volver", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def update_panel_role(self) -> None:
        if not self.require_permission("security.write"):
            return
        current_role = self.manager.get_panel_role()
        role = self.prompt_text("Rol (superadmin/operator)", current_role).strip().lower()
        normalized = self.manager.normalize_role(role)
        self.manager.set_panel_role(normalized)
        self.session_role = normalized
        self.message = f"Rol actualizado: {normalized}"

    def draw_apply_preview(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Apply Preview", "Comandos previstos para integrar servicios")
        lines = (
            ["[DNS SERVER]"]
            + dns_apply_preview()
            + [""]
            + ["[OPTIMIZAR]"]
            + optimization_preview()
            + [""]
            + ["[FTP]"]
            + ftp_apply_preview()
            + [""]
            + ["[MAIL]"]
            + mail_apply_preview()
        )
        for i, line in enumerate(lines[: h - 6]):
            self.screen.addnstr(4 + i, 2, line, w - 4)
        self.screen.addnstr(h - 2, 2, "Teclas: b volver", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_apply_run(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Apply Real", "Resultados de aplicacion operativa")
        max_rows = h - 6
        lines = self.apply_logs or ["Sin ejecucion aun."]
        for i, line in enumerate(lines[-max_rows:]):
            self.screen.addnstr(4 + i, 2, line, w - 4)
        self.screen.addnstr(h - 2, 2, "Teclas: r aplicar ahora | b volver", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_web_update(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Actualizar web", "Descarga repo Git y despliega sobre el proyecto preservando DB/uploads")
        lines = [
            f"Repo: {self.web_update_config.repo_url or '(sin definir)'}",
            f"Branch: {self.web_update_config.branch}",
            f"Destino: {self.web_update_config.project_dir}",
            f"Servicio: {self.web_update_config.service_name or '(sin restart)'}",
            f"Backups: {self.web_update_config.backup_dir}",
            f"Temporal: {self.web_update_config.temp_dir}",
            f"Descargado: {'si' if self.web_update_downloaded else 'no'}",
            f"Commit: {self.web_update_commit or '-'}",
            "",
            "c configurar + preflight",
            "d descargar repo",
            "r backup + reemplazar",
            "b volver",
            "",
            "Ultimos logs:",
        ]
        max_rows = h - 6
        log_rows = self.web_update_logs[-max(0, max_rows - len(lines)) :]
        for i, line in enumerate((lines + log_rows)[:max_rows]):
            self.screen.addnstr(4 + i, 2, line, w - 4)
        self.screen.addnstr(h - 2, 2, "Teclas: c configurar | d descargar | r reemplazar | b volver", w - 4, curses.A_BOLD)
        self.screen.refresh()

    def configure_web_update(self) -> None:
        repo_url = self.prompt_text("Repo Git", self.web_update_config.repo_url or "https://github.com/usuario/carthtml.git")
        branch = self.prompt_text("Branch", self.web_update_config.branch or "main")
        project_dir = self.prompt_text("Destino proyecto", self.web_update_config.project_dir or "/var/www/carthtml")
        service_name = self.prompt_text("Servicio systemd", self.web_update_config.service_name or "carthtml")
        backup_dir = self.prompt_text("Directorio backups", self.web_update_config.backup_dir or "/var/backups/carthtml")
        temp_dir = self.prompt_text("Directorio temporal", self.web_update_config.temp_dir or "/tmp/carthtml-update")
        self.web_update_config = WebUpdateConfig(
            repo_url=repo_url.strip(),
            branch=branch.strip() or "main",
            project_dir=project_dir.strip() or "/var/www/carthtml",
            service_name=service_name.strip(),
            backup_dir=backup_dir.strip() or "/var/backups/carthtml",
            temp_dir=temp_dir.strip() or "/tmp/carthtml-update",
        )
        result = web_update_preflight(self.web_update_config)
        self.web_update_logs = result.logs
        self.message = "Preflight OK." if result.ok else "Preflight con errores."
        if not result.ok:
            self.web_update_downloaded = False
            self.web_update_commit = ""

    def configure_dns_server(self) -> None:
        current = self.get_dns_config()
        ns1_hostname = self.prompt_text("Default NS1 FQDN", current.ns1_hostname).lower().rstrip(".")
        ns1_ipv4 = self.prompt_text("Default NS1 IPv4", current.ns1_ipv4)
        ns2_hostname = self.prompt_text("Default NS2 FQDN", current.ns2_hostname).lower().rstrip(".")
        ns2_ipv4 = self.prompt_text("Default NS2 IPv4", current.ns2_ipv4)
        listen_on = self.prompt_text("Listen on (any o ip,ip)", current.listen_on)
        forwarders = self.prompt_text("Forwarders (ip,ip)", current.forwarders)
        recursion_raw = self.prompt_text("Recursion (si/no)", "si" if current.allow_recursion else "no").lower()

        if not is_valid_domain(ns1_hostname):
            self.message = "NS1 invalido. Usa FQDN completo."
            return
        if not is_valid_ipv4(ns1_ipv4):
            self.message = "IPv4 de NS1 invalida."
            return
        if ns2_hostname and not is_valid_domain(ns2_hostname):
            self.message = "NS2 invalido. Usa FQDN completo."
            return
        if ns2_ipv4 and not is_valid_ipv4(ns2_ipv4):
            self.message = "IPv4 de NS2 invalida."
            return
        if ns2_hostname and not ns2_ipv4:
            self.message = "Falta IPv4 para NS2."
            return
        if ns2_ipv4 and not ns2_hostname:
            self.message = "Falta FQDN para NS2."
            return
        if listen_on.strip().lower() != "any" and not is_valid_ipv4_list(listen_on):
            self.message = "Listen on invalido."
            return
        if not is_valid_ipv4_list(forwarders):
            self.message = "Forwarders invalidos."
            return
        allow_recursion = recursion_raw in {"si", "s", "yes", "y", "1"}
        self.save_dns_config(
            DNSConfig(
                ns1_hostname=ns1_hostname,
                ns1_ipv4=ns1_ipv4,
                ns2_hostname=ns2_hostname,
                ns2_ipv4=ns2_ipv4,
                listen_on=listen_on.strip() or "any",
                forwarders=forwarders.strip(),
                allow_recursion=allow_recursion,
            )
        )
        self.message = "Configuracion DNS global guardada."

    def configure_recovery(self) -> None:
        current_email, current_whatsapp = self.get_recovery_settings()
        email = self.prompt_text("Recovery email", current_email).strip().lower()
        whatsapp = self.prompt_text("Recovery WhatsApp", current_whatsapp).strip()
        if email and not is_valid_email(email):
            self.message = "Recovery email invalido."
            return
        self.save_recovery_settings(email, whatsapp)
        self.message = "Recovery configurado."

    def configure_domain_dns(self) -> None:
        raw = self.prompt_text("ID dominio a configurar")
        try:
            item_id = int(raw)
        except ValueError:
            self.message = "ID invalido."
            return
        row = self.store.get_domain(item_id)
        if not row:
            self.message = "Dominio no encontrado."
            return

        ns1_hostname = self.prompt_text("NS1 FQDN", row["ns1_hostname"]).lower().rstrip(".")
        ns1_ipv4 = self.prompt_text("NS1 IPv4", row["ns1_ipv4"])
        ns2_hostname = self.prompt_text("NS2 FQDN", row["ns2_hostname"]).lower().rstrip(".")
        ns2_ipv4 = self.prompt_text("NS2 IPv4", row["ns2_ipv4"])
        if ns1_hostname and not is_valid_domain(ns1_hostname):
            self.message = "NS1 invalido."
            return
        if ns1_ipv4 and not is_valid_ipv4(ns1_ipv4):
            self.message = "IPv4 de NS1 invalida."
            return
        if ns2_hostname and not is_valid_domain(ns2_hostname):
            self.message = "NS2 invalido."
            return
        if ns2_ipv4 and not is_valid_ipv4(ns2_ipv4):
            self.message = "IPv4 de NS2 invalida."
            return
        if ns2_hostname and not ns2_ipv4:
            self.message = "Falta IPv4 para NS2."
            return
        if ns2_ipv4 and not ns2_hostname:
            self.message = "Falta FQDN para NS2."
            return

        self.manager.update_domain(
            item_id,
            {
                "domain": str(row["domain"]),
                "ns1_hostname": ns1_hostname,
                "ns1_ipv4": ns1_ipv4,
                "ns2_hostname": ns2_hostname,
                "ns2_ipv4": ns2_ipv4,
            },
        )
        self.message = f"DNS del dominio {row['domain']} actualizado."

    def import_current_bind(self) -> None:
        if not self.require_permission("ops.execute"):
            return
        result = import_bind_zones()
        self.apply_logs = result.logs
        if not result.ok:
            self.message = "No se pudo importar BIND actual."
            return
        self.store.replace_domains(
            [
                (
                    str(item["domain"]),
                    str(item.get("ns1_hostname", "")),
                    str(item.get("ns1_ipv4", "")),
                    str(item.get("ns2_hostname", "")),
                    str(item.get("ns2_ipv4", "")),
                )
                for item in result.domains
            ]
        )
        self.store.replace_dns_records(
            [
                (
                    str(item["zone"]),
                    str(item["name"]),
                    str(item["type"]),
                    str(item["value"]),
                    int(item["ttl"]),
                )
                for item in result.records
            ]
        )
        self.message = f"DNS importado desde BIND: {len(result.domains)} zonas."

    def add_domain(self) -> None:
        domain = self.prompt_text("Dominio", "").lower().strip()
        if not is_valid_domain(domain):
            self.message = "Dominio invalido."
            return
        try:
            self.manager.create_domain({"domain": domain})
        except Exception as exc:
            self.message = f"No se pudo agregar dominio: {exc}"
            return
        self.message = "Dominio agregado."

    def add_dns(self) -> None:
        domains = [str(row["domain"]) for row in self.store.list_domains()]
        zone_default = domains[0] if len(domains) == 1 else ""
        zone = self.prompt_text("Zone (ej: ropadesanlorenzo.com)", zone_default).lower()
        name = self.prompt_text("Host (@, www, api)")
        rtype = self.prompt_text("Type (A/AAAA/CNAME/MX/TXT)").upper()
        value = self.prompt_text("Value")
        ttl_raw = self.prompt_text("TTL", "300")
        if not is_valid_domain(zone):
            self.message = "Zone invalida."
            return
        if not is_valid_hostname_label(name):
            self.message = "Host invalido."
            return
        if not is_valid_record_type(rtype):
            self.message = "Tipo de record invalido."
            return
        try:
            ttl = int(ttl_raw)
            if ttl < 60:
                raise ValueError
        except ValueError:
            self.message = "TTL invalido."
            return
        self.manager.create_dns({"zone": zone, "name": name, "type": rtype, "value": value, "ttl": ttl})
        self.message = "Record DNS agregado."

    def add_ftp(self) -> None:
        username = self.prompt_text("Usuario FTP")
        home_dir = self.prompt_text("Home dir", f"/var/www/{username}")
        password = self.prompt_text("Password FTP", hidden=True)
        if len(username) < 3:
            self.message = "Usuario FTP demasiado corto."
            return
        if len(password) < 8:
            self.message = "Password FTP minimo 8 caracteres."
            return
        try:
            password_hash = hash_password_for_system(password)
        except Exception as exc:
            self.message = f"No se pudo hashear password: {exc}"
            return
        self.store.add_ftp(username, home_dir, password_hash)
        self.message = "Cuenta FTP agregada (lista para aplicar)."

    def add_mail(self) -> None:
        address = self.prompt_text("Cuenta mail (user@dominio)").lower()
        password = self.prompt_text("Password", hidden=True)
        if not is_valid_email(address):
            self.message = "Email invalido."
            return
        if len(password) < 8:
            self.message = "Password minimo 8 caracteres."
            return
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        self.store.add_mail(address, password_hash)
        self.message = "Cuenta mail agregada (registro local)."

    def delete_by_id(self, kind: str) -> None:
        raw = self.prompt_text("ID a eliminar")
        try:
            item_id = int(raw)
        except ValueError:
            self.message = "ID invalido."
            return
        if kind == "domain":
            deleted = self.store.delete_domain(item_id)
        elif kind == "dns":
            deleted = self.store.delete_dns(item_id)
        elif kind == "ftp":
            deleted = self.store.delete_ftp(item_id)
        else:
            deleted = self.store.delete_mail(item_id)
        self.message = "Registro eliminado." if deleted else "ID no encontrado."

    def run(self) -> None:
        curses.curs_set(0)
        self.screen.keypad(True)

        while self.running and not self.ensure_panel_login():
            pass
        while self.running and not self.authenticate():
            pass

        while self.running:
            if self.state == "menu":
                self.draw_menu()
            elif self.state == "domains":
                self.draw_domains()
            elif self.state == "dns":
                self.draw_dns()
            elif self.state == "dns_server":
                self.draw_dns_server()
            elif self.state == "optimization":
                self.draw_optimization()
            elif self.state == "apache_sites":
                self.draw_apache_sites()
            elif self.state == "apache_confs":
                self.draw_apache_confs()
            elif self.state == "ftp":
                self.draw_ftp()
            elif self.state == "mail":
                self.draw_mail()
            elif self.state == "security":
                self.draw_security()
            elif self.state == "preview":
                self.draw_apply_preview()
            elif self.state == "apply_run":
                self.draw_apply_run()
            elif self.state == "web_update":
                self.draw_web_update()

            key = self.screen.getch()
            if key in (3, ord("q"), ord("Q")):
                if self.state == "menu":
                    self.running = False
                else:
                    self.state = "menu"
                continue

            if self.state == "menu":
                if key == curses.KEY_UP:
                    self.menu_index = max(0, self.menu_index - 1)
                elif key == curses.KEY_DOWN:
                    self.menu_index = min(10, self.menu_index + 1)
                elif key in (10, 13, curses.KEY_ENTER):
                    if self.menu_index == 0:
                        self.state = "domains"
                    elif self.menu_index == 1:
                        self.state = "dns"
                    elif self.menu_index == 2:
                        self.state = "dns_server"
                    elif self.menu_index == 3:
                        self.state = "optimization"
                    elif self.menu_index == 4:
                        if self.require_permission("accounts.read"):
                            self.state = "ftp"
                    elif self.menu_index == 5:
                        if self.require_permission("accounts.read"):
                            self.state = "mail"
                    elif self.menu_index == 6:
                        self.state = "security"
                    elif self.menu_index == 7:
                        self.state = "preview"
                    elif self.menu_index == 8:
                        self.state = "apply_run"
                    elif self.menu_index == 9:
                        self.state = "web_update"
                    else:
                        self.running = False
            elif self.state == "domains":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("a"), ord("A")):
                    if not self.require_permission("domains.write"):
                        continue
                    self.add_domain()
                elif key in (ord("c"), ord("C")):
                    if not self.require_permission("domains.write"):
                        continue
                    self.configure_domain_dns()
                elif key in (ord("d"), ord("D")):
                    if not self.require_permission("domains.write"):
                        continue
                    self.delete_by_id("domain")
                elif key in (ord("i"), ord("I")):
                    self.import_current_bind()
            elif self.state == "dns":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("a"), ord("A")):
                    if not self.require_permission("dns.write"):
                        continue
                    try:
                        self.add_dns()
                    except Exception as exc:
                        self.message = f"Error DNS: {exc}"
                elif key in (ord("d"), ord("D")):
                    if not self.require_permission("dns.write"):
                        continue
                    self.delete_by_id("dns")
                elif key in (ord("i"), ord("I")):
                    self.import_current_bind()
            elif self.state == "dns_server":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("c"), ord("C")):
                    if not self.require_permission("settings.write"):
                        continue
                    self.configure_dns_server()
            elif self.state == "optimization":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("r"), ord("R")):
                    if not self.require_permission("ops.execute"):
                        continue
                    result = apply_optimization()
                    self.optimization_logs = result.logs
                    self.message = "Optimizacion aplicada." if result.ok else "Optimizacion con errores."
                elif key in (ord("e"), ord("E")):
                    if not self.require_permission("apache.write"):
                        continue
                    self.toggle_apache_module(True)
                elif key in (ord("x"), ord("X")):
                    if not self.require_permission("apache.write"):
                        continue
                    self.toggle_apache_module(False)
                elif key in (ord("s"), ord("S")):
                    self.state = "apache_sites"
                elif key in (ord("f"), ord("F")):
                    self.state = "apache_confs"
            elif self.state == "apache_sites":
                if key in (ord("b"), ord("B")):
                    self.state = "optimization"
                elif key in (ord("e"), ord("E")):
                    if not self.require_permission("apache.write"):
                        continue
                    self.toggle_apache_site(True)
                elif key in (ord("x"), ord("X")):
                    if not self.require_permission("apache.write"):
                        continue
                    self.toggle_apache_site(False)
            elif self.state == "apache_confs":
                if key in (ord("b"), ord("B")):
                    self.state = "optimization"
                elif key in (ord("e"), ord("E")):
                    if not self.require_permission("apache.write"):
                        continue
                    self.toggle_apache_conf(True)
                elif key in (ord("x"), ord("X")):
                    if not self.require_permission("apache.write"):
                        continue
                    self.toggle_apache_conf(False)
            elif self.state == "ftp":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("a"), ord("A")):
                    if not self.require_permission("accounts.write"):
                        continue
                    try:
                        self.add_ftp()
                    except Exception as exc:
                        self.message = f"Error FTP: {exc}"
                elif key in (ord("d"), ord("D")):
                    if not self.require_permission("accounts.write"):
                        continue
                    self.delete_by_id("ftp")
            elif self.state == "mail":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("a"), ord("A")):
                    if not self.require_permission("accounts.write"):
                        continue
                    try:
                        self.add_mail()
                    except Exception as exc:
                        self.message = f"Error Mail: {exc}"
                elif key in (ord("d"), ord("D")):
                    if not self.require_permission("accounts.write"):
                        continue
                    self.delete_by_id("mail")
            elif self.state == "security":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("c"), ord("C")):
                    if not self.require_permission("security.write"):
                        continue
                    self.update_panel_login()
                elif key in (ord("p"), ord("P")):
                    self.update_panel_role()
                elif key in (ord("r"), ord("R")):
                    if not self.require_permission("security.write"):
                        continue
                    self.configure_recovery()
                elif key in (ord("k"), ord("K")):
                    if not self.require_permission("security.write"):
                        continue
                    self.recover_panel_access()
            elif self.state == "preview":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
            elif self.state == "apply_run":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("r"), ord("R")):
                    if not self.require_permission("ops.execute"):
                        continue
                    dns_result = apply_dns(
                        [dict(r) for r in self.store.list_dns()],
                        [dict(r) for r in self.store.list_domains()],
                        self.get_dns_config(),
                    )
                    ftp_result = apply_ftp([dict(r) for r in self.store.list_ftp()])
                    self.apply_logs = dns_result.logs + ftp_result.logs
                    if not dns_result.ok or not ftp_result.ok:
                        self.message = "Apply finalizo con errores (revisar logs)."
                    else:
                        self.message = "Apply completado OK (DNS/FTP)."
            elif self.state == "web_update":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("c"), ord("C")):
                    if not self.require_permission("web.write"):
                        continue
                    self.configure_web_update()
                elif key in (ord("d"), ord("D")):
                    if not self.require_permission("web.write"):
                        continue
                    result = download_web_update(self.web_update_config)
                    self.web_update_logs = result.logs
                    self.web_update_downloaded = result.downloaded
                    self.web_update_commit = result.commit
                    self.message = "Descarga OK." if result.ok else "Descarga con errores."
                elif key in (ord("r"), ord("R")):
                    if not self.require_permission("web.write"):
                        continue
                    result = replace_web_update(self.web_update_config)
                    self.web_update_logs = result.logs
                    self.message = "Reemplazo OK." if result.ok else "Reemplazo con errores."


def run_control_panel() -> None:
    curses.wrapper(lambda scr: ControlPanelTUI(scr).run())
