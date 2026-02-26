"""Post-install control panel TUI."""

from __future__ import annotations

import curses
import hashlib
from typing import List

from .services import (
    apply_dns,
    apply_ftp,
    dns_apply_preview,
    ftp_apply_preview,
    hash_password_for_system,
    mail_apply_preview,
)
from .storage import PanelStore
from .validators import is_valid_domain, is_valid_email, is_valid_hostname_label, is_valid_record_type


class ControlPanelTUI:
    def __init__(self, screen: "curses.window") -> None:
        self.screen = screen
        self.store = PanelStore()
        self.running = True
        self.state = "menu"
        self.menu_index = 0
        self.message = "Panel cargado."
        self.apply_logs: List[str] = []

    def prompt_text(self, prompt: str, initial: str = "") -> str:
        h, w = self.screen.getmaxyx()
        y = h - 2
        self.screen.move(y, 1)
        self.screen.clrtoeol()
        self.screen.addnstr(y, 1, f"{prompt}: {initial}", w - 2)
        curses.echo()
        curses.curs_set(1)
        try:
            raw = self.screen.getstr(y, len(prompt) + 3 + len(initial), w - len(prompt) - 5)
            value = raw.decode("utf-8", errors="ignore").strip()
            return value or initial
        finally:
            curses.noecho()
            curses.curs_set(0)

    def draw_header(self, title: str, subtitle: str) -> None:
        h, w = self.screen.getmaxyx()
        self.screen.addnstr(0, 2, title, w - 4, curses.A_BOLD)
        self.screen.addnstr(1, 2, subtitle, w - 4, curses.A_DIM)

    def draw_menu(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        dns_count, ftp_count, mail_count = self.store.get_counts()
        self.draw_header("Panel de Control (TUI)", "Post-instalacion")
        options = [
            f"DNS records ({dns_count})",
            f"FTP accounts ({ftp_count})",
            f"Mail accounts ({mail_count})",
            "Apply preview",
            "Apply real now",
            "Salir",
        ]
        for i, label in enumerate(options):
            attr = curses.A_REVERSE if i == self.menu_index else curses.A_NORMAL
            self.screen.addnstr(4 + i, 2, f"{'>' if i == self.menu_index else ' '} {label}", w - 4, attr)
        self.screen.addnstr(
            h - 2,
            2,
            "Teclas: flechas mover | enter abrir | q salir",
            w - 4,
            curses.A_BOLD,
        )
        self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)
        self.screen.refresh()

    def draw_table(self, title: str, rows: List[str], footer: str) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header(title, "a agregar | d eliminar por ID | b volver")
        max_rows = h - 7
        if not rows:
            self.screen.addnstr(4, 2, "(sin registros)", w - 4, curses.A_DIM)
        for i, row in enumerate(rows[:max_rows]):
            self.screen.addnstr(4 + i, 2, row, w - 4)
        self.screen.addnstr(h - 3, 2, self.message, w - 4, curses.A_DIM)
        self.screen.addnstr(h - 2, 2, footer, w - 4, curses.A_BOLD)
        self.screen.refresh()

    def draw_dns(self) -> None:
        rows = self.store.list_dns()
        lines = [f"[{r['id']:03d}] {r['zone']} {r['name']} {r['type']} {r['value']} ttl={r['ttl']}" for r in rows]
        self.draw_table("DNS Records", lines, "Teclas: a agregar | d eliminar | b volver")

    def draw_ftp(self) -> None:
        rows = self.store.list_ftp()
        lines = [f"[{r['id']:03d}] {r['username']} -> {r['home_dir']}" for r in rows]
        self.draw_table("FTP Accounts", lines, "Teclas: a agregar | d eliminar | b volver")

    def draw_mail(self) -> None:
        rows = self.store.list_mail()
        lines = [f"[{r['id']:03d}] {r['address']}" for r in rows]
        self.draw_table("Mail Accounts", lines, "Teclas: a agregar | d eliminar | b volver")

    def draw_apply_preview(self) -> None:
        self.screen.erase()
        h, w = self.screen.getmaxyx()
        self.draw_header("Apply Preview", "Comandos previstos para integrar servicios")
        lines = ["[DNS]"] + dns_apply_preview() + ["", "[FTP]"] + ftp_apply_preview() + ["", "[MAIL]"] + mail_apply_preview()
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

    def add_dns(self) -> None:
        zone = self.prompt_text("Zone (ej: ropadesanlorenzo.com)").lower()
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

        self.store.add_dns(zone, name, rtype, value, ttl)
        self.message = "Record DNS agregado."

    def add_ftp(self) -> None:
        username = self.prompt_text("Usuario FTP")
        home_dir = self.prompt_text("Home dir", f"/var/www/{username}")
        password = self.prompt_text("Password FTP")
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
        password = self.prompt_text("Password")
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

        if kind == "dns":
            deleted = self.store.delete_dns(item_id)
        elif kind == "ftp":
            deleted = self.store.delete_ftp(item_id)
        else:
            deleted = self.store.delete_mail(item_id)

        self.message = "Registro eliminado." if deleted else "ID no encontrado."

    def run(self) -> None:
        curses.curs_set(0)
        self.screen.keypad(True)

        while self.running:
            if self.state == "menu":
                self.draw_menu()
            elif self.state == "dns":
                self.draw_dns()
            elif self.state == "ftp":
                self.draw_ftp()
            elif self.state == "mail":
                self.draw_mail()
            elif self.state == "preview":
                self.draw_apply_preview()
            elif self.state == "apply_run":
                self.draw_apply_run()

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
                    self.menu_index = min(5, self.menu_index + 1)
                elif key in (10, 13, curses.KEY_ENTER):
                    if self.menu_index == 0:
                        self.state = "dns"
                    elif self.menu_index == 1:
                        self.state = "ftp"
                    elif self.menu_index == 2:
                        self.state = "mail"
                    elif self.menu_index == 3:
                        self.state = "preview"
                    elif self.menu_index == 4:
                        self.state = "apply_run"
                    else:
                        self.running = False
            elif self.state == "dns":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("a"), ord("A")):
                    try:
                        self.add_dns()
                    except Exception as exc:
                        self.message = f"Error DNS: {exc}"
                elif key in (ord("d"), ord("D")):
                    self.delete_by_id("dns")
            elif self.state == "ftp":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("a"), ord("A")):
                    try:
                        self.add_ftp()
                    except Exception as exc:
                        self.message = f"Error FTP: {exc}"
                elif key in (ord("d"), ord("D")):
                    self.delete_by_id("ftp")
            elif self.state == "mail":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("a"), ord("A")):
                    try:
                        self.add_mail()
                    except Exception as exc:
                        self.message = f"Error Mail: {exc}"
                elif key in (ord("d"), ord("D")):
                    self.delete_by_id("mail")
            elif self.state == "preview":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
            elif self.state == "apply_run":
                if key in (ord("b"), ord("B")):
                    self.state = "menu"
                elif key in (ord("r"), ord("R")):
                    dns_result = apply_dns([dict(r) for r in self.store.list_dns()])
                    ftp_result = apply_ftp([dict(r) for r in self.store.list_ftp()])
                    self.apply_logs = dns_result.logs + ftp_result.logs
                    if not dns_result.ok or not ftp_result.ok:
                        self.message = "Apply finalizo con errores (revisar logs)."
                    else:
                        self.message = "Apply completado OK (DNS/FTP)."


def run_control_panel() -> None:
    curses.wrapper(lambda scr: ControlPanelTUI(scr).run())
