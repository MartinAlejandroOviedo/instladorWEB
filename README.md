# nicepanel
instalador y mini panel de control TUI para VPS Debian.

## Flujo
1. Ejecutar instalador base:
`python3 installer_tui.py`
2. Luego administrar datos del panel (DNS/FTP/Mail):
`python3 panel_control_tui.py`

## Estructura
- `installer_tui.py`: instalador inicial del stack.
- `panel_control/`: mini panel TUI modular.
- `panel_control/storage.py`: SQLite y CRUD.
- `panel_control/validators.py`: validaciones.
- `panel_control/services.py`: preview de comandos de integracion.
- `panel_control/app.py`: interfaz TUI de administracion.

## Estado operativo actual del panel
- DNS: CRUD + apply real a BIND (`/etc/bind/panel-zones` + reload).
- FTP: CRUD + apply real a usuarios del sistema + restart `vsftpd`.
- Mail: CRUD en base local (pendiente integracion full postfix/dovecot).
