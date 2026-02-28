# nicepanel
instalador y mini panel de control TUI para VPS Debian.

## Flujo
1. Ejecutar instalador base:
`python3 installer_tui.py`
2. Luego administrar datos del panel (DNS/FTP/Mail):
`python3 panel_control_tui.py`

Ambas TUI ahora piden login. En la primera ejecucion se crea el usuario/password admin y luego se reutiliza para instalacion y configuracion.
Si se pierde el acceso, se puede escribir `RECUPERAR` en login para intentar reset por email o por un futuro canal WhatsApp.

## Estructura
- `installer_tui.py`: instalador inicial del stack.
- `panel_control/`: mini panel TUI modular.
- `panel_control/storage.py`: SQLite y CRUD.
- `panel_control/validators.py`: validaciones.
- `panel_control/services.py`: preview de comandos de integracion.
- `panel_control/app.py`: interfaz TUI de administracion.

## Estado operativo actual del panel
- DNS: importacion desde BIND actual + dominios con NS por zona + CRUD de records + configuracion base del servidor BIND (`named.conf.options` y `named.conf.local`) + reload.
- Optimizacion: compresion, cache de estaticos, ajustes seguros, recomendaciones visibles y manejo de modulos/sites/confs Apache desde el panel.
- FTP: CRUD + apply real a usuarios del sistema + restart `vsftpd`.
- Mail: CRUD en base local (pendiente integracion full postfix/dovecot).
- Seguridad: login local para acceder al instalador y al panel de configuracion + recovery email + base lista para recovery por WhatsApp.
