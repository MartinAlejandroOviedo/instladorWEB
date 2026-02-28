# NicePanel

```text
    _  ___         ___                __
   / |/ (_)______ / _ \___ ____  ___ / /
  /    / / __/ -_) ___/ _ `/ _ \/ -_) /
 /_/|_/_/\__/\__/_/   \_,_/_//_/\__/_/
```

instalador y mini panel de control TUI para VPS Debian.

## Flujo
1. Ejecutar instalador base:
`python3 installer_tui.py`
2. Luego administrar datos del panel (DNS/FTP/Mail):
`python3 panel_control_tui.py`
3. API REST minima del panel:
`python3 panel_control_api.py`
4. Exponer API por Apache reverse proxy:
`python3 panel_control_api_proxy_setup.py --server-name panel.tudominio.com --auth-password 'cambiar-esto'`

Tambien podes usar un launcher unificado:
`python3 start.py`

La UI web basica queda servida por la misma API en `/`.

Ambas TUI ahora piden login. En la primera ejecucion se crea el usuario/password admin y luego se reutiliza para instalacion y configuracion.
Si se pierde el acceso, se puede escribir `RECUPERAR` en login para intentar reset por email o por un futuro canal WhatsApp.

## Estructura
- `installer_tui.py`: instalador inicial del stack.
- `panel_control/`: mini panel TUI modular.
- `panel_control/storage.py`: SQLite y CRUD.
- `panel_control/validators.py`: validaciones.
- `panel_control/services.py`: preview de comandos de integracion.
- `panel_control/app.py`: interfaz TUI de administracion.
- `panel_control/api.py`: API REST minima usando la misma SQLite.
- `panel_control_api_proxy_setup.py`: configura systemd + Apache reverse proxy para la API.

La SQLite ahora separa `public_settings` y `secret_settings`. La tabla legacy `settings` se mantiene solo como compatibilidad de lectura para instalaciones anteriores.
Si no se puede usar `/var/lib/panelctl/panel.db`, el fallback local ahora queda oculto en `~/.local/share/nicepanel/.panel.db`.
El `recovery_whatsapp` del panel se guarda cifrado con una clave local separada en `~/.local/share/nicepanel/.panel.key` cuando no se usa `/etc/panelctl/panel.key`.

## Estado operativo actual del panel
- DNS: importacion desde BIND actual + dominios con NS por zona + CRUD de records + configuracion base del servidor BIND (`named.conf.options` y `named.conf.local`) + reload.
- Optimizacion: compresion, cache de estaticos, ajustes seguros, recomendaciones visibles y manejo de modulos/sites/confs Apache desde el panel.
- FTP: CRUD + apply real a usuarios del sistema + restart `vsftpd`.
- Mail: CRUD en base local (pendiente integracion full postfix/dovecot).
- Seguridad: login local para acceder al instalador y al panel de configuracion + recovery email + base lista para recovery por WhatsApp.

## Roles
- `superadmin`: acceso total, incluido instalador, credenciales, cambios de rol, operaciones `apply`, import desde BIND y cambios de Apache.
- `operator`: puede administrar dominios, DNS y settings publicos, pero no ejecutar operaciones del sistema ni tocar credenciales o Apache.

## API REST minima
- `POST /api/login`: recibe `username` y `password`, devuelve token Bearer.
- `POST /api/logout`: revoca el token actual.
- `POST /api/logout-all`: invalida todos los tokens del usuario actual.
- `GET /api/me`: usuario autenticado y rol actual.
- `GET /api/domains`: dominios guardados.
- `POST /api/domains`: crea o actualiza un dominio.
- `PUT /api/domains/<id>`: actualiza dominio y DNS por zona.
- `DELETE /api/domains/<id>`: elimina dominio y records de esa zona.
- `GET /api/dns`: records DNS guardados.
- `POST /api/dns`: crea record DNS.
- `PUT /api/dns/<id>`: actualiza record DNS.
- `DELETE /api/dns/<id>`: elimina record DNS.
- `GET /api/apache/modules`: modulos Apache comunes y estado.
- `GET /api/apache/sites`: sitios Apache disponibles.
- `GET /api/apache/confs`: confs Apache disponibles.
- `GET /api/settings`: configuracion publica del panel.
- `PUT /api/settings`: actualiza configuracion publica (`dns`, `recovery_email`, `recovery_whatsapp`).
- `POST /api/ops/import-bind`: importa zonas actuales de BIND y opcionalmente las persiste en SQLite.
- `POST /api/ops/dns/preview`: devuelve preview textual del apply DNS.
- `POST /api/ops/dns/apply`: escribe zonas BIND desde la SQLite actual y recarga `bind9`.
- `POST /api/ops/optimization/preview`: preview textual de optimizacion Apache.
- `POST /api/ops/optimization/apply`: aplica optimizacion Apache segura.
- `POST /api/ops/apache/module`: habilita o deshabilita un modulo Apache con `{name, enabled}`.
- `POST /api/ops/apache/site`: habilita o deshabilita un site Apache con `{name, enabled}`.
- `POST /api/ops/apache/conf`: habilita o deshabilita una conf Apache con `{name, enabled}`.

Por defecto escucha en `127.0.0.1:8088`.
Los tokens tienen expiracion, revocacion individual y revocacion global por version.

## UI web basica
- `GET /`: login y panel web.
- pestañas para `Dominios`, `DNS`, `Settings` y `Apache`.
- usa el mismo token Bearer de la API y guarda la sesion en `localStorage`.
- adapta visibilidad segun el rol actual y limpia la sesion visual al salir.
- permite iniciar recuperacion web con usuario + WhatsApp configurado.
- si entrás con clave temporal, obliga a cambiar la password antes de usar el panel.
- si cambias `app.css` o `app.js`, conviene recargar con `Ctrl+F5` para evitar cache del navegador.

## Reverse Proxy API
- La API queda interna en `127.0.0.1:8088`.
- Apache publica `/api/` sobre el `--server-name` indicado.
- El reverse proxy agrega Basic Auth delante de `/api/`.
