#!/usr/bin/env python3
"""Configure Apache reverse proxy for NicePanel API."""

from __future__ import annotations

import argparse
import os
import sys

from panel_control.services import APIProxyConfig, setup_api_proxy


def main() -> int:
    parser = argparse.ArgumentParser(description="Configura Apache + systemd para exponer NicePanel API.")
    parser.add_argument("--server-name", required=True, help="Dominio o hostname publico para Apache")
    parser.add_argument("--auth-user", default="nicepanel", help="Usuario de Basic Auth")
    parser.add_argument("--auth-password", required=True, help="Password de Basic Auth")
    parser.add_argument("--project-dir", default=os.path.abspath(os.path.dirname(__file__)), help="Directorio del proyecto")
    parser.add_argument("--api-host", default="127.0.0.1", help="Host interno de la API")
    parser.add_argument("--api-port", type=int, default=8088, help="Puerto interno de la API")
    parser.add_argument("--public-path", default="/api/", help="Path publico a exponer en Apache")
    parser.add_argument("--service-name", default="nicepanel-api", help="Nombre del servicio systemd")
    parser.add_argument("--site-name", default="nicepanel-api", help="Nombre del sitio Apache")
    args = parser.parse_args()

    result = setup_api_proxy(
        APIProxyConfig(
            server_name=args.server_name,
            project_dir=args.project_dir,
            api_host=args.api_host,
            api_port=args.api_port,
            public_path=args.public_path,
            auth_user=args.auth_user,
            auth_password=args.auth_password,
            service_name=args.service_name,
            site_name=args.site_name,
        )
    )
    for line in result.logs:
        print(line)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
