"""SQLite storage backend for control panel data."""

from __future__ import annotations

import os
import sqlite3
from typing import List, Tuple

DEFAULT_DB_PATH = "/var/lib/panelctl/panel.db"
FALLBACK_DB_PATH = os.path.abspath("panel.db")


class PanelStore:
    def __init__(self, db_path: str | None = None) -> None:
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = DEFAULT_DB_PATH if os.access(os.path.dirname(DEFAULT_DB_PATH), os.W_OK) else FALLBACK_DB_PATH
        self._ensure_parent_dir()
        self._init_db()

    def _ensure_parent_dir(self) -> None:
        parent = os.path.dirname(self.db_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone TEXT NOT NULL,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    ttl INTEGER NOT NULL DEFAULT 300
                );

                CREATE TABLE IF NOT EXISTS ftp_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    home_dir TEXT NOT NULL,
                    password_hash TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS mail_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                """
            )
            self._ensure_columns(conn)

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        ftp_cols = {row["name"] for row in conn.execute("PRAGMA table_info(ftp_accounts)").fetchall()}
        if "password_hash" not in ftp_cols:
            conn.execute("ALTER TABLE ftp_accounts ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")

    def list_dns(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM dns_records ORDER BY zone, name, type, id").fetchall()

    def add_dns(self, zone: str, name: str, rtype: str, value: str, ttl: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO dns_records(zone, name, type, value, ttl) VALUES (?, ?, ?, ?, ?)",
                (zone, name, rtype, value, ttl),
            )

    def delete_dns(self, item_id: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM dns_records WHERE id = ?", (item_id,))
            return cur.rowcount

    def list_ftp(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM ftp_accounts ORDER BY username, id").fetchall()

    def add_ftp(self, username: str, home_dir: str, password_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ftp_accounts(username, home_dir, password_hash, enabled) VALUES (?, ?, ?, 1)",
                (username, home_dir, password_hash),
            )

    def delete_ftp(self, item_id: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM ftp_accounts WHERE id = ?", (item_id,))
            return cur.rowcount

    def list_mail(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM mail_accounts ORDER BY address, id").fetchall()

    def add_mail(self, address: str, password_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO mail_accounts(address, password_hash, enabled) VALUES (?, ?, 1)",
                (address, password_hash),
            )

    def delete_mail(self, item_id: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM mail_accounts WHERE id = ?", (item_id,))
            return cur.rowcount

    def get_counts(self) -> Tuple[int, int, int]:
        with self._connect() as conn:
            dns_count = conn.execute("SELECT COUNT(*) FROM dns_records").fetchone()[0]
            ftp_count = conn.execute("SELECT COUNT(*) FROM ftp_accounts").fetchone()[0]
            mail_count = conn.execute("SELECT COUNT(*) FROM mail_accounts").fetchone()[0]
        return dns_count, ftp_count, mail_count
