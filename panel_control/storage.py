"""SQLite storage backend for control panel data."""

from __future__ import annotations

import os
import shutil
import sqlite3
from typing import List, Tuple

DEFAULT_DB_PATH = "/var/lib/panelctl/panel.db"
LEGACY_FALLBACK_DB_PATH = os.path.abspath("panel.db")
FALLBACK_DB_PATH = os.path.expanduser("~/.local/share/nicepanel/.panel.db")


class PanelStore:
    def __init__(self, db_path: str | None = None) -> None:
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = DEFAULT_DB_PATH if os.access(os.path.dirname(DEFAULT_DB_PATH), os.W_OK) else FALLBACK_DB_PATH
        self._ensure_parent_dir()
        self._maybe_migrate_legacy_fallback()
        self._init_db()
        self._tighten_permissions()

    def _ensure_parent_dir(self) -> None:
        parent = os.path.dirname(self.db_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    def _maybe_migrate_legacy_fallback(self) -> None:
        if self.db_path != FALLBACK_DB_PATH:
            return
        if not os.path.exists(LEGACY_FALLBACK_DB_PATH) or os.path.exists(self.db_path):
            return
        try:
            shutil.move(LEGACY_FALLBACK_DB_PATH, self.db_path)
        except OSError:
            return

    def _tighten_permissions(self) -> None:
        if self.db_path == DEFAULT_DB_PATH or self.db_path == FALLBACK_DB_PATH:
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    ns1_hostname TEXT NOT NULL DEFAULT '',
                    ns1_ipv4 TEXT NOT NULL DEFAULT '',
                    ns2_hostname TEXT NOT NULL DEFAULT '',
                    ns2_ipv4 TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1
                );

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
                    domain TEXT NOT NULL DEFAULT '',
                    home_dir TEXT NOT NULL,
                    password_hash TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS mail_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL UNIQUE,
                    local_part TEXT NOT NULL DEFAULT '',
                    domain TEXT NOT NULL DEFAULT '',
                    password_hash TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS public_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS secret_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    jti TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS recovery_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requester TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL
                );
                """
            )
            self._ensure_columns(conn)

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        domain_cols = {row["name"] for row in conn.execute("PRAGMA table_info(domains)").fetchall()}
        for column in ["ns1_hostname", "ns1_ipv4", "ns2_hostname", "ns2_ipv4"]:
            if column not in domain_cols:
                conn.execute(f"ALTER TABLE domains ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
        ftp_cols = {row["name"] for row in conn.execute("PRAGMA table_info(ftp_accounts)").fetchall()}
        if "domain" not in ftp_cols:
            conn.execute("ALTER TABLE ftp_accounts ADD COLUMN domain TEXT NOT NULL DEFAULT ''")
        if "password_hash" not in ftp_cols:
            conn.execute("ALTER TABLE ftp_accounts ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
        mail_cols = {row["name"] for row in conn.execute("PRAGMA table_info(mail_accounts)").fetchall()}
        if "local_part" not in mail_cols:
            conn.execute("ALTER TABLE mail_accounts ADD COLUMN local_part TEXT NOT NULL DEFAULT ''")
        if "domain" not in mail_cols:
            conn.execute("ALTER TABLE mail_accounts ADD COLUMN domain TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            UPDATE mail_accounts
            SET local_part = substr(address, 1, instr(address, '@') - 1)
            WHERE local_part = '' AND instr(address, '@') > 1
            """
        )
        conn.execute(
            """
            UPDATE mail_accounts
            SET domain = substr(address, instr(address, '@') + 1)
            WHERE domain = '' AND instr(address, '@') > 1
            """
        )

    def list_dns(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM dns_records ORDER BY zone, name, type, id").fetchall()

    def list_domains(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM domains ORDER BY domain, id").fetchall()

    def add_domain(self, domain: str) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO domains(domain, enabled) VALUES (?, 1)", (domain,))

    def delete_domain(self, item_id: int) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT domain FROM domains WHERE id = ?", (item_id,)).fetchone()
            if not row:
                return 0
            conn.execute("DELETE FROM dns_records WHERE zone = ?", (row["domain"],))
            conn.execute("DELETE FROM ftp_accounts WHERE domain = ?", (row["domain"],))
            conn.execute("DELETE FROM mail_accounts WHERE domain = ?", (row["domain"],))
            cur = conn.execute("DELETE FROM domains WHERE id = ?", (item_id,))
            return cur.rowcount

    def get_domain(self, item_id: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM domains WHERE id = ?", (item_id,)).fetchone()

    def get_domain_by_name(self, domain: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM domains WHERE domain = ?", (domain,)).fetchone()

    def update_domain_dns(
        self,
        item_id: int,
        domain: str,
        ns1_hostname: str,
        ns1_ipv4: str,
        ns2_hostname: str,
        ns2_ipv4: str,
    ) -> int:
        with self._connect() as conn:
            current = conn.execute("SELECT domain FROM domains WHERE id = ?", (item_id,)).fetchone()
            if not current:
                return 0
            cur = conn.execute(
                """
                UPDATE domains
                SET domain = ?, ns1_hostname = ?, ns1_ipv4 = ?, ns2_hostname = ?, ns2_ipv4 = ?
                WHERE id = ?
                """,
                (domain, ns1_hostname, ns1_ipv4, ns2_hostname, ns2_ipv4, item_id),
            )
            if current["domain"] != domain:
                conn.execute("UPDATE dns_records SET zone = ? WHERE zone = ?", (domain, current["domain"]))
                conn.execute("UPDATE ftp_accounts SET domain = ? WHERE domain = ?", (domain, current["domain"]))
                conn.execute(
                    """
                    UPDATE mail_accounts
                    SET domain = ?, address = lower(local_part || '@' || ?)
                    WHERE domain = ?
                    """,
                    (domain, domain, current["domain"]),
                )
            return cur.rowcount

    def upsert_domain(
        self,
        domain: str,
        ns1_hostname: str = "",
        ns1_ipv4: str = "",
        ns2_hostname: str = "",
        ns2_ipv4: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO domains(domain, ns1_hostname, ns1_ipv4, ns2_hostname, ns2_ipv4, enabled)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(domain) DO UPDATE SET
                    ns1_hostname = excluded.ns1_hostname,
                    ns1_ipv4 = excluded.ns1_ipv4,
                    ns2_hostname = excluded.ns2_hostname,
                    ns2_ipv4 = excluded.ns2_ipv4
                """,
                (domain, ns1_hostname, ns1_ipv4, ns2_hostname, ns2_ipv4),
            )

    def replace_dns_records(self, records: List[tuple[str, str, str, str, int]]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_records")
            conn.executemany(
                "INSERT INTO dns_records(zone, name, type, value, ttl) VALUES (?, ?, ?, ?, ?)",
                records,
            )

    def replace_domains(self, domains: List[tuple[str, str, str, str, str]]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM domains")
            conn.executemany(
                """
                INSERT INTO domains(domain, ns1_hostname, ns1_ipv4, ns2_hostname, ns2_ipv4, enabled)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                domains,
            )

    def add_dns(self, zone: str, name: str, rtype: str, value: str, ttl: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO dns_records(zone, name, type, value, ttl) VALUES (?, ?, ?, ?, ?)",
                (zone, name, rtype, value, ttl),
            )
            conn.execute("INSERT OR IGNORE INTO domains(domain, enabled) VALUES (?, 1)", (zone,))

    def get_dns(self, item_id: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM dns_records WHERE id = ?", (item_id,)).fetchone()

    def update_dns(self, item_id: int, zone: str, name: str, rtype: str, value: str, ttl: int) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE dns_records
                SET zone = ?, name = ?, type = ?, value = ?, ttl = ?
                WHERE id = ?
                """,
                (zone, name, rtype, value, ttl, item_id),
            )
            if cur.rowcount:
                conn.execute("INSERT OR IGNORE INTO domains(domain, enabled) VALUES (?, 1)", (zone,))
            return cur.rowcount

    def delete_dns(self, item_id: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM dns_records WHERE id = ?", (item_id,))
            return cur.rowcount

    def list_ftp(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM ftp_accounts ORDER BY domain, username, id").fetchall()

    def get_ftp(self, item_id: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM ftp_accounts WHERE id = ?", (item_id,)).fetchone()

    def get_ftp_by_username(self, username: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM ftp_accounts WHERE username = ?", (username,)).fetchone()

    def add_ftp(self, username: str, domain: str, home_dir: str, password_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ftp_accounts(username, domain, home_dir, password_hash, enabled)
                VALUES (?, ?, ?, ?, 1)
                """,
                (username, domain, home_dir, password_hash),
            )

    def update_ftp(self, item_id: int, username: str, domain: str, home_dir: str, password_hash: str | None = None) -> int:
        with self._connect() as conn:
            if password_hash:
                cur = conn.execute(
                    """
                    UPDATE ftp_accounts
                    SET username = ?, domain = ?, home_dir = ?, password_hash = ?
                    WHERE id = ?
                    """,
                    (username, domain, home_dir, password_hash, item_id),
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE ftp_accounts
                    SET username = ?, domain = ?, home_dir = ?
                    WHERE id = ?
                    """,
                    (username, domain, home_dir, item_id),
                )
            return cur.rowcount

    def delete_ftp(self, item_id: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM ftp_accounts WHERE id = ?", (item_id,))
            return cur.rowcount

    def list_mail(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM mail_accounts ORDER BY domain, local_part, id").fetchall()

    def get_mail(self, item_id: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM mail_accounts WHERE id = ?", (item_id,)).fetchone()

    def get_mail_by_address(self, address: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM mail_accounts WHERE address = ?", (address,)).fetchone()

    def add_mail(self, local_part: str, domain: str, address: str, password_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO mail_accounts(address, local_part, domain, password_hash, enabled)
                VALUES (?, ?, ?, ?, 1)
                """,
                (address, local_part, domain, password_hash),
            )

    def update_mail(
        self,
        item_id: int,
        local_part: str,
        domain: str,
        address: str,
        password_hash: str | None = None,
    ) -> int:
        with self._connect() as conn:
            if password_hash:
                cur = conn.execute(
                    """
                    UPDATE mail_accounts
                    SET address = ?, local_part = ?, domain = ?, password_hash = ?
                    WHERE id = ?
                    """,
                    (address, local_part, domain, password_hash, item_id),
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE mail_accounts
                    SET address = ?, local_part = ?, domain = ?
                    WHERE id = ?
                    """,
                    (address, local_part, domain, item_id),
                )
            return cur.rowcount

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

    def get_setting(self, key: str, default: str = "") -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def _get_scoped_setting(self, table: str, key: str, default: str = "") -> str:
        with self._connect() as conn:
            row = conn.execute(f"SELECT value FROM {table} WHERE key = ?", (key,)).fetchone()
            if row:
                return str(row["value"])
            legacy = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return str(legacy["value"]) if legacy else default

    def _set_scoped_setting(self, table: str, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO {table}(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    def get_public_setting(self, key: str, default: str = "") -> str:
        return self._get_scoped_setting("public_settings", key, default)

    def set_public_setting(self, key: str, value: str) -> None:
        self._set_scoped_setting("public_settings", key, value)

    def get_secret_setting(self, key: str, default: str = "") -> str:
        return self._get_scoped_setting("secret_settings", key, default)

    def set_secret_setting(self, key: str, value: str) -> None:
        self._set_scoped_setting("secret_settings", key, value)

    def revoke_token(self, jti: str, expires_at: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO revoked_tokens(jti, expires_at) VALUES (?, ?)
                """,
                (jti, expires_at),
            )

    def is_token_revoked(self, jti: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
            return row is not None

    def purge_expired_revoked_tokens(self, now_ts: int) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_ts,))
            return cur.rowcount

    def add_recovery_event(
        self,
        actor: str,
        channel: str,
        status: str,
        requester: str,
        detail: str,
        created_at: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO recovery_events(actor, channel, status, requester, detail, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (actor, channel, status, requester, detail, created_at),
            )

    def count_recent_recovery_events(self, actor: str, channel: str, since_ts: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM recovery_events
                WHERE actor = ? AND channel = ? AND created_at >= ?
                """,
                (actor, channel, since_ts),
            ).fetchone()
            return int(row["total"]) if row else 0

    def list_recent_recovery_events(self, limit: int = 20) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                """
                SELECT * FROM recovery_events
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
