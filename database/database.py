from __future__ import annotations

import json
import os
import sqlite3
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from services.app_paths import harden_path

SCHEMA_VERSION = 2
RECORD_AAD_PREFIX = b"ironkeypy.entry.v2|"
HISTORY_AAD_PREFIX = b"ironkeypy.history.v2|"
UNREADABLE_TITLE = "⚠ Registro ilegível"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fold(text: str) -> str:
    """Normaliza para busca: minúsculas, sem acentos."""
    decomposed = unicodedata.normalize("NFKD", (text or "").lower())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


@dataclass
class VaultEntry:
    """Registro do cofre já decifrado (nunca é persistido nesta forma)."""

    uid: str = ""
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    category: str = ""
    totp_secret: str = ""
    favorite: bool = False
    created_at: str = ""
    updated_at: str = ""
    password_changed_at: str = ""
    row_id: Optional[int] = field(default=None, compare=False)

    def payload(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("row_id", None)
        return data

    def matches(self, term: str) -> bool:
        needle = _fold(term)
        if not needle:
            return True
        haystack = " ".join(
            _fold(v) for v in (self.title, self.username, self.url, self.notes, self.category)
        )
        return all(part in haystack for part in needle.split())

    @property
    def display_title(self) -> str:
        return self.title or self.url or "(sem título)"


class PasswordDatabase:
    def __init__(self, db_name: str = "ironkeypy.db", crypto_manager=None):
        self.db_name = db_name
        self.crypto_manager = crypto_manager
        self._cache: Optional[List[VaultEntry]] = None
        self.create_table()

    # ------------------------------------------------------------------
    # Infraestrutura
    # ------------------------------------------------------------------
    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_name, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            # Impede que texto sensível sobreviva em páginas liberadas do arquivo.
            conn.execute("PRAGMA secure_delete=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def set_crypto_manager(self, crypto_manager) -> None:
        self.crypto_manager = crypto_manager
        self.invalidate_cache()

    def invalidate_cache(self) -> None:
        self._cache = None

    def create_table(self) -> None:
        fresh = not os.path.exists(self.db_name)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    uid         TEXT    NOT NULL UNIQUE,
                    data        TEXT    NOT NULL,
                    created_at  TEXT    NOT NULL,
                    updated_at  TEXT    NOT NULL
                );
                CREATE TABLE IF NOT EXISTS password_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_uid   TEXT    NOT NULL,
                    data        TEXT    NOT NULL,
                    replaced_at TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_history_uid ON password_history(entry_uid);
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        if fresh:
            harden_path(self.db_name)

    # ------------------------------------------------------------------
    # Criptografia de registro
    # ------------------------------------------------------------------
    def _require_crypto(self):
        if self.crypto_manager is None or not self.crypto_manager.is_unlocked():
            raise RuntimeError("O cofre está trancado — operação não permitida.")
        return self.crypto_manager

    def _encrypt_entry(self, entry: VaultEntry) -> str:
        crypto = self._require_crypto()
        aad = RECORD_AAD_PREFIX + entry.uid.encode("ascii")
        return crypto.encrypt(json.dumps(entry.payload(), ensure_ascii=False), aad=aad)

    def _decrypt_entry(self, uid: str, blob: str, row_id: int,
                       created_at: str, updated_at: str) -> VaultEntry:
        crypto = self._require_crypto()
        aad = RECORD_AAD_PREFIX + uid.encode("ascii")
        raw = json.loads(crypto.decrypt(blob, aad=aad))
        raw.pop("row_id", None)
        entry = VaultEntry(**{k: v for k, v in raw.items() if k in VaultEntry.__annotations__})
        entry.uid = uid
        entry.row_id = row_id
        entry.created_at = entry.created_at or created_at
        entry.updated_at = entry.updated_at or updated_at
        return entry

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def add_entry(self, entry: VaultEntry) -> Optional[VaultEntry]:
        self._require_crypto()
        now = _utcnow()
        entry.uid = entry.uid or uuid.uuid4().hex
        entry.created_at = entry.created_at or now
        entry.updated_at = now
        entry.password_changed_at = entry.password_changed_at or now

        blob = self._encrypt_entry(entry)
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO entries (uid, data, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (entry.uid, blob, entry.created_at, entry.updated_at),
            )
            entry.row_id = cursor.lastrowid
        self.invalidate_cache()
        return entry

    def update_entry(self, entry: VaultEntry, keep_history: bool = True,
                     history_limit: int = 10) -> bool:
        """Atualiza um registro; a senha anterior vai para o histórico cifrado."""
        crypto = self._require_crypto()
        previous = self.get_entry(entry.uid)
        if previous is None:
            return False

        password_changed = previous.password != entry.password
        entry.created_at = previous.created_at
        entry.updated_at = _utcnow()
        entry.password_changed_at = (
            entry.updated_at if password_changed else previous.password_changed_at
        )

        blob = self._encrypt_entry(entry)
        with self._connect() as conn:
            conn.execute(
                "UPDATE entries SET data = ?, updated_at = ? WHERE uid = ?",
                (blob, entry.updated_at, entry.uid),
            )
            if password_changed and keep_history and previous.password:
                aad = HISTORY_AAD_PREFIX + entry.uid.encode("ascii")
                conn.execute(
                    "INSERT INTO password_history (entry_uid, data, replaced_at) VALUES (?, ?, ?)",
                    (entry.uid, crypto.encrypt(previous.password, aad=aad), entry.updated_at),
                )
                if history_limit > 0:
                    conn.execute(
                        """DELETE FROM password_history
                           WHERE entry_uid = ? AND id NOT IN (
                               SELECT id FROM password_history WHERE entry_uid = ?
                               ORDER BY id DESC LIMIT ?)""",
                        (entry.uid, entry.uid, history_limit),
                    )
        self.invalidate_cache()
        return True

    def delete_entry(self, uid: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM entries WHERE uid = ?", (uid,))
            conn.execute("DELETE FROM password_history WHERE entry_uid = ?", (uid,))
        self.invalidate_cache()
        return cursor.rowcount > 0

    def get_entry(self, uid: str) -> Optional[VaultEntry]:
        for entry in self.get_all_entries():
            if entry.uid == uid:
                return entry
        return None

    def get_all_entries(self, use_cache: bool = True) -> List[VaultEntry]:
        if use_cache and self._cache is not None:
            return list(self._cache)
        self._require_crypto()

        entries: List[VaultEntry] = []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, uid, data, created_at, updated_at FROM entries"
            ).fetchall()

        for row_id, uid, blob, created_at, updated_at in rows:
            try:
                entries.append(self._decrypt_entry(uid, blob, row_id, created_at, updated_at))
            except Exception:
                # Registro corrompido/adulterado: exposto de forma explícita
                # em vez de silenciosamente ignorado.
                entries.append(
                    VaultEntry(
                        uid=uid,
                        title=UNREADABLE_TITLE,
                        username="",
                        password="",
                        notes=(
                            "Este registro falhou na verificação de integridade "
                            "(pode ter sido corrompido ou adulterado). "
                            "Restaure um backup para recuperá-lo."
                        ),
                        created_at=created_at,
                        updated_at=updated_at,
                        row_id=row_id,
                    )
                )
        self._cache = entries
        return list(entries)

    def search_entries(self, term: str, sort_order: str = "updated_desc") -> List[VaultEntry]:
        entries = [e for e in self.get_all_entries() if e.matches(term)]
        return self.sort_entries(entries, sort_order)

    @staticmethod
    def sort_entries(entries: List[VaultEntry], sort_order: str) -> List[VaultEntry]:
        # Favoritos sempre primeiro — hierarquia visual pedida pelos usuários.
        if sort_order == "title_asc":
            key = lambda e: (not e.favorite, _fold(e.display_title))          # noqa: E731
        elif sort_order == "created_desc":
            key = lambda e: (not e.favorite, _invert(e.created_at))            # noqa: E731
        else:
            key = lambda e: (not e.favorite, _invert(e.updated_at))            # noqa: E731
        return sorted(entries, key=key)

    def get_password_history(self, uid: str) -> List[tuple]:
        crypto = self._require_crypto()
        aad = HISTORY_AAD_PREFIX + uid.encode("ascii")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data, replaced_at FROM password_history "
                "WHERE entry_uid = ? ORDER BY id DESC",
                (uid,),
            ).fetchall()
        history = []
        for blob, replaced_at in rows:
            try:
                history.append((crypto.decrypt(blob, aad=aad), replaced_at))
            except Exception:
                continue
        return history

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    # ------------------------------------------------------------------
    # Migração do formato v1
    # ------------------------------------------------------------------
    def needs_migration(self) -> bool:
        with self._connect() as conn:
            table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'"
            ).fetchone()
            if not table:
                return False
            return conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0] > 0

    def migrate_from_v1(self) -> Tuple[int, Optional[str]]:
        """
        Reescreve a tabela ``passwords`` (v1) no formato cifrado v2.

        Retorna ``(registros_migrados, caminho_da_copia_de_seguranca)``.

        Ordem das operações, pensada para não perder nem vazar dados:

        1. copia o arquivo original para ``*.v1-<timestamp>.bak`` (rede de
           segurança caso a migração falhe pela metade);
        2. reescreve todos os registros cifrados no esquema novo;
        3. **remove** a tabela ``passwords`` e roda ``VACUUM``.
        """
        import shutil

        crypto = self._require_crypto()

        backup_path: Optional[str] = None
        if os.path.exists(self.db_name):
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            backup_path = f"{self.db_name}.v1-{stamp}.bak"
            try:
                shutil.copy2(self.db_name, backup_path)
                harden_path(backup_path)
            except OSError:
                backup_path = None
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, site, username, password, created_at FROM passwords"
            ).fetchall()

        migrated = 0
        for _old_id, site, username, enc_password, created_at in rows:
            try:
                password = crypto.decrypt(enc_password)
            except Exception:
                password = enc_password  # registro v0 em texto puro
            entry = VaultEntry(
                title=site or "",
                username=username or "",
                password=password or "",
                created_at=_iso_or_now(created_at),
                password_changed_at=_iso_or_now(created_at),
                notes="Migrado automaticamente do formato v1.",
            )
            if self.add_entry(entry):
                migrated += 1

        with self._connect() as conn:
            conn.execute("DROP TABLE IF EXISTS passwords")
            conn.execute("DROP TABLE IF EXISTS passwords_v1_backup")
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('migrated_at', ?)",
                (_utcnow(),),
            )

        self._reclaim_space()
        self.invalidate_cache()
        return migrated, backup_path

    def _reclaim_space(self) -> None:
        """
        Devolve ao SO as páginas liberadas, zerando o conteúdo antigo.

        ``VACUUM`` não roda dentro de transação, por isso usa conexão própria
        em autocommit. O checkpoint do WAL é necessário porque o journal também
        guarda cópias das páginas removidas.
        """
        conn = sqlite3.connect(self.db_name, timeout=10, isolation_level=None)
        try:
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("VACUUM")
        except sqlite3.Error:
            pass
        finally:
            conn.close()

    def reencrypt_all(self) -> int:
        """
        Recifra todos os registros com a DEK atual.

        Necessário ao concluir a migração de um cofre v1 (que lia via Fernet) e
        útil como manutenção após uma rotação de chave.
        """
        self._require_crypto()
        entries = self.get_all_entries(use_cache=False)
        with self._connect() as conn:
            for entry in entries:
                if entry.title.endswith(UNREADABLE_TITLE):
                    continue
                conn.execute(
                    "UPDATE entries SET data = ? WHERE uid = ?",
                    (self._encrypt_entry(entry), entry.uid),
                )
        self.invalidate_cache()
        return len(entries)

    # ------------------------------------------------------------------
    # Compatibilidade com a API antiga (usada por scripts/testes externos)
    # ------------------------------------------------------------------
    def add_password(self, site: str, username: str, password: str) -> bool:
        try:
            return self.add_entry(
                VaultEntry(title=site, username=username, password=password)
            ) is not None
        except Exception:
            return False

    def get_all_passwords(self) -> List[tuple]:
        return [
            (e.row_id, e.title, e.username, e.password, e.created_at)
            for e in self.get_all_entries()
        ]

    def search_passwords(self, search_term: str) -> List[tuple]:
        return [
            (e.row_id, e.title, e.username, e.password, e.created_at)
            for e in self.search_entries(search_term)
        ]

    def delete_password(self, password_id: int) -> bool:
        for entry in self.get_all_entries():
            if entry.row_id == password_id:
                return self.delete_entry(entry.uid)
        return False

    def bulk_add(self, entries: Iterable[VaultEntry]) -> int:
        return sum(1 for e in entries if self.add_entry(e))


def _invert(iso: str) -> str:
    """Chave de ordenação decrescente para strings ISO-8601."""
    return "".join(chr(0x10FFFD - ord(c)) if ord(c) < 0x10FFFD else c for c in (iso or ""))


def _iso_or_now(value: str) -> str:
    if not value:
        return _utcnow()
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        ).isoformat(timespec="seconds")
    except (ValueError, TypeError):
        return value
