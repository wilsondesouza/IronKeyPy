"""
Persistência do cofre em SQLite.

Vulnerabilidade corrigida (crítica)
-----------------------------------
Na versão anterior **apenas a coluna ``password`` era cifrada**. Site, nome de
usuário e datas ficavam em texto puro no ``ironkeypy.db``. Qualquer pessoa com
acesso ao arquivo (backup em nuvem, malware, perícia, outro usuário da máquina)
obtinha o mapa completo "em quais serviços a vítima tem conta e com qual
login" — que é metade do valor de um cofre de senhas e insumo direto para
phishing dirigido e *credential stuffing*.

Agora cada registro é serializado em JSON e cifrado inteiro com AES-256-GCM.
O ciphertext é ligado a um ``uid`` aleatório via AAD, impedindo que um atacante
com acesso de escrita ao banco troque registros de lugar (ataque de
*cut-and-paste* / confusão de credencial).

Outras correções
----------------
* Conexões eram abertas/fechadas sem ``try/finally`` — vazavam em caso de erro.
* ``search_passwords`` interpolava o termo em ``LIKE`` sem escapar ``%``/``_``;
  além disso a busca não alcançava o conteúdo cifrado. A busca agora é feita
  em memória sobre os registros decifrados (com cache), cobrindo também
  usuário, URL, notas e categoria.
* Não existia **edição** de registro nem histórico de senhas.
* ``created_at`` usava horário local sem fuso; agora é ISO-8601 UTC.

Schema v3 — preparação para sincronização entre dispositivos
------------------------------------------------------------
Sincronizar não é copiar arquivo: é **mesclar estado**. Duas consequências
diretas no banco:

* cada registro ganha ``rev`` (contador monotônico), ``deleted_at``
  (*tombstone*) e ``device_id`` (quem escreveu por último). Sem isso, apagar um
  registro no desktop o faria "ressuscitar" no celular, porque do ponto de vista
  do outro dispositivo ele simplesmente nunca existiu;
* exclusão deixa de ser ``DELETE`` e passa a ser **tombstone mínimo**: o
  conteúdo (usuário, senha, URL, notas, TOTP) é apagado na hora e só o título
  permanece, para que uma senha apagada não continue viajando — cifrada — dentro
  do arquivo de sincronização por até 90 dias.

A especificação normativa está em ``docs/CONTRATO-DE-SINCRONIZACAO.md``.
"""

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

SCHEMA_VERSION = 3
RECORD_AAD_PREFIX = b"ironkeypy.entry.v2|"
HISTORY_AAD_PREFIX = b"ironkeypy.history.v2|"
UNREADABLE_TITLE = "⚠ Registro ilegível"

# Campos de conteúdo apagados quando um registro vira tombstone (§6.4 do contrato).
TOMBSTONE_WIPED_FIELDS = ("username", "password", "url", "notes", "totp_secret", "category")

CONFLICT_SAME_REV = "same_rev"
CONFLICT_RESURRECTION = "resurrection"


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
    # --- controle de sincronização (schema v3) ---
    rev: int = 1                # contador monotônico, por registro
    deleted_at: str = ""        # tombstone: vazio = registro vivo
    device_id: str = ""         # dispositivo que produziu a rev atual
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
    def is_deleted(self) -> bool:
        return bool(self.deleted_at)

    @property
    def display_title(self) -> str:
        return self.title or self.url or "(sem título)"

    def as_tombstone(self, device_id: str = "") -> "VaultEntry":
        """
        Converte em tombstone mínimo (§6.4): apaga o conteúdo e marca a exclusão.

        ``password_changed_at`` e ``created_at`` são preservados como metadados
        de ordenação; ``title`` permanece para que o usuário reconheça o
        registro ao revisar um conflito de ressurreição.
        """
        self.deleted_at = _utcnow()
        self.updated_at = self.deleted_at
        self.rev = int(self.rev or 1) + 1
        if device_id:
            self.device_id = device_id
        for field_name in TOMBSTONE_WIPED_FIELDS:
            setattr(self, field_name, "")
        self.favorite = False
        return self


class PasswordDatabase:
    def __init__(self, db_name: str = "ironkeypy.db", crypto_manager=None):
        self.db_name = db_name
        self.crypto_manager = crypto_manager
        self.device_id = ""
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

    def set_device_id(self, device_id: str) -> None:
        """Identifica este dispositivo nas escritas (usado pelo motor de sync)."""
        self.device_id = device_id or ""

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
                    updated_at  TEXT    NOT NULL,
                    rev         INTEGER NOT NULL DEFAULT 1,
                    deleted_at  TEXT,
                    device_id   TEXT
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
                CREATE TABLE IF NOT EXISTS sync_conflicts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_uid   TEXT    NOT NULL,
                    device_id   TEXT    NOT NULL,
                    detected_at TEXT    NOT NULL,
                    detail      TEXT    NOT NULL,
                    resolved    INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_conflicts_pending
                    ON sync_conflicts(resolved, detected_at);
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        self._migrate_to_v3()
        if fresh:
            harden_path(self.db_name)

    # ------------------------------------------------------------------
    # Migração v2 -> v3 (sincronização)
    # ------------------------------------------------------------------
    def _migrate_to_v3(self) -> bool:
        """
        Acrescenta as colunas de sincronização. Idempotente.

        Só mexe em colunas de **metadados** (rev/deleted_at/device_id), nunca no
        conteúdo cifrado, então não precisa do cofre destrancado. Ainda assim,
        faz cópia de segurança do arquivo antes de alterar um banco com dados.
        """
        with self._connect() as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(entries)")}
            if not columns:
                return False
            missing = {"rev", "deleted_at", "device_id"} - columns
            impacted = (
                bool(missing)
                and conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0] > 0
            )

        if impacted:
            self._backup_file("v2")

        with self._connect() as conn:
            for column, ddl in (("rev", "INTEGER NOT NULL DEFAULT 1"),
                                ("deleted_at", "TEXT"),
                                ("device_id", "TEXT")):
                if column not in columns:
                    conn.execute(f"ALTER TABLE entries ADD COLUMN {column} {ddl}")
            # O índice depende de deleted_at: só pode ser criado depois da coluna.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(deleted_at)"
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('sync_migrated_at', ?)",
                (_utcnow(),),
            )
        self.invalidate_cache()
        return True

    def _backup_file(self, suffix: str) -> Optional[str]:
        """Cópia de segurança datada do banco, antes de uma migração destrutiva."""
        import shutil

        if not os.path.exists(self.db_name):
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        target = f"{self.db_name}.{suffix}-{stamp}.bak"
        try:
            shutil.copy2(self.db_name, target)
            harden_path(target)
        except OSError:
            return None
        return target

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
                       created_at: str, updated_at: str,
                       rev: int = 1, deleted_at: Optional[str] = None,
                       device_id: Optional[str] = None) -> VaultEntry:
        crypto = self._require_crypto()
        aad = RECORD_AAD_PREFIX + uid.encode("ascii")
        raw = json.loads(crypto.decrypt(blob, aad=aad))
        raw.pop("row_id", None)
        entry = VaultEntry(**{k: v for k, v in raw.items() if k in VaultEntry.__annotations__})
        entry.uid = uid
        entry.row_id = row_id
        entry.created_at = entry.created_at or created_at
        entry.updated_at = entry.updated_at or updated_at
        # O JSON cifrado é a fonte da verdade; as colunas são a cópia
        # desnormalizada usada para filtrar/ordenar em SQL.
        try:
            entry.rev = max(1, int(entry.rev or rev or 1))
        except (TypeError, ValueError):
            entry.rev = max(1, int(rev or 1))
        entry.deleted_at = entry.deleted_at or (deleted_at or "")
        entry.device_id = entry.device_id or (device_id or "")
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
        entry.rev = 1
        entry.deleted_at = ""
        entry.device_id = entry.device_id or self.device_id

        blob = self._encrypt_entry(entry)
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO entries (uid, data, created_at, updated_at, rev, deleted_at, device_id) "
                "VALUES (?, ?, ?, ?, ?, NULL, ?)",
                (entry.uid, blob, entry.created_at, entry.updated_at,
                 entry.rev, entry.device_id),
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
        # Toda alteração de conteúdo avança a revisão: é o que permite ao outro
        # dispositivo saber, sem depender de relógio, qual versão é mais nova.
        entry.rev = int(previous.rev or 1) + 1
        entry.deleted_at = previous.deleted_at
        entry.device_id = self.device_id or previous.device_id

        blob = self._encrypt_entry(entry)
        with self._connect() as conn:
            conn.execute(
                "UPDATE entries SET data = ?, updated_at = ?, rev = ?, device_id = ? WHERE uid = ?",
                (blob, entry.updated_at, entry.rev, entry.device_id, entry.uid),
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

    def delete_entry(self, uid: str, hard: bool = False) -> bool:
        """
        Exclui um registro.

        O padrão é **exclusão lógica** (tombstone): a linha continua existindo,
        com o conteúdo apagado, para que a exclusão se propague aos outros
        dispositivos. ``hard=True`` apaga de verdade — usado pela purga de
        tombstones e por operações internas, nunca pela UI.

        O histórico de senhas é removido imediatamente nos dois casos: senhas
        antigas de um registro excluído não têm por que sobreviver.
        """
        if hard:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM entries WHERE uid = ?", (uid,))
                conn.execute("DELETE FROM password_history WHERE entry_uid = ?", (uid,))
            self.invalidate_cache()
            return cursor.rowcount > 0

        entry = self.get_entry(uid)
        if entry is None:
            return False
        entry.as_tombstone(self.device_id)

        blob = self._encrypt_entry(entry)
        with self._connect() as conn:
            conn.execute(
                "UPDATE entries SET data = ?, updated_at = ?, rev = ?, deleted_at = ?, "
                "device_id = ? WHERE uid = ?",
                (blob, entry.updated_at, entry.rev, entry.deleted_at,
                 entry.device_id, entry.uid),
            )
            conn.execute("DELETE FROM password_history WHERE entry_uid = ?", (uid,))
        self.invalidate_cache()
        return True

    def get_entry(self, uid: str) -> Optional[VaultEntry]:
        for entry in self.get_all_entries():
            if entry.uid == uid:
                return entry
        return None

    def get_all_entries(self, use_cache: bool = True,
                        include_deleted: bool = False) -> List[VaultEntry]:
        """
        Registros do cofre. Por padrão **só os vivos** — tombstones são detalhe
        de sincronização, não conteúdo que o usuário deva ver.
        """
        if not include_deleted and use_cache and self._cache is not None:
            return list(self._cache)
        self._require_crypto()

        entries: List[VaultEntry] = []
        with self._connect() as conn:
            where = "" if include_deleted else " WHERE deleted_at IS NULL"
            rows = conn.execute(
                "SELECT id, uid, data, created_at, updated_at, rev, deleted_at, device_id "
                f"FROM entries{where}"
            ).fetchall()

        for row_id, uid, blob, created_at, updated_at, rev, deleted_at, device_id in rows:
            try:
                entries.append(
                    self._decrypt_entry(uid, blob, row_id, created_at, updated_at,
                                        rev, deleted_at, device_id)
                )
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
                        rev=int(rev or 1),
                        deleted_at=deleted_at or "",
                        device_id=device_id or "",
                        row_id=row_id,
                    )
                )
        if not include_deleted:
            self._cache = entries
        return list(entries)

    def get_state_for_sync(self) -> List[VaultEntry]:
        """Estado completo: vivos **e** tombstones (entrada do motor de sync)."""
        return self.get_all_entries(use_cache=False, include_deleted=True)

    def get_tombstones(self) -> List[VaultEntry]:
        return [e for e in self.get_state_for_sync() if e.is_deleted]

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

    def count(self, include_deleted: bool = False) -> int:
        where = "" if include_deleted else " WHERE deleted_at IS NULL"
        with self._connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM entries{where}").fetchone()[0]

    # ------------------------------------------------------------------
    # Sincronização: purga, conflitos e reconciliação
    # ------------------------------------------------------------------
    def purge_tombstones(self, max_age_days: int = 90) -> int:
        """
        Remove definitivamente tombstones mais antigos que ``max_age_days``.

        Decisão D1: teto fixo, sem depender de consenso entre dispositivos. O
        risco aceito é que um dispositivo muito tempo offline ressuscite um
        registro — o que é sempre reportado como conflito, nunca silencioso.
        """
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(max_age_days))).isoformat(
            timespec="seconds"
        )
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT uid FROM entries WHERE deleted_at IS NOT NULL AND deleted_at < ?",
                (cutoff,),
            ).fetchall()
            uids = [row[0] for row in rows]
            for uid in uids:
                conn.execute("DELETE FROM entries WHERE uid = ?", (uid,))
                conn.execute("DELETE FROM password_history WHERE entry_uid = ?", (uid,))
        if uids:
            self.record_purged_uids(uids)
            self.invalidate_cache()
        return len(uids)

    # --- tabela meta ----------------------------------------------------
    def get_meta(self, key: str, default: str = "") -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, str(value))
            )

    def record_purged_uids(self, uids: List[str], limit: int = 500) -> None:
        """
        Memoriza uids de tombstones já purgados.

        Serve para reconhecer uma **ressurreição**: um registro vivo que chega do
        remoto com um uid que já foi apagado aqui há tempos é indistinguível de
        "registro novo", a menos que a gente lembre do que foi purgado.
        """
        if not uids:
            return
        history = self.get_purged_uids()
        history.extend({"uid": uid, "at": _utcnow()} for uid in uids)
        self.set_meta("sync_purged_uids", json.dumps(history[-limit:]))

    def get_purged_uids(self) -> List[dict]:
        try:
            return json.loads(self.get_meta("sync_purged_uids", "[]"))
        except (TypeError, ValueError):
            return []

    def log_conflict(self, entry_uid: str, device_id: str, detail: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sync_conflicts (entry_uid, device_id, detected_at, detail) "
                "VALUES (?, ?, ?, ?)",
                (entry_uid, device_id or "", _utcnow(),
                 json.dumps(detail, ensure_ascii=False, sort_keys=True)),
            )

    def count_pending_conflicts(self) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM sync_conflicts WHERE resolved = 0"
            ).fetchone()[0]

    def list_conflicts(self, only_pending: bool = True, limit: int = 200) -> List[dict]:
        where = "WHERE resolved = 0" if only_pending else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT id, entry_uid, device_id, detected_at, detail, resolved "
                f"FROM sync_conflicts {where} ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        conflicts = []
        for row in rows:
            try:
                detail = json.loads(row[4])
            except (TypeError, ValueError):
                detail = {"raw": row[4]}
            conflicts.append({
                "id": row[0], "entry_uid": row[1], "device_id": row[2],
                "detected_at": row[3], "detail": detail, "resolved": bool(row[5]),
            })
        return conflicts

    def resolve_conflicts(self, conflict_ids: Optional[Iterable[int]] = None) -> int:
        with self._connect() as conn:
            if conflict_ids is None:
                cursor = conn.execute("UPDATE sync_conflicts SET resolved = 1 WHERE resolved = 0")
            else:
                ids = [int(i) for i in conflict_ids]
                if not ids:
                    return 0
                placeholders = ",".join("?" * len(ids))
                cursor = conn.execute(
                    f"UPDATE sync_conflicts SET resolved = 1 WHERE id IN ({placeholders})",
                    ids,
                )
        return cursor.rowcount

    def _upsert_with_conn(self, conn, entry: VaultEntry) -> str:
        """Grava um registro como veio do merge, reutilizando a conexão dada."""
        entry.deleted_at = entry.deleted_at or ""
        entry.rev = max(1, int(entry.rev or 1))
        blob = self._encrypt_entry(entry)
        cursor = conn.execute(
            "UPDATE entries SET data = ?, created_at = ?, updated_at = ?, rev = ?, "
            "deleted_at = ?, device_id = ? WHERE uid = ?",
            (blob, entry.created_at, entry.updated_at, entry.rev,
             entry.deleted_at or None, entry.device_id, entry.uid),
        )
        if cursor.rowcount == 0:
            conn.execute(
                "INSERT INTO entries (uid, data, created_at, updated_at, rev, "
                "deleted_at, device_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (entry.uid, blob, entry.created_at, entry.updated_at, entry.rev,
                 entry.deleted_at or None, entry.device_id),
            )
            action = "inserted"
        else:
            action = "updated"
        if entry.is_deleted:
            # Exclusão chegou de outro dispositivo: o histórico local daquele
            # registro não deve sobreviver.
            conn.execute("DELETE FROM password_history WHERE entry_uid = ?", (entry.uid,))
        return action

    def upsert_from_sync(self, entry: VaultEntry) -> str:
        """
        Grava um registro **como veio do merge**, preservando uid/rev/timestamps.

        Diferente de :meth:`add_entry`/:meth:`update_entry`, aqui nada é
        "reinventado": o estado remoto é aplicado literalmente, senão a
        reconciliação nunca convergiria.
        """
        self._require_crypto()
        with self._connect() as conn:
            action = self._upsert_with_conn(conn, entry)
        self.invalidate_cache()
        return action

    def apply_sync_state(self, merged: List[VaultEntry],
                         remove_uids: Iterable[str] = ()) -> Tuple[int, int]:
        """Aplica o resultado do merge em **uma** transação: ou entra tudo, ou nada."""
        self._require_crypto()
        removed = 0
        with self._connect() as conn:
            for entry in merged:
                if not entry.uid:
                    entry.uid = uuid.uuid4().hex
                self._upsert_with_conn(conn, entry)
            for uid in remove_uids:
                cursor = conn.execute("DELETE FROM entries WHERE uid = ?", (uid,))
                conn.execute("DELETE FROM password_history WHERE entry_uid = ?", (uid,))
                removed += cursor.rowcount
        self.invalidate_cache()
        return len(merged), removed

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
        3. **remove** a tabela ``passwords`` e roda ``VACUUM`` — sem isso, os
           nomes de sites e usuários continuariam legíveis em texto puro dentro
           do arquivo, anulando justamente a correção que a migração aplica.
        """
        crypto = self._require_crypto()
        backup_path = self._backup_file("v1")
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
        # Inclui tombstones: eles também estão cifrados com a DEK e ficariam
        # ilegíveis (portanto impossíveis de purgar corretamente) após rotação.
        entries = self.get_state_for_sync()
        with self._connect() as conn:
            for entry in entries:
                if entry.title.endswith(UNREADABLE_TITLE):
                    continue
                conn.execute(
                    "UPDATE entries SET data = ?, rev = ?, deleted_at = ?, device_id = ? "
                    "WHERE uid = ?",
                    (self._encrypt_entry(entry), entry.rev,
                     entry.deleted_at or None, entry.device_id, entry.uid),
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
