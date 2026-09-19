"""
Backup portátil e importação/exportação.

Bug crítico corrigido
---------------------
A versão anterior "exportava backup" copiando apenas o ``ironkeypy.db``. Como o
salt de derivação da chave vive no ``config.json`` (não copiado), **o backup era
irrecuperável em outra máquina ou após uma reinstalação** — o usuário só
descobriria isso no pior momento possível. Pior: a importação sobrescrevia o
banco atual *antes* de verificar se o arquivo podia sequer ser decifrado.

O novo formato ``.ikbak`` é autocontido: carrega o próprio salt, os parâmetros
de KDF e os dados cifrados com AES-256-GCM, protegidos por uma senha escolhida
na hora da exportação (por padrão, a própria senha mestre). Também é verificado
integralmente **antes** de tocar no cofre atual.
"""

from __future__ import annotations

import base64
import csv
import gzip
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from database.database import VaultEntry
from services.app_paths import harden_path
from services.crypto_manager import CryptoManager, CryptoError

BACKUP_MAGIC = "IronKeyPy-Backup"
BACKUP_VERSION = 1
BACKUP_AAD = b"ironkeypy.backup.v1"
NONCE_SIZE = 12


class BackupError(Exception):
    pass


# ----------------------------------------------------------------------
# Backup cifrado portátil (.ikbak)
# ----------------------------------------------------------------------
def export_encrypted_backup(entries: List[VaultEntry], passphrase: str, path: str) -> int:
    """Grava um arquivo autocontido e cifrado. Retorna o nº de registros."""
    if not passphrase:
        raise BackupError("Informe uma senha para proteger o backup.")
    # Backup é instantâneo de conteúdo: tombstones (registros já excluídos,
    # reduzidos a metadados) não pertencem a ele.
    entries = [e for e in entries if not e.is_deleted]

    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entry_count": len(entries),
        "entries": [_entry_to_dict(e) for e in entries],
    }
    compressed = gzip.compress(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    kdf = CryptoManager.default_kdf_params()
    with CryptoManager._derive_kek(passphrase, kdf) as key:  # noqa: SLF001 - mesma família
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(key.bytes()).encrypt(nonce, compressed, BACKUP_AAD)

    envelope = {
        "magic": BACKUP_MAGIC,
        "version": BACKUP_VERSION,
        "kdf": kdf,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "data": base64.b64encode(ciphertext).decode("ascii"),
    }

    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2)
    harden_path(tmp)
    os.replace(tmp, path)
    harden_path(path)
    return len(entries)


def read_encrypted_backup(path: str, passphrase: str) -> Tuple[List[VaultEntry], Dict[str, Any]]:
    """
    Lê e **valida** um backup sem tocar no cofre atual.

    Levanta :class:`BackupError` com mensagem acionável em qualquer falha.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError(
            "Arquivo ilegível. Selecione um backup .ikbak gerado pelo IronKey Py."
        ) from exc

    if envelope.get("magic") != BACKUP_MAGIC:
        raise BackupError("Este arquivo não é um backup do IronKey Py.")
    if int(envelope.get("version", 0)) > BACKUP_VERSION:
        raise BackupError(
            "Backup criado por uma versão mais recente do IronKey Py. Atualize o aplicativo."
        )

    try:
        with CryptoManager._derive_kek(passphrase, envelope["kdf"]) as key:  # noqa: SLF001
            plain = AESGCM(key.bytes()).decrypt(
                base64.b64decode(envelope["nonce"]),
                base64.b64decode(envelope["data"]),
                BACKUP_AAD,
            )
    except InvalidTag as exc:
        raise BackupError(
            "Senha incorreta ou backup corrompido — a verificação de integridade falhou."
        ) from exc
    except (KeyError, ValueError, CryptoError) as exc:
        raise BackupError(f"Backup inválido: {exc}") from exc

    try:
        payload = json.loads(gzip.decompress(plain).decode("utf-8"))
        entries = [_dict_to_entry(d) for d in payload.get("entries", [])]
    except Exception as exc:
        raise BackupError("Conteúdo do backup malformado.") from exc

    meta = {
        "exported_at": payload.get("exported_at", "desconhecido"),
        "entry_count": len(entries),
    }
    return entries, meta


def merge_entries(existing: List[VaultEntry], incoming: List[VaultEntry]) -> Tuple[List[VaultEntry], int]:
    """
    Importa registros novos sem duplicar.

    Critério de identidade, em ordem: ``uid`` quando o registro tem um (backup
    do IronKey Py) e, só na ausência dele (importação de CSV), o par
    ``(título, usuário)`` em minúsculas.

    Correção relevante para a sincronização: a versão anterior **descartava o
    uid** e gerava um novo a cada importação. Isso destruía a identidade do
    registro — e sem identidade estável não existe mesclagem entre dispositivos,
    só duplicação.
    """
    by_uid = {e.uid for e in existing if e.uid}
    by_pair = {(e.title.strip().lower(), e.username.strip().lower()) for e in existing}

    new_entries, skipped = [], 0
    for entry in incoming:
        # Backup é um instantâneo de conteúdo: tombstones não fazem parte dele.
        if entry.is_deleted:
            skipped += 1
            continue
        if entry.uid and entry.uid in by_uid:
            skipped += 1
            continue
        key = (entry.title.strip().lower(), entry.username.strip().lower())
        if not entry.uid and key in by_pair:
            skipped += 1
            continue
        if not entry.uid:
            import uuid

            entry.uid = uuid.uuid4().hex
        entry.row_id = None
        by_uid.add(entry.uid)
        by_pair.add(key)
        new_entries.append(entry)
    return new_entries, skipped


# ----------------------------------------------------------------------
# CSV (interoperabilidade — sempre em texto puro)
# ----------------------------------------------------------------------
CSV_HEADER = ["title", "url", "username", "password", "notes", "category",
              "totp_secret", "favorite", "created_at", "updated_at"]

# Cabeçalhos aceitos na importação, mapeados para os campos internos.
CSV_ALIASES = {
    "title": "title", "name": "title", "nome": "title", "site": "title",
    "account": "title", "item name": "title",
    "url": "url", "login_uri": "url", "web site": "url", "website": "url",
    "username": "username", "login_username": "username", "user": "username",
    "usuario": "username", "usuário": "username", "login": "username",
    "e-mail": "username", "email": "username",
    "password": "password", "login_password": "password", "senha": "password",
    "notes": "notes", "note": "notes", "notas": "notes", "observacoes": "notes",
    "category": "category", "folder": "category", "grouping": "category",
    "group": "category", "categoria": "category", "type": "category",
    "totp": "totp_secret", "login_totp": "totp_secret", "otpauth": "totp_secret",
    "favorite": "favorite", "fav": "favorite", "favorito": "favorite",
}


def export_csv(entries: List[VaultEntry], path: str) -> int:
    """
    Exporta em texto puro para migração a outro gerenciador.

    **Não é backup.** A UI exige confirmação explícita antes de chamar isto.
    """
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADER)
        writer.writeheader()
        for entry in entries:
            row = _entry_to_dict(entry)
            writer.writerow({k: row.get(k, "") for k in CSV_HEADER})
    harden_path(path)
    return len(entries)


def import_csv(path: str) -> Tuple[List[VaultEntry], List[str]]:
    """Importa CSV do Bitwarden/LastPass/Chrome/KeePass. Retorna (registros, avisos)."""
    warnings: List[str] = []
    entries: List[VaultEntry] = []

    with open(path, "r", newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            raise BackupError("CSV vazio ou sem cabeçalho.")

        mapping = {}
        for column in reader.fieldnames:
            normalized = (column or "").strip().lower()
            if normalized in CSV_ALIASES:
                mapping.setdefault(CSV_ALIASES[normalized], column)

        if "password" not in mapping:
            raise BackupError(
                "Não encontrei uma coluna de senha no CSV. "
                f"Colunas lidas: {', '.join(reader.fieldnames)}"
            )

        for line_no, row in enumerate(reader, start=2):
            def value(field: str) -> str:
                column = mapping.get(field)
                return (row.get(column) or "").strip() if column else ""

            title = value("title")
            password = value("password")
            if not title and not password:
                continue
            if not title:
                title = value("url") or f"Importado (linha {line_no})"
                warnings.append(f"Linha {line_no}: sem título, usei “{title}”.")

            entries.append(
                VaultEntry(
                    title=title,
                    username=value("username"),
                    password=password,
                    url=value("url"),
                    notes=value("notes"),
                    category=value("category"),
                    totp_secret=value("totp_secret"),
                    favorite=value("favorite").lower() in ("1", "true", "yes", "sim"),
                )
            )

    if not entries:
        raise BackupError("Nenhum registro válido encontrado no CSV.")
    return entries, warnings


# ----------------------------------------------------------------------
def _entry_to_dict(entry: VaultEntry) -> Dict[str, Any]:
    data = asdict(entry)
    data.pop("row_id", None)
    data["favorite"] = bool(entry.favorite)
    return data


def _dict_to_entry(data: Dict[str, Any]) -> VaultEntry:
    allowed = set(VaultEntry.__annotations__) - {"row_id"}
    clean = {k: v for k, v in data.items() if k in allowed}
    clean["favorite"] = bool(clean.get("favorite", False))
    try:
        clean["rev"] = max(1, int(clean.get("rev") or 1))
    except (TypeError, ValueError):
        clean["rev"] = 1
    clean["deleted_at"] = str(clean.get("deleted_at") or "")
    clean["device_id"] = str(clean.get("device_id") or "")
    for key in ("title", "username", "password", "url", "notes", "category",
                "totp_secret", "uid", "created_at", "updated_at", "password_changed_at"):
        clean[key] = str(clean.get(key) or "")
    return VaultEntry(**clean)
