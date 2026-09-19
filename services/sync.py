from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import tempfile
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from database.database import UNREADABLE_TITLE, VaultEntry
from services.app_paths import harden_path
from services.secure_memory import SecretBytes

# ----------------------------------------------------------------------
# Constantes de formato (não alterar sem subir SYNC_VERSION)
# ----------------------------------------------------------------------
SYNC_MAGIC = "IronKeyPy-Sync"
SYNC_VERSION = 1
MANIFEST_MAGIC = "IronKeyPy-Sync-Manifest"
MANIFEST_VERSION = 1
SYNC_SCHEMA = 3

SYNC_PAYLOAD_NAME = "ironkeypy-sync.ikbak"
MANIFEST_NAME = "ironkeypy-sync.manifest.json"
CONSUMED_SUFFIX = ".mesclado"

SYNC_KEY_INFO = b"IronKeyPy/sync-key/v1"
MANIFEST_KEY_INFO = b"IronKeyPy/sync-manifest/v1"

NONCE_SIZE = 12
GENERATION_MAX = 9_223_372_036_854_775_807
CLOCK_TOLERANCE_SECONDS = 24 * 3600


class SyncError(Exception):
    """Falha de sincronização com mensagem pronta para exibir ao usuário."""

class SyncFormatError(SyncError):
    """Arquivo/estrutura inválida ou de versão não suportada."""

@dataclass
class SyncOutcome:

    status: str = "noop"          # ok | noop | disabled | error
    reason: str = "manual"        # manual | unlock | lock | timer
    added: int = 0
    updated: int = 0
    removed: int = 0
    purged: int = 0
    conflicts: int = 0
    resurrections: int = 0
    generation: int = 0
    message: str = ""
    warnings: List[str] = field(default_factory=list)

    @property
    def changed_locally(self) -> bool:
        return bool(self.added or self.updated or self.removed)

    def summary(self) -> str:
        if self.status == "error":
            return self.message or "Falha na sincronização."
        if self.status == "disabled":
            return self.message or "Sincronização desativada."
        parts = []
        if self.added:
            parts.append(f"{self.added} novo(s)")
        if self.updated:
            parts.append(f"{self.updated} atualizado(s)")
        if self.removed:
            parts.append(f"{self.removed} removido(s)")
        if self.purged:
            parts.append(f"{self.purged} excluído(s) definitivamente")
        if not parts:
            return "Cofre já estava atualizado."
        return "Sincronizado: " + ", ".join(parts) + "."


# ----------------------------------------------------------------------
# Utilidades de serialização
# ----------------------------------------------------------------------
def _canonical(obj: Any) -> bytes:
    """JSON canônico: chaves ordenadas, sem espaços, UTF-8 (base dos hashes/MACs)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _age_days(value: str) -> float:
    parsed = _parse_ts(value)
    if parsed is None:
        return 0.0
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400


def content_hash(entry: VaultEntry) -> str:
    """Hash do conteúdo do registro (sem metadados de ordenação) — §2.1 do contrato."""
    material = {
        "title": entry.title,
        "username": entry.username,
        "password": entry.password,
        "url": entry.url,
        "notes": entry.notes,
        "category": entry.category,
        "totp_secret": entry.totp_secret,
        "favorite": bool(entry.favorite),
        "password_changed_at": entry.password_changed_at,
    }
    return hashlib.sha256(_canonical(material)).hexdigest()


def _rank(entry: VaultEntry) -> Tuple[int, str, str]:
    """Chave de desempate determinística (rev é a autoridade; resto estabiliza)."""
    return (max(1, int(entry.rev or 1)), entry.updated_at or "", entry.device_id or "")


def _clone(entry: VaultEntry) -> VaultEntry:
    copy = VaultEntry(**entry.payload())
    copy.uid = entry.uid
    return copy


def _conflict_uid(uid: str, loser_hash: str, device_id: str) -> str:

    material = f"ironkeypy.conflict.v1|{uid}|{loser_hash}|{device_id}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


# ----------------------------------------------------------------------
# Chaves
# ----------------------------------------------------------------------
def _sync_key(crypto) -> SecretBytes:
    return crypto.derive_subkey(SYNC_KEY_INFO)


def _manifest_key(crypto) -> SecretBytes:
    return crypto.derive_subkey(MANIFEST_KEY_INFO)


def _payload_aad(header: Dict[str, Any]) -> bytes:
    return _canonical({
        "magic": header.get("magic"),
        "version": header.get("version"),
        "vault_id": header.get("vault_id"),
        "generation": header.get("generation"),
        "updated_by": header.get("updated_by"),
    })


def _manifest_mac(manifest_key: bytes, manifest: Dict[str, Any]) -> str:
    body = {k: v for k, v in manifest.items() if k != "mac"}
    return base64.b64encode(
        hmac.new(manifest_key, _canonical(body), hashlib.sha256).digest()
    ).decode("ascii")


# ----------------------------------------------------------------------
# Leitura/escrita do par arquivo + manifesto
# ----------------------------------------------------------------------
def _atomic_write_text(path: Path, text: str) -> None:
    """Gravação atômica com fsync do arquivo **e** do diretório."""
    directory = str(path.parent)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{path.name}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        harden_path(tmp)
        os.replace(tmp, path)
        _fsync_dir(directory)
    except Exception:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise


def _fsync_dir(directory: str) -> None:
    if os.name != "posix":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def build_payload(entries: List[VaultEntry], devices: List[Dict[str, Any]],
                  tombstone_max_age_days: int) -> Dict[str, Any]:

    serializable = []
    for entry in entries:
        if entry.title.endswith(UNREADABLE_TITLE):
            continue
        data = entry.payload()
        data["rev"] = max(1, int(entry.rev or 1))
        data["deleted_at"] = entry.deleted_at or ""
        data["device_id"] = entry.device_id or ""
        serializable.append(data)
    return {
        "schema": SYNC_SCHEMA,
        "created_at": _utcnow(),
        "purge": {"tombstone_max_age_days": int(tombstone_max_age_days)},
        "devices": devices,
        "entries": serializable,
    }


def encrypt_payload(payload: Dict[str, Any], crypto, vault_id: str,
                    generation: int, device_id: str, app: str) -> Dict[str, Any]:

    raw = gzip.compress(_canonical(payload))
    header = {
        "magic": SYNC_MAGIC,
        "version": SYNC_VERSION,
        "vault_id": vault_id,
        "generation": int(generation),
        "updated_at": _utcnow(),
        "updated_by": device_id,
        "app": app,
    }
    with _sync_key(crypto) as key:
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(key.bytes()).encrypt(nonce, raw, _payload_aad(header))
    header["nonce"] = base64.b64encode(nonce).decode("ascii")
    header["data"] = base64.b64encode(ciphertext).decode("ascii")
    return header


def write_remote(directory: str, payload: Dict[str, Any], crypto, vault_id: str,
                 device_id: str, generation: int, app: str) -> Dict[str, Any]:

    folder = Path(directory)
    payload_path = folder / SYNC_PAYLOAD_NAME
    manifest_path = folder / MANIFEST_NAME

    envelope = encrypt_payload(payload, crypto, vault_id, generation, device_id, app)
    _atomic_write_text(payload_path, json.dumps(envelope, indent=2))

    raw = payload_path.read_bytes()
    manifest = {
        "magic": MANIFEST_MAGIC,
        "version": MANIFEST_VERSION,
        "vault_id": vault_id,
        "generation": int(generation),
        "payload_file": SYNC_PAYLOAD_NAME,
        "payload_bytes": len(raw),
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "updated_at": envelope["updated_at"],
        "updated_by": device_id,
        "app": app,
    }
    with _manifest_key(crypto) as mkey:
        manifest["mac"] = _manifest_mac(mkey.bytes(), manifest)
    _atomic_write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


@dataclass
class RemoteSnapshot:

    payload: Optional[Dict[str, Any]]
    generation: int
    source_file: str
    warnings: List[str] = field(default_factory=list)


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _decrypt_envelope(envelope: Dict[str, Any], crypto, vault_id: str) -> Dict[str, Any]:
    if envelope.get("magic") != SYNC_MAGIC:
        raise SyncFormatError("O arquivo não é um arquivo de sincronização do IronKey Py.")
    if int(envelope.get("version", 0)) > SYNC_VERSION:
        raise SyncFormatError(
            "Arquivo de sincronização criado por uma versão mais nova do IronKey Py. "
            "Atualize o aplicativo neste dispositivo."
        )
    if envelope.get("vault_id") != vault_id:
        raise SyncFormatError(
            "O arquivo de sincronização pertence a outro cofre (identificador diferente)."
        )
    try:
        with _sync_key(crypto) as key:
            plain = AESGCM(key.bytes()).decrypt(
                base64.b64decode(envelope["nonce"]),
                base64.b64decode(envelope["data"]),
                _payload_aad(envelope),
            )
    except InvalidTag as exc:
        raise SyncFormatError(
            "Não foi possível abrir o arquivo de sincronização: ele foi alterado, "
            "corrompido, ou a chave do cofre mudou (rotação de chave)."
        ) from exc
    except (KeyError, ValueError) as exc:
        raise SyncFormatError("Arquivo de sincronização malformado.") from exc

    try:
        payload = json.loads(gzip.decompress(plain).decode("utf-8"))
    except Exception as exc:
        raise SyncFormatError("Conteúdo do arquivo de sincronização ilegível.") from exc

    if int(payload.get("schema", 0)) > SYNC_SCHEMA:
        raise SyncFormatError(
            "O cofre compartilhado usa um formato mais recente (schema "
            f"{payload.get('schema')}). Atualize o IronKey Py neste dispositivo antes "
            "de sincronizar — mesclar agora descartaria campos desconhecidos."
        )
    return payload


def _validate_manifest(manifest: Dict[str, Any], payload_path: Path, crypto,
                       vault_id: str) -> None:
    if manifest.get("magic") != MANIFEST_MAGIC:
        raise SyncFormatError("Manifesto de sincronização inválido.")
    if int(manifest.get("version", 0)) > MANIFEST_VERSION:
        raise SyncFormatError("Manifesto criado por uma versão mais nova do aplicativo.")
    if manifest.get("vault_id") != vault_id:
        raise SyncFormatError("Manifesto pertence a outro cofre.")
    with _manifest_key(crypto) as mkey:
        expected = _manifest_mac(mkey.bytes(), manifest)
    if not hmac.compare_digest(str(manifest.get("mac", "")), expected):
        raise SyncFormatError(
            "Manifesto de sincronização não autenticou — foi alterado ou está incompleto."
        )
    if not payload_path.exists():
        raise SyncFormatError("O arquivo de conteúdo ainda não chegou (sincronização parcial).")
    raw = payload_path.read_bytes()
    if manifest.get("payload_bytes") not in (None, len(raw)):
        raise SyncFormatError("Conteúdo incompleto na pasta (gravação em andamento).")
    if manifest.get("payload_sha256") and not hmac.compare_digest(
        str(manifest["payload_sha256"]), hashlib.sha256(raw).hexdigest()
    ):
        raise SyncFormatError("Conteúdo não confere com o manifesto (cópia parcial).")


def _conflict_candidates(directory: str) -> List[Path]:

    folder = Path(directory)
    base = Path(SYNC_PAYLOAD_NAME).stem
    patterns = (f"{base} (*).ikbak", f"{base}-conflito*.ikbak", f"*{base}*conflito*.ikbak")
    found: List[Path] = []
    for pattern in patterns:
        for path in folder.glob(pattern):
            if path.name.endswith(CONSUMED_SUFFIX) or path in found:
                continue
            found.append(path)
    return found


def read_remote(directory: str, crypto, vault_id: str,
                consume_conflicts: bool = True) -> RemoteSnapshot:

    folder = Path(directory)
    warnings: List[str] = []
    candidates: List[Tuple[int, Dict[str, Any], str]] = []

    manifest_path = folder / MANIFEST_NAME
    if manifest_path.exists():
        try:
            manifest = _read_json(manifest_path)
            payload_path = folder / str(manifest.get("payload_file") or SYNC_PAYLOAD_NAME)
            _validate_manifest(manifest, payload_path, crypto, vault_id)
            payload = _decrypt_envelope(_read_json(payload_path), crypto, vault_id)
            candidates.append((int(manifest.get("generation", 0)), payload, payload_path.name))
        except (SyncError, OSError, ValueError) as exc:
            warnings.append(f"Manifesto ignorado: {exc}")

    for path in _conflict_candidates(directory):
        try:
            envelope = _read_json(path)
            payload = _decrypt_envelope(envelope, crypto, vault_id)
            candidates.append((int(envelope.get("generation", 0)), payload, path.name))
            warnings.append(f"Cópia de conflito do serviço de nuvem incorporada: {path.name}")
            if consume_conflicts:
                try:
                    os.replace(path, path.with_name(path.name + CONSUMED_SUFFIX))
                except OSError:
                    pass
        except (SyncError, OSError, ValueError):
            continue

    if not candidates:
        return RemoteSnapshot(payload=None, generation=0, source_file="", warnings=warnings)
    generation, payload, source = max(candidates, key=lambda item: item[0])
    return RemoteSnapshot(payload=payload, generation=generation,
                          source_file=source, warnings=warnings)

# ----------------------------------------------------------------------
# Mesclagem
# ----------------------------------------------------------------------
@dataclass
class MergeResult:
    entries: List[VaultEntry]
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    resurrections: List[Dict[str, Any]] = field(default_factory=list)
    changed: bool = False

def merge_states(local: List[VaultEntry], remote: List[VaultEntry], *,
                 device_id: str, device_label: str = "",
                 purged_uids: Optional[Iterable[str]] = None,
                 now: Optional[str] = None) -> MergeResult:
    """
    Mescla dois estados de cofre. Função **pura**: não toca banco nem disco.

    Regras (contrato §6):
      * maior ``rev`` vence — nunca o relógio, que pode estar errado;
      * ``rev`` iguais + um tombstone → vence o tombstone (exclusão é intenção);
      * ``rev`` iguais + conteúdos iguais → convergiram, nada a fazer;
      * ``rev`` iguais + conteúdos diferentes → **conflito**: ninguém é
        descartado; o perdedor vira registro novo com uid determinístico.
    """
    now = now or _utcnow()
    purged = set(purged_uids or ())
    local_by_uid = {e.uid: e for e in local if e.uid}
    remote_by_uid = {e.uid: e for e in remote if e.uid}

    merged: Dict[str, VaultEntry] = {}
    conflicts: List[Dict[str, Any]] = []
    resurrections: List[Dict[str, Any]] = []

    for uid in sorted(set(local_by_uid) | set(remote_by_uid)):
        mine = local_by_uid.get(uid)
        theirs = remote_by_uid.get(uid)

        if mine is None:
            candidate = _clone(theirs)
            if not candidate.is_deleted and uid in purged:
                # Já foi excluído aqui e o tombstone já expirou: só pode ser um
                # dispositivo muito tempo offline ressuscitando o registro.
                resurrections.append({
                    "kind": "resurrection",
                    "uid": uid,
                    "title": candidate.title,
                    "device_id": candidate.device_id,
                    "detected_at": now,
                })
            merged[uid] = candidate
            continue

        if theirs is None:
            merged[uid] = _clone(mine)
            continue

        if mine.rev != theirs.rev:
            winner = mine if mine.rev > theirs.rev else theirs
            merged[uid] = _clone(winner)
            continue

        # rev iguais
        if mine.is_deleted != theirs.is_deleted:
            winner = mine if mine.is_deleted else theirs
            merged[uid] = _clone(winner)
            continue

        if content_hash(mine) == content_hash(theirs):
            merged[uid] = _clone(mine if _rank(mine) >= _rank(theirs) else theirs)
            continue

        if mine.is_deleted and theirs.is_deleted:
            merged[uid] = _clone(mine if _rank(mine) >= _rank(theirs) else theirs)
            continue

        winner, loser = (mine, theirs) if _rank(mine) >= _rank(theirs) else (theirs, mine)
        kept = _clone(winner)
        kept.rev = max(1, int(kept.rev or 1)) + 1
        kept.updated_at = now
        kept.device_id = device_id or kept.device_id

        copy = _clone(loser)
        copy.uid = _conflict_uid(uid, content_hash(loser), loser.device_id or "desconhecido")
        copy.rev = 1
        copy.title = _conflict_title(loser.display_title, device_label, now)
        copy.device_id = loser.device_id

        merged[uid] = kept
        merged.setdefault(copy.uid, copy)
        conflicts.append({
            "kind": "same_rev",
            "uid": uid,
            "kept_uid": uid,
            "kept_title": kept.title,
            "kept_rev": kept.rev,
            "lost_uid": copy.uid,
            "lost_title": copy.title,
            "lost_rev": loser.rev,
            "device_id": loser.device_id or "",
            "detected_at": now,
        })

    # Ordem estável evita reescritas espúrias do arquivo a cada sincronização.
    entries = [merged[uid] for uid in sorted(merged)]
    changed = _state_fingerprint(entries) != _state_fingerprint(local_by_uid.values())
    return MergeResult(entries=entries, conflicts=conflicts,
                       resurrections=resurrections, changed=changed)

def _conflict_title(title: str, device_label: str, when: str) -> str:
    stamp = (when or "")[:16].replace("T", " ")
    label = _strip_accents(device_label or "outro dispositivo")
    suffix = f" (conflito: {label} {stamp})".strip()
    return (title or "(sem título)")[:180] + suffix

def _strip_accents(text: str) -> str:
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch)
    )

def _state_fingerprint(entries: Iterable[VaultEntry]) -> List[tuple]:
    """Assinatura do estado, para detectar mudança real (independe de ordem)."""
    return sorted(
        (e.uid, max(1, int(e.rev or 1)), content_hash(e), bool(e.is_deleted))
        for e in entries
    )

# ----------------------------------------------------------------------
# Estado de dispositivos
# ----------------------------------------------------------------------
def merge_devices(remote_devices: List[Dict[str, Any]], device_id: str,
                  device_label: str, now: Optional[str] = None) -> List[Dict[str, Any]]:
    """Une a lista de dispositivos, atualizando a entrada deste dispositivo."""
    now = now or _utcnow()
    by_id: Dict[str, Dict[str, Any]] = {}
    for item in remote_devices or []:
        if isinstance(item, dict) and item.get("device_id"):
            by_id[str(item["device_id"])] = {
                "device_id": str(item["device_id"]),
                "label": str(item.get("label") or "")[:60],
                "last_seen": str(item.get("last_seen") or ""),
            }
    current = by_id.get(device_id, {"device_id": device_id, "label": "", "last_seen": ""})
    current["last_seen"] = now
    if device_label:
        current["label"] = device_label[:60]
    by_id[device_id] = current
    return [by_id[key] for key in sorted(by_id)]

# ----------------------------------------------------------------------
# Orquestração
# ----------------------------------------------------------------------
class SyncEngine:

    def __init__(self, database, crypto_manager, settings, app_version: str = ""):
        self.db = database
        self.crypto = crypto_manager
        self.settings = settings
        self.app_version = f"IronKeyPy {app_version}".strip()

    # -- validação de configuração -------------------------------------
    def validate_directory(self, directory: str) -> Tuple[bool, str]:
        if not directory:
            return False, "Nenhuma pasta de sincronização escolhida."
        path = Path(directory).expanduser()
        if not path.exists():
            return False, "A pasta escolhida não existe."
        if not path.is_dir():
            return False, "O caminho escolhido não é uma pasta."
        from services.app_paths import get_app_data_dir

        try:
            if path.resolve() == get_app_data_dir().resolve():
                return False, (
                    "A pasta de sincronização não pode ser a própria pasta de dados do "
                    "IronKey Py: elas guardam arquivos diferentes."
                )
        except OSError:
            pass
        if not os.access(path, os.R_OK | os.W_OK):
            return False, "Sem permissão de leitura/escrita na pasta escolhida."
        return True, ""

    # -- sincronização --------------------------------------------------
    def synchronize(self, reason: str = "manual") -> SyncOutcome:
        outcome = SyncOutcome(reason=reason)
        try:
            return self._synchronize(outcome)
        except SyncError as exc:
            outcome.status = "error"
            outcome.message = str(exc)
            return outcome
        except OSError as exc:
            outcome.status = "error"
            outcome.message = f"Falha de acesso à pasta de sincronização: {exc}"
            return outcome
        except Exception as exc:  # pragma: no cover - rede de segurança da UI
            outcome.status = "error"
            outcome.message = f"Erro inesperado na sincronização: {exc}"
            return outcome

    def _synchronize(self, outcome: SyncOutcome) -> SyncOutcome:
        if not self.settings.sync_enabled:
            outcome.status = "disabled"
            outcome.message = "Sincronização desativada nas configurações."
            return outcome
        if not self.crypto.is_unlocked():
            outcome.status = "error"
            outcome.message = "O cofre precisa estar destravado para sincronizar."
            return outcome

        directory = self.settings.sync_dir
        ok, problem = self.validate_directory(directory)
        if not ok:
            outcome.status = "error"
            outcome.message = problem
            return outcome

        vault_id = base64.b64encode(self.crypto.vault_id_bytes()).decode("ascii")
        device_id = self.settings.device_id
        device_label = self.settings.device_name
        self.db.set_device_id(device_id)

        snapshot = read_remote(directory, self.crypto, vault_id)
        outcome.warnings.extend(snapshot.warnings)
        remote_payload = snapshot.payload or {}

        remote_entries: List[VaultEntry] = []
        remote_devices: List[Dict[str, Any]] = []
        remote_generation = 0
        remote_purge_days = self.settings.tombstone_max_age_days
        if remote_payload:
            remote_entries = _entries_from_payload(remote_payload)
            remote_devices = list(remote_payload.get("devices") or [])
            remote_generation = snapshot.generation
            # Nunca purgar antes do que o outro lado ainda espera (§6.5).
            remote_purge_days = max(
                remote_purge_days,
                int((remote_payload.get("purge") or {}).get(
                    "tombstone_max_age_days", 0) or 0),
            )

        known_generation = _int_or_zero(self.db.get_meta("sync_last_generation", "0"))
        if remote_payload and remote_generation < known_generation:
            outcome.warnings.append(
                "O arquivo de sincronização regrediu de geração "
                f"({remote_generation} < {known_generation}) — provavelmente uma versão "
                "antiga restaurada pela nuvem. O merge foi feito mesmo assim."
            )

        local_entries = self.db.get_state_for_sync()
        local_by_uid = {e.uid: e for e in local_entries}

        purged_uids = [item.get("uid") for item in self.db.get_purged_uids() if item.get("uid")]
        result = merge_states(
            local_entries, remote_entries,
            device_id=device_id, device_label=device_label,
            purged_uids=purged_uids,
        )

        added = sum(1 for e in result.entries if e.uid not in local_by_uid)
        updated = sum(
            1 for e in result.entries
            if e.uid in local_by_uid and _state_fingerprint([e]) != _state_fingerprint([local_by_uid[e.uid]])
        )
        remove_uids = [uid for uid in local_by_uid if uid not in {e.uid for e in result.entries}]

        if result.changed or remove_uids:
            self.db.apply_sync_state(result.entries, remove_uids)
        outcome.added, outcome.updated, outcome.removed = added, updated, len(remove_uids)

        for conflict in result.conflicts:
            self.db.log_conflict(conflict["uid"], conflict.get("device_id", ""), conflict)
        for resurrection in result.resurrections:
            self.db.log_conflict(resurrection["uid"], resurrection.get("device_id", ""),
                                 resurrection)
        outcome.conflicts = len(result.conflicts)
        outcome.resurrections = len(result.resurrections)

        outcome.purged = self.db.purge_tombstones(remote_purge_days)

        now = _utcnow()
        devices = merge_devices(remote_devices, device_id, device_label, now)
        payload = build_payload(
            self.db.get_state_for_sync(), devices, remote_purge_days
        )
        generation = min(GENERATION_MAX, max(remote_generation, known_generation) + 1)
        manifest = write_remote(
            directory, payload, self.crypto, vault_id, device_id, generation,
            self.app_version,
        )

        self.db.set_meta("sync_last_generation", str(generation))
        self.db.set_meta("sync_last_at", now)
        self.db.set_meta("sync_last_hash", manifest["payload_sha256"])
        self.db.set_meta("sync_last_dir", directory)

        outcome.generation = generation
        outcome.status = "ok"
        outcome.message = outcome.summary()
        if outcome.conflicts:
            outcome.warnings.append(
                f"{outcome.conflicts} conflito(s) de edição simultânea: as duas versões "
                "foram mantidas e a duplicata está marcada com “(conflito: …)”."
            )
        if outcome.resurrections:
            outcome.warnings.append(
                f"{outcome.resurrections} registro(s) reapareceram de um dispositivo que "
                "ficou muito tempo sem sincronizar — confira antes de apagar."
            )
        self.db.invalidate_cache()
        return outcome

    # -- estado para a UI ----------------------------------------------
    def status(self) -> Dict[str, Any]:
        configured = self.settings.sync_enabled and bool(self.settings.sync_dir)
        last_at = self.db.get_meta("sync_last_at", "") if configured else ""
        return {
            "enabled": bool(self.settings.sync_enabled),
            "directory": self.settings.sync_dir,
            "configured": configured,
            "last_at": last_at,
            "last_generation": _int_or_zero(self.db.get_meta("sync_last_generation", "0")),
            "device_name": self.settings.device_name,
            "pending_conflicts": self.db.count_pending_conflicts() if configured else 0,
            "tombstones": len(self.db.get_tombstones()) if configured else 0,
        }

def _entries_from_payload(payload: Dict[str, Any]) -> List[VaultEntry]:
    """Converte o JSON do arquivo de sync em registros (tolerante a campos ausentes)."""
    allowed = set(VaultEntry.__annotations__) - {"row_id", "rev", "deleted_at", "device_id"}
    entries: List[VaultEntry] = []
    for raw in payload.get("entries") or []:
        if not isinstance(raw, dict) or not raw.get("uid"):
            continue
        clean = {k: v for k, v in raw.items() if k in allowed}
        clean["favorite"] = bool(clean.get("favorite", False))
        for key in ("title", "username", "password", "url", "notes", "category",
                    "totp_secret", "uid", "created_at", "updated_at", "password_changed_at"):
            clean[key] = str(clean.get(key) or "")
        try:
            entry = VaultEntry(**clean)
            entry.rev = max(1, int(raw.get("rev") or 1))
        except (TypeError, ValueError):
            continue
        entry.deleted_at = str(raw.get("deleted_at") or "")
        entry.device_id = str(raw.get("device_id") or "")
        entries.append(entry)
    return entries

def _int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def sync_filename_pattern() -> str:
    """Padrão documentado dos arquivos criados na pasta do usuário (ajuda/UI)."""
    return f"{SYNC_PAYLOAD_NAME!r} + {MANIFEST_NAME!r}"


__all__ = [
    "SyncEngine", "SyncOutcome", "SyncError", "SyncFormatError", "RemoteSnapshot",
    "MergeResult", "merge_states", "merge_devices", "read_remote", "write_remote",
    "build_payload", "encrypt_payload", "content_hash", "sync_filename_pattern",
    "SYNC_PAYLOAD_NAME", "MANIFEST_NAME", "SYNC_VERSION", "SYNC_SCHEMA",
    "MERGED_FILES", "CONSUMED_SUFFIX",
]

MERGED_FILES = (SYNC_PAYLOAD_NAME, MANIFEST_NAME)