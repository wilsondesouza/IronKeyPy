"""
Entrada de um novo dispositivo no cofre existente ("pareamento", versão 1).

Por que isto é necessário
-------------------------
O backup ``.ikbak`` **não** serve para colocar um segundo dispositivo no mesmo
cofre: ao restaurá-lo, o aplicativo cria um cofre **novo**, com uma DEK nova e,
portanto, uma chave de sincronização diferente. Os dois dispositivos ficariam
com cofres distintos apontando para a mesma pasta — exatamente o cenário que
gera duplicação e conflito eterno.

Para sincronizar, os dois lados precisam da **mesma DEK** e do mesmo
``vault_id``. É isso que este módulo transfere, num arquivo próprio
(``*.ikenr``), protegido pela senha mestre do cofre:

    ironkeypy-entrada.ikenr  →  cabeçalho do cofre (kdf, vault_id, DEK embrulhada)

Decisões de segurança
---------------------
* A senha mestre é exigida **para exportar e para importar**, nas duas pontas.
  O arquivo não é um atalho para pular autenticação.
* O arquivo **não** fica na pasta de sincronização. Ele é transferido uma única
  vez, por um canal à escolha do usuário (pen drive, anexo, gerenciador de
  senhas). Guardá-lo na nuvem junto do cofre daria a um atacante, de uma só vez,
  o ciphertext do cofre e o material para ataque de dicionário offline contra a
  senha mestre — exposição que hoje só existe na máquina do usuário.
* Ao importar, o cofre **local** é substituído. Se já houver dados locais, uma
  cópia de segurança é feita antes e nada é apagado sem confirmação explícita.
* Sem a senha mestre correta, o arquivo é inútil: o conteúdo só é aceito depois
  de a DEK embrulhada ser efetivamente desembrulhada.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.app_paths import harden_path
from services.crypto_manager import CryptoManager, CryptoError
from services.secure_memory import SecretBytes

ENROLL_MAGIC = "IronKeyPy-Enroll"
ENROLL_VERSION = 1
ENROLL_AAD = b"ironkeypy.enroll.v1"
ENROLL_EXTENSION = ".ikenr"
NONCE_SIZE = 12

REQUIRED_HEADER_KEYS = ("format_version", "vault_id", "kdf", "wrapped_dek", "verifier")


class EnrollmentError(Exception):
    """Falha ao exportar/importar a entrada de dispositivo (mensagem exibível)."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ikenr-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        harden_path(tmp)
        os.replace(tmp, path)
        harden_path(path)
    except Exception:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise


def export_enrollment(crypto_manager: CryptoManager, master_password: str, path: str,
                      device_label: str = "") -> Dict[str, Any]:
    """
    Gera o arquivo de entrada a partir de um cofre **destravado**.

    O cabeçalho exportado é o do próprio cofre (mesmo salt de KDF, mesmo
    ``vault_id``, mesma DEK embrulhada), de modo que o dispositivo novo passa a
    ser criptograficamente idêntico ao original.
    """
    if not crypto_manager.is_unlocked():
        raise EnrollmentError("Destrave o cofre antes de exportar a entrada de dispositivo.")
    if not crypto_manager.verify_master_password(master_password):
        raise EnrollmentError("Senha mestre incorreta.")

    header = crypto_manager.export_header()
    missing = [key for key in REQUIRED_HEADER_KEYS if not header.get(key)]
    if missing:
        raise EnrollmentError(
            "O cabeçalho do cofre está incompleto (" + ", ".join(missing) + ")."
        )

    payload = {
        "created_at": _utcnow(),
        "source_device": device_label[:60],
        "header": header,
    }
    raw = gzip.compress(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"))

    kdf = CryptoManager.default_kdf_params()
    with CryptoManager._derive_kek(master_password, kdf) as key:  # noqa: SLF001 - mesma família
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(key.bytes()).encrypt(nonce, raw, ENROLL_AAD)

    envelope = {
        "magic": ENROLL_MAGIC,
        "version": ENROLL_VERSION,
        "created_at": payload["created_at"],
        "kdf": kdf,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "data": base64.b64encode(ciphertext).decode("ascii"),
    }
    _atomic_write(path, json.dumps(envelope, indent=2, sort_keys=True))
    return {"created_at": payload["created_at"], "path": path}


def read_enrollment(path: str, master_password: str) -> Dict[str, Any]:
    """Decifra e valida o arquivo de entrada. Não altera nada localmente."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise EnrollmentError(
            "Arquivo ilegível. Selecione um arquivo de entrada (.ikenr) do IronKey Py."
        ) from exc

    if envelope.get("magic") != ENROLL_MAGIC:
        raise EnrollmentError("Este arquivo não é um arquivo de entrada do IronKey Py.")
    if int(envelope.get("version", 0)) > ENROLL_VERSION:
        raise EnrollmentError(
            "Arquivo criado por uma versão mais recente do IronKey Py. Atualize o aplicativo."
        )

    try:
        with CryptoManager._derive_kek(master_password, envelope["kdf"]) as key:  # noqa: SLF001
            plain = AESGCM(key.bytes()).decrypt(
                base64.b64decode(envelope["nonce"]),
                base64.b64decode(envelope["data"]),
                ENROLL_AAD,
            )
    except InvalidTag as exc:
        raise EnrollmentError(
            "Senha mestre incorreta ou arquivo corrompido — a verificação falhou."
        ) from exc
    except (KeyError, ValueError, TypeError, CryptoError) as exc:
        raise EnrollmentError(f"Arquivo de entrada inválido: {exc}") from exc

    try:
        payload = json.loads(gzip.decompress(plain).decode("utf-8"))
        header = payload["header"]
        if not isinstance(header, dict):
            raise ValueError("cabeçalho ausente")
    except Exception as exc:
        raise EnrollmentError("Conteúdo do arquivo de entrada malformado.") from exc

    missing = [key for key in REQUIRED_HEADER_KEYS if not header.get(key)]
    if missing:
        raise EnrollmentError(
            "Cabeçalho incompleto no arquivo (" + ", ".join(missing) + ")."
        )
    return {"header": header, "created_at": payload.get("created_at", ""),
            "source_device": payload.get("source_device", "")}


def import_enrollment(path: str, master_password: str, config_path: str,
                      db_path: Optional[str] = None,
                      replace_existing: bool = False) -> Dict[str, Any]:
    """
    Instala o cabeçalho do cofre neste dispositivo.

    Antes de qualquer escrita, a DEK é **efetivamente desembrulhada** num arquivo
    temporário: se a senha mestre estiver errada ou o cabeçalho for inválido, nada
    acontece com o cofre atual.

    Se houver banco local com registros e ``replace_existing`` for falso, a
    operação é recusada — nunca se descarta dados do usuário por engano.
    """
    data = read_enrollment(path, master_password)
    header = data["header"]

    # Validação real: monta um cofre temporário e tenta destrancá-lo.
    probe_dir = tempfile.mkdtemp(prefix="ikp-enroll-")
    probe_config = os.path.join(probe_dir, "config.json")
    try:
        with open(probe_config, "w", encoding="utf-8") as fh:
            json.dump(header, fh, indent=2, sort_keys=True)
        probe = CryptoManager(config_file=probe_config)
        if not probe.unlock(master_password):
            raise EnrollmentError(
                "A senha mestre não corresponde a este arquivo de entrada."
            )
        probe.lock()
    except CryptoError as exc:
        raise EnrollmentError(f"Cabeçalho do cofre inválido: {exc}") from exc
    finally:
        try:
            shutil.rmtree(probe_dir, ignore_errors=True)
        except OSError:
            pass

    preserved_db: Optional[str] = None
    if db_path and os.path.exists(db_path):
        has_data = os.path.getsize(db_path) > 0
        if has_data and not replace_existing:
            raise EnrollmentError(
                "Este dispositivo já possui um cofre com dados. Confirme a substituição "
                "para continuar — uma cópia de segurança do cofre atual será mantida."
            )
        if has_data:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            preserved_db = f"{db_path}.substituido-{stamp}.bak"
            shutil.copy2(db_path, preserved_db)
            harden_path(preserved_db)
        for suffix in ("", "-wal", "-shm"):
            candidate = db_path + suffix
            if os.path.exists(candidate):
                os.remove(candidate)

    os.makedirs(os.path.dirname(os.path.abspath(config_path)) or ".", exist_ok=True)
    _atomic_write(config_path, json.dumps(header, indent=2, sort_keys=True))

    return {
        "created_at": data["created_at"],
        "source_device": data["source_device"],
        "vault_id": str(header.get("vault_id"))[:8] + "…",
        "preserved_db": preserved_db,
    }


def describe_header(header: Dict[str, Any]) -> str:
    """Resumo legível do cabeçalho (usado nas confirmações da interface)."""
    kdf = header.get("kdf") or {}
    algorithm = kdf.get("algorithm", "?")
    if algorithm == "argon2id":
        detail = (f"Argon2id (m={int(kdf.get('memory_cost', 0)) // 1024} MiB, "
                  f"t={kdf.get('time_cost')}, p={kdf.get('parallelism')})")
    else:
        detail = f"{algorithm} ({int(kdf.get('iterations', 0)):,} iterações)".replace(",", ".")
    return f"{detail} · cofre {str(header.get('vault_id'))[:8]}…"


__all__ = [
    "EnrollmentError", "export_enrollment", "read_enrollment", "import_enrollment",
    "describe_header", "ENROLL_EXTENSION",
]
