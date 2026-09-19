"""
Núcleo criptográfico do IronKey Py.

Modelo de segurança (formato de cofre v2)
-----------------------------------------
    senha mestre --Argon2id/PBKDF2--> KEK (32B)
    KEK --AES-256-GCM--> desembrulha a DEK (32B, aleatória)
    DEK --AES-256-GCM--> cifra cada registro do cofre

Envelope encryption (KEK/DEK) traz três ganhos diretos sobre a versão anterior,
que derivava a chave Fernet diretamente da senha mestre:

1. **Troca de senha mestre em O(1)**: basta reembrulhar a DEK; o banco inteiro
   permanece intacto (antes, era impossível trocar a senha mestre).
2. **AEAD real com dados associados**: AES-256-GCM autentica o cabeçalho do
   cofre, impedindo que um atacante troque o salt/parâmetros de KDF ou mova
   ciphertexts entre registros (ataque de "cut-and-paste").
3. **Rotação de parâmetros de KDF** sem reprocessar o cofre.

Correções de vulnerabilidade em relação à versão anterior
---------------------------------------------------------
* ``verify_master_password`` retornava ``True`` quando a chave ``test_data``
  não existia no ``config.json`` — bastava editar o arquivo (texto puro, sem
  integridade) para entrar no cofre. Agora a verificação **falha fechada**.
* PBKDF2 com 100.000 iterações estava abaixo da recomendação atual do OWASP
  (600.000 para HMAC-SHA256). O padrão passou a ser Argon2id; PBKDF2-SHA256
  com 600k iterações é o fallback.
* Fernet usa AES-128-CBC + HMAC-SHA256; migramos para AES-256-GCM (AEAD),
  mantendo leitura de cofres legados para migração automática.
* Escrita do cabeçalho agora é atômica (tmp + ``os.replace``) e com permissão
  0600, evitando cofre corrompido por queda de energia e leitura por outros
  usuários da máquina.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from services.app_paths import harden_path
from services.secure_memory import SecretBytes

try:  # cryptography >= 44
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover - depende da versão instalada
    Argon2id = None  # type: ignore[assignment]
    ARGON2_AVAILABLE = False


FORMAT_VERSION = 2
KEY_SIZE = 32          # AES-256
NONCE_SIZE = 12        # 96 bits, recomendado para GCM
SALT_SIZE = 16
VERIFIER_PLAINTEXT = b"IronKeyPy/vault-verifier/v2"

# Parâmetros padrão do Argon2id (RFC 9106, "second recommended option"
# reforçada): 128 MiB e 4 passagens. Custa ~0,3-1,0 s em um desktop típico —
# imperceptível no login e proibitivamente caro para ataque em GPU/ASIC,
# justamente por exigir 128 MiB por tentativa paralela.
ARGON2_DEFAULTS = {
    "algorithm": "argon2id",
    "time_cost": 4,
    "memory_cost": 131072,   # KiB => 128 MiB
    "parallelism": 4,
}

# Fallback quando Argon2id não está disponível (OWASP 2023: >= 600k).
PBKDF2_DEFAULTS = {
    "algorithm": "pbkdf2-sha256",
    "iterations": 600_000,
}


class CryptoError(Exception):
    """Erro genérico de criptografia (mensagens seguras para exibir na UI)."""


class VaultLockedError(CryptoError):
    """Operação exigiu o cofre destrancado."""


class InvalidMasterPassword(CryptoError):
    """Senha mestre incorreta ou cabeçalho adulterado."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CryptoManager:
    """Gerencia o cabeçalho do cofre, a KEK derivada e a DEK de dados."""

    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self._dek: Optional[SecretBytes] = None
        self._header: Dict[str, Any] = {}
        self._legacy_fernet = None  # usado apenas durante a migração de cofres v1
        self._load_header()

    # ------------------------------------------------------------------
    # Cabeçalho do cofre
    # ------------------------------------------------------------------
    def _load_header(self) -> None:
        if not os.path.exists(self.config_file):
            self._header = {}
            return
        try:
            with open(self.config_file, "r", encoding="utf-8") as fh:
                self._header = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise CryptoError(
                "O arquivo de configuração do cofre está corrompido ou ilegível. "
                "Restaure um backup antes de continuar."
            ) from exc

    def _write_header(self, header: Dict[str, Any]) -> None:
        """Gravação atômica: evita cabeçalho truncado (= cofre inacessível)."""
        directory = os.path.dirname(os.path.abspath(self.config_file)) or "."
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".config-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(header, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            harden_path(tmp_path)
            os.replace(tmp_path, self.config_file)
            harden_path(self.config_file)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        self._header = header

    def _header_aad(self, header: Dict[str, Any]) -> bytes:
        """
        Dados associados que amarram a DEK embrulhada ao cabeçalho.

        Qualquer alteração no salt ou nos parâmetros de KDF invalida a tag GCM,
        de modo que um cofre adulterado é rejeitado em vez de aceito.
        """
        material = {
            "format_version": header.get("format_version"),
            "kdf": header.get("kdf"),
            "vault_id": header.get("vault_id"),
        }
        return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # ------------------------------------------------------------------
    # Derivação de chave
    # ------------------------------------------------------------------
    @staticmethod
    def default_kdf_params() -> Dict[str, Any]:
        params = dict(ARGON2_DEFAULTS if ARGON2_AVAILABLE else PBKDF2_DEFAULTS)
        params["salt"] = _b64e(os.urandom(SALT_SIZE))
        return params

    @staticmethod
    def _derive_kek(master_password: str, kdf: Dict[str, Any]) -> SecretBytes:
        salt = _b64d(kdf["salt"])
        password = master_password.encode("utf-8")
        algorithm = kdf.get("algorithm", "pbkdf2-sha256")

        if algorithm == "argon2id":
            if not ARGON2_AVAILABLE:
                raise CryptoError(
                    "Este cofre usa Argon2id, mas a biblioteca 'cryptography' "
                    "instalada é antiga. Atualize com: pip install -U cryptography"
                )
            kdf_impl = Argon2id(
                salt=salt,
                length=KEY_SIZE,
                iterations=int(kdf.get("time_cost", 3)),
                lanes=int(kdf.get("parallelism", 4)),
                memory_cost=int(kdf.get("memory_cost", 65536)),
            )
        elif algorithm == "pbkdf2-sha256":
            kdf_impl = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=KEY_SIZE,
                salt=salt,
                iterations=int(kdf.get("iterations", 600_000)),
            )
        else:
            raise CryptoError(f"Algoritmo de derivação desconhecido: {algorithm!r}")

        try:
            return SecretBytes(kdf_impl.derive(password))
        except MemoryError as exc:  # pragma: no cover - máquinas muito limitadas
            raise CryptoError(
                "Memória insuficiente para derivar a chave com os parâmetros "
                "deste cofre. Feche outros programas e tente novamente."
            ) from exc

    # ------------------------------------------------------------------
    # Ciclo de vida do cofre
    # ------------------------------------------------------------------
    def is_initialized(self) -> bool:
        return bool(self._header) and (
            "wrapped_dek" in self._header or self._header.get("initialized") is True
        )

    def is_legacy_vault(self) -> bool:
        """Cofre criado pela versão 1.x (Fernet + PBKDF2 100k)."""
        return bool(self._header) and self._header.get("format_version") is None and (
            "test_data" in self._header or "salt" in self._header
        )

    def is_unlocked(self) -> bool:
        return self._dek is not None

    def create_vault(self, master_password: str) -> None:
        """Cria um cofre novo (primeira execução)."""
        if self.is_initialized():
            raise CryptoError("O cofre já foi inicializado.")

        kdf = self.default_kdf_params()
        header: Dict[str, Any] = {
            "format_version": FORMAT_VERSION,
            "vault_id": _b64e(os.urandom(8)),
            "kdf": kdf,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
        }

        dek = SecretBytes(AESGCM.generate_key(bit_length=256))
        with self._derive_kek(master_password, kdf) as kek:
            header["wrapped_dek"] = self._wrap_dek(kek.bytes(), dek.bytes(), self._header_aad(header))
        header["verifier"] = self._make_verifier(dek.bytes())

        self._write_header(header)
        self._dek = dek

    def unlock(self, master_password: str) -> bool:
        """
        Destranca o cofre. Retorna ``False`` para senha incorreta.

        Falha fechada: qualquer inconsistência do cabeçalho resulta em recusa.
        """
        if not self._header:
            return False

        if self.is_legacy_vault():
            return self._unlock_legacy(master_password)

        kdf = self._header.get("kdf")
        wrapped = self._header.get("wrapped_dek")
        verifier = self._header.get("verifier")
        if not kdf or not wrapped or not verifier:
            raise CryptoError(
                "Cabeçalho do cofre incompleto ou adulterado. "
                "Restaure um backup para recuperar o acesso."
            )

        try:
            with self._derive_kek(master_password, kdf) as kek:
                dek_raw = self._unwrap_dek(kek.bytes(), wrapped, self._header_aad(self._header))
        except InvalidTag:
            return False

        dek = SecretBytes(dek_raw)
        if not self._check_verifier(dek.bytes(), verifier):
            dek.wipe()
            return False

        self._dek = dek
        return True

    def lock(self) -> None:
        if self._dek is not None:
            self._dek.wipe()
            self._dek = None
        self._legacy_fernet = None

    # Compatibilidade com a API antiga -----------------------------------
    def initialize(self, master_password: str) -> bool:
        """Alias legado de :meth:`unlock` (mantido para não quebrar chamadas)."""
        try:
            return self.unlock(master_password)
        except CryptoError:
            return False

    def verify_master_password(self, master_password: str) -> bool:
        """
        Verifica a senha mestre **sem** manter o cofre destrancado.

        Diferente da versão anterior, nunca retorna ``True`` por ausência de
        dados de verificação.
        """
        if not self._header:
            return False
        if self.is_legacy_vault():
            return self._verify_legacy(master_password)

        kdf = self._header.get("kdf")
        wrapped = self._header.get("wrapped_dek")
        verifier = self._header.get("verifier")
        if not kdf or not wrapped or not verifier:
            return False
        try:
            with self._derive_kek(master_password, kdf) as kek:
                dek_raw = self._unwrap_dek(kek.bytes(), wrapped, self._header_aad(self._header))
        except (InvalidTag, CryptoError):
            return False
        try:
            return self._check_verifier(dek_raw, verifier)
        finally:
            SecretBytes(dek_raw).wipe()

    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Reembrulha a DEK com uma KEK nova.

        O banco de dados **não** é reprocessado: os registros continuam cifrados
        com a mesma DEK. A operação é atômica no nível do cabeçalho.
        """
        if not self.verify_master_password(current_password):
            return False
        if self._dek is None and not self.unlock(current_password):
            return False
        assert self._dek is not None

        header = json.loads(json.dumps(self._header))  # cópia profunda
        header["format_version"] = FORMAT_VERSION
        header["kdf"] = self.default_kdf_params()   # salt novo + parâmetros atuais
        header["updated_at"] = _utcnow()
        header.setdefault("vault_id", _b64e(os.urandom(8)))
        # Remove resquícios do formato legado.
        header.pop("test_data", None)
        header.pop("salt", None)
        header.pop("initialized", None)

        with self._derive_kek(new_password, header["kdf"]) as kek:
            header["wrapped_dek"] = self._wrap_dek(
                kek.bytes(), self._dek.bytes(), self._header_aad(header)
            )
        header["verifier"] = self._make_verifier(self._dek.bytes())
        self._write_header(header)
        return True

    # ------------------------------------------------------------------
    # Primitivas de embrulho / verificação
    # ------------------------------------------------------------------
    @staticmethod
    def _wrap_dek(kek: bytes, dek: bytes, aad: bytes) -> str:
        nonce = os.urandom(NONCE_SIZE)
        blob = AESGCM(kek).encrypt(nonce, dek, aad)
        return _b64e(nonce + blob)

    @staticmethod
    def _unwrap_dek(kek: bytes, wrapped: str, aad: bytes) -> bytes:
        raw = _b64d(wrapped)
        return AESGCM(kek).decrypt(raw[:NONCE_SIZE], raw[NONCE_SIZE:], aad)

    @staticmethod
    def _make_verifier(dek: bytes) -> str:
        nonce = os.urandom(NONCE_SIZE)
        return _b64e(nonce + AESGCM(dek).encrypt(nonce, VERIFIER_PLAINTEXT, b"verifier"))

    @staticmethod
    def _check_verifier(dek: bytes, verifier: str) -> bool:
        try:
            raw = _b64d(verifier)
            plain = AESGCM(dek).decrypt(raw[:NONCE_SIZE], raw[NONCE_SIZE:], b"verifier")
        except Exception:
            return False
        return secrets.compare_digest(plain, VERIFIER_PLAINTEXT)

    # ------------------------------------------------------------------
    # Cifragem de dados do cofre
    # ------------------------------------------------------------------
    def encrypt(self, data: str, aad: bytes = b"ironkeypy.record.v2") -> str:
        if self._dek is None:
            raise VaultLockedError("O cofre está trancado.")
        nonce = os.urandom(NONCE_SIZE)
        blob = AESGCM(self._dek.bytes()).encrypt(nonce, data.encode("utf-8"), aad)
        return _b64e(nonce + blob)

    def decrypt(self, encrypted_data: str, aad: bytes = b"ironkeypy.record.v2") -> str:
        if self._dek is None:
            raise VaultLockedError("O cofre está trancado.")
        try:
            raw = _b64d(encrypted_data)
            plain = AESGCM(self._dek.bytes()).decrypt(raw[:NONCE_SIZE], raw[NONCE_SIZE:], aad)
            return plain.decode("utf-8")
        except InvalidTag:
            # Pode ser registro legado (Fernet) durante a migração.
            legacy = self._try_legacy_decrypt(encrypted_data)
            if legacy is not None:
                return legacy
            raise CryptoError(
                "Registro corrompido ou adulterado (falha na verificação de integridade)."
            )
        except Exception:
            legacy = self._try_legacy_decrypt(encrypted_data)
            if legacy is not None:
                return legacy
            raise CryptoError("Não foi possível decifrar o registro.")

    def export_header(self) -> Dict[str, Any]:
        """
        Cópia do cabeçalho do cofre (KDF, ``vault_id``, DEK embrulhada, verifier).

        É o que a entrada de dispositivo (``services/enrollment.py``) transfere:
        dois dispositivos com o **mesmo** cabeçalho compartilham a DEK e, com ela,
        a chave de sincronização. A DEK não é exposta em claro — continua
        embrulhada pela KEK derivada da senha mestre.
        """
        return json.loads(json.dumps(self._header))

    def vault_id_bytes(self) -> bytes:
        """``vault_id`` decodificado, usado como salt das subchaves do cofre."""
        raw = self._header.get("vault_id")
        if not raw:
            raise CryptoError("Cabeçalho do cofre não possui identificador.")
        try:
            return _b64d(raw)
        except Exception as exc:  # pragma: no cover - cabeçalho adulterado
            raise CryptoError("Identificador do cofre inválido.") from exc

    def derive_subkey(self, purpose: bytes, length: int = KEY_SIZE) -> SecretBytes:
        """
        Deriva uma subchave da DEK via HKDF (usada por backups e pela sincronização).

        ``vault_id`` entra como salt e ``purpose`` como ``info``: cada finalidade
        recebe uma chave distinta, e uma subchave só vale para **este** cofre.

        Consequências: nada novo para armazenar ou para o usuário digitar; trocar
        a senha mestre não muda as subchaves (a DEK não muda); **rotacionar a DEK
        invalida todas elas**, então quem depende de uma (a sincronização) precisa
        tratar isso explicitamente.
        """
        if self._dek is None:
            raise VaultLockedError("O cofre está trancado.")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=self.vault_id_bytes(),
            info=bytes(purpose),
        )
        with SecretBytes(self._dek.bytes()) as material:
            return SecretBytes(hkdf.derive(material.bytes()))

    # ------------------------------------------------------------------
    # Suporte a cofres legados (v1: Fernet + PBKDF2 100k)
    # ------------------------------------------------------------------
    def _legacy_key(self, master_password: str) -> bytes:
        salt = _b64d(self._header["salt"])
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))

    def _verify_legacy(self, master_password: str) -> bool:
        from cryptography.fernet import Fernet

        test_data = self._header.get("test_data")
        if not test_data:
            # Falha fechada: sem material de verificação não há como validar.
            return False
        try:
            Fernet(self._legacy_key(master_password)).decrypt(_b64d(test_data))
            return True
        except Exception:
            return False

    def _unlock_legacy(self, master_password: str) -> bool:
        from cryptography.fernet import Fernet

        if not self._verify_legacy(master_password):
            return False
        self._legacy_fernet = Fernet(self._legacy_key(master_password))
        # A DEK temporária permite ler o cofre antigo enquanto a migração roda.
        self._dek = SecretBytes(AESGCM.generate_key(bit_length=256))
        return True

    def _try_legacy_decrypt(self, encrypted_data: str) -> Optional[str]:
        if self._legacy_fernet is None:
            return None
        try:
            return self._legacy_fernet.decrypt(_b64d(encrypted_data)).decode("utf-8")
        except Exception:
            return None

    def finalize_migration(self, master_password: str) -> None:
        """
        Converte um cofre v1 para v2 preservando a DEK temporária já em uso.

        Deve ser chamado **depois** que o banco reescreveu todos os registros
        com a DEK nova.
        """
        if self._dek is None:
            raise VaultLockedError("O cofre está trancado.")

        header: Dict[str, Any] = {
            "format_version": FORMAT_VERSION,
            "vault_id": _b64e(os.urandom(8)),
            "kdf": self.default_kdf_params(),
            "created_at": self._header.get("created_at", _utcnow()),
            "updated_at": _utcnow(),
            "migrated_from": 1,
        }
        with self._derive_kek(master_password, header["kdf"]) as kek:
            header["wrapped_dek"] = self._wrap_dek(
                kek.bytes(), self._dek.bytes(), self._header_aad(header)
            )
        header["verifier"] = self._make_verifier(self._dek.bytes())
        self._write_header(header)
        self._legacy_fernet = None

    # ------------------------------------------------------------------
    def kdf_description(self) -> str:
        kdf = self._header.get("kdf") or {}
        algorithm = kdf.get("algorithm", "desconhecido")
        if algorithm == "argon2id":
            mem_mib = int(kdf.get("memory_cost", 0)) // 1024
            return (
                f"Argon2id (t={kdf.get('time_cost')}, "
                f"m={mem_mib} MiB, p={kdf.get('parallelism')})"
            )
        if algorithm == "pbkdf2-sha256":
            return f"PBKDF2-HMAC-SHA256 ({int(kdf.get('iterations', 0)):,} iterações)".replace(",", ".")
        if self.is_legacy_vault():
            return "PBKDF2-HMAC-SHA256 (100.000 iterações) — formato legado v1"
        return algorithm
