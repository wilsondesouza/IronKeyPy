"""Testes do núcleo criptográfico (incluindo regressões de segurança)."""

import base64
import json
import os
import tempfile
import unittest

from services.crypto_manager import (
    CryptoError,
    CryptoManager,
    VaultLockedError,
)

MASTER = "Cavalo-Bateria-Grampo-Correto-42"


class CryptoManagerTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.config = os.path.join(self.dir, "config.json")

    def _read_header(self):
        with open(self.config, encoding="utf-8") as fh:
            return json.load(fh)

    def _write_header(self, header):
        with open(self.config, "w", encoding="utf-8") as fh:
            json.dump(header, fh)

    def test_create_and_unlock(self):
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)
        self.assertTrue(manager.is_unlocked())

        reopened = CryptoManager(self.config)
        self.assertFalse(reopened.is_unlocked())
        self.assertFalse(reopened.unlock("senha errada"))
        self.assertTrue(reopened.unlock(MASTER))

    def test_roundtrip(self):
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)
        token = manager.encrypt("segredo com acentuação ção 🔐")
        self.assertNotIn("segredo", token)
        self.assertEqual(manager.decrypt(token), "segredo com acentuação ção 🔐")

    def test_aad_prevents_record_swap(self):
        """Ciphertext de um registro não pode ser reaproveitado em outro."""
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)
        token = manager.encrypt("dado", aad=b"registro-A")
        with self.assertRaises(CryptoError):
            manager.decrypt(token, aad=b"registro-B")

    def test_locked_vault_refuses_operations(self):
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)
        manager.lock()
        self.assertFalse(manager.is_unlocked())
        with self.assertRaises(VaultLockedError):
            manager.encrypt("x")

    # ------------------------------------------------------------------
    # Regressões de segurança
    # ------------------------------------------------------------------
    def test_missing_verifier_fails_closed(self):
        """
        REGRESSÃO: na v1, apagar 'test_data' do config.json fazia
        verify_master_password() retornar True para QUALQUER senha.
        """
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)

        header = self._read_header()
        header.pop("verifier")
        self._write_header(header)

        attacker = CryptoManager(self.config)
        self.assertFalse(attacker.verify_master_password("qualquer coisa"))
        with self.assertRaises(CryptoError):
            attacker.unlock("qualquer coisa")

    def test_tampered_kdf_params_rejected(self):
        """Alterar o salt/iterações invalida a tag GCM da DEK embrulhada."""
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)

        header = self._read_header()
        header["kdf"]["salt"] = base64.b64encode(os.urandom(16)).decode()
        self._write_header(header)

        self.assertFalse(CryptoManager(self.config).unlock(MASTER))

    def test_tampered_ciphertext_detected(self):
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)
        token = manager.encrypt("dado importante")

        raw = bytearray(base64.b64decode(token))
        raw[-1] ^= 0x01
        corrupted = base64.b64encode(bytes(raw)).decode()

        with self.assertRaises(CryptoError):
            manager.decrypt(corrupted)

    def test_change_master_password(self):
        manager = CryptoManager(self.config)
        manager.create_vault(MASTER)
        token = manager.encrypt("continua legível")

        self.assertTrue(manager.change_master_password(MASTER, "Nova-Frase-Senha-Muito-Longa-77"))
        self.assertFalse(manager.change_master_password("errada", "Outra-Frase-Senha-99"))

        reopened = CryptoManager(self.config)
        self.assertFalse(reopened.unlock(MASTER))
        self.assertTrue(reopened.unlock("Nova-Frase-Senha-Muito-Longa-77"))
        # A DEK é a mesma: os dados continuam decifráveis sem reescrita.
        self.assertEqual(reopened.decrypt(token), "continua legível")

    def test_header_written_atomically_with_restrictive_permissions(self):
        CryptoManager(self.config).create_vault(MASTER)
        self.assertTrue(os.path.exists(self.config))
        if os.name == "posix":
            self.assertEqual(os.stat(self.config).st_mode & 0o777, 0o600)
        leftovers = [f for f in os.listdir(self.dir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_legacy_v1_vault_migration(self):
        """Cofre v1 (Fernet + PBKDF2 100k) deve abrir e ser convertido."""
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        key = base64.urlsafe_b64encode(kdf.derive(MASTER.encode()))
        fernet = Fernet(key)
        legacy_secret = base64.b64encode(fernet.encrypt(b"senha antiga")).decode()

        self._write_header({
            "salt": base64.b64encode(salt).decode(),
            "initialized": True,
            "test_data": base64.b64encode(fernet.encrypt(b"test")).decode(),
        })

        manager = CryptoManager(self.config)
        self.assertTrue(manager.is_legacy_vault())
        self.assertFalse(manager.unlock("senha errada"))
        self.assertTrue(manager.unlock(MASTER))
        self.assertEqual(manager.decrypt(legacy_secret), "senha antiga")

        manager.finalize_migration(MASTER)
        self.assertFalse(manager.is_legacy_vault())
        header = self._read_header()
        self.assertEqual(header["format_version"], 2)
        self.assertNotIn("test_data", header)


if __name__ == "__main__":
    unittest.main()
