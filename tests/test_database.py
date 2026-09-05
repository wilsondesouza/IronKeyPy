"""Testes de persistência cifrada, migração e histórico."""

import os
import sqlite3
import tempfile
import unittest

from database.database import PasswordDatabase, VaultEntry
from services.crypto_manager import CryptoManager

MASTER = "Cavalo-Bateria-Grampo-Correto-42"


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.crypto = CryptoManager(os.path.join(self.dir, "config.json"))
        self.crypto.create_vault(MASTER)
        self.db_path = os.path.join(self.dir, "vault.db")
        self.db = PasswordDatabase(self.db_path, self.crypto)

    def _add(self, **kwargs):
        defaults = dict(title="GitHub", username="user", password="s3nh4")
        defaults.update(kwargs)
        return self.db.add_entry(VaultEntry(**defaults))

    # ------------------------------------------------------------------
    def test_crud(self):
        entry = self._add()
        self.assertEqual(self.db.count(), 1)

        entry.password = "nova-senha"
        entry.notes = "atualizada"
        self.assertTrue(self.db.update_entry(entry))

        fetched = self.db.get_entry(entry.uid)
        self.assertEqual(fetched.password, "nova-senha")
        self.assertEqual(fetched.notes, "atualizada")

        self.assertTrue(self.db.delete_entry(entry.uid))
        self.assertEqual(self.db.count(), 0)

    def test_no_plaintext_on_disk(self):
        """
        REGRESSÃO CRÍTICA: na v1, site e usuário ficavam em texto puro no
        SQLite — qualquer um com o arquivo sabia em quais serviços a vítima
        tinha conta.
        """
        self._add(title="BancoSecreto", username="cpf12345678900",
                  password="s3gr3d0", notes="conta conjunta", url="https://banco.x")

        with open(self.db_path, "rb") as fh:
            raw = fh.read()
        for leak in (b"BancoSecreto", b"cpf12345678900", b"s3gr3d0",
                     b"conta conjunta", b"banco.x"):
            self.assertNotIn(leak, raw, f"vazou em texto puro: {leak!r}")

    def test_search_covers_all_fields(self):
        self._add(title="GitHub", username="wilson", url="https://github.com")
        self._add(title="Nubank", username="wilson@mail.com", notes="cartão azul")

        self.assertEqual(len(self.db.search_entries("github")), 1)
        self.assertEqual(len(self.db.search_entries("wilson")), 2)
        self.assertEqual(len(self.db.search_entries("cartao")), 1)   # sem acento
        self.assertEqual(len(self.db.search_entries("CARTÃO")), 1)   # maiúsculas
        self.assertEqual(len(self.db.search_entries("%")), 0)        # curinga não vaza

    def test_favorites_sort_first(self):
        self._add(title="Zeta")
        self._add(title="Alfa", favorite=True)
        self.assertEqual(self.db.search_entries("", "title_asc")[0].title, "Alfa")

    def test_password_history(self):
        entry = self._add(password="v1")
        entry.password = "v2"
        self.db.update_entry(entry)
        entry.password = "v3"
        self.db.update_entry(entry)

        history = self.db.get_password_history(entry.uid)
        self.assertEqual([h[0] for h in history], ["v2", "v1"])

    def test_history_not_created_when_password_unchanged(self):
        entry = self._add(password="mesma")
        entry.title = "Outro título"
        self.db.update_entry(entry)
        self.assertEqual(self.db.get_password_history(entry.uid), [])

    def test_locked_vault_blocks_reads(self):
        self._add()
        self.crypto.lock()
        self.db.invalidate_cache()
        with self.assertRaises(RuntimeError):
            self.db.get_all_entries()

    def test_corrupted_record_is_surfaced_not_hidden(self):
        entry = self._add()
        conn = sqlite3.connect(self.db_path)
        with conn:
            conn.execute("UPDATE entries SET data = ? WHERE uid = ?", ("Zm9v", entry.uid))
        conn.close()
        self.db.invalidate_cache()
        entries = self.db.get_all_entries()
        self.assertEqual(len(entries), 1)
        self.assertIn("ilegível", entries[0].title)

    def test_migration_from_v1_schema(self):
        legacy_db = os.path.join(self.dir, "legacy.db")
        conn = sqlite3.connect(legacy_db)
        with conn:
            conn.execute(
                """CREATE TABLE passwords (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       site TEXT NOT NULL, username TEXT NOT NULL,
                       password TEXT NOT NULL, created_at TEXT NOT NULL)"""
            )
            conn.execute(
                "INSERT INTO passwords (site, username, password, created_at) VALUES (?,?,?,?)",
                ("Antigo", "usuario", self.crypto.encrypt("segredo-v1"), "2024-01-02 10:00:00"),
            )
        conn.close()

        db = PasswordDatabase(legacy_db, self.crypto)
        self.assertTrue(db.needs_migration())
        migrated, backup_path = db.migrate_from_v1()
        self.assertEqual(migrated, 1)
        self.assertFalse(db.needs_migration())

        entries = db.get_all_entries(use_cache=False)
        self.assertEqual(entries[0].title, "Antigo")
        self.assertEqual(entries[0].password, "segredo-v1")

        # A tabela antiga é REMOVIDA (senão site/usuário continuariam em texto
        # puro dentro do arquivo, anulando a própria migração)…
        conn = sqlite3.connect(legacy_db)
        with conn:
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertNotIn("passwords", tables)
        self.assertNotIn("passwords_v1_backup", tables)

        with open(legacy_db, "rb") as fh:
            self.assertNotIn(b"Antigo", fh.read())

        # …mas uma cópia integral do arquivo original fica como rede de segurança.
        self.assertTrue(backup_path and os.path.exists(backup_path))

    def test_legacy_api_compatibility(self):
        self.assertTrue(self.db.add_password("Site", "user", "pass"))
        rows = self.db.get_all_passwords()
        self.assertEqual(rows[0][1], "Site")
        self.assertEqual(rows[0][3], "pass")


if __name__ == "__main__":
    unittest.main()
