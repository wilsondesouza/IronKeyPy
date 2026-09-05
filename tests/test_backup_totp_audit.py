"""Testes de backup portátil, CSV, TOTP e auditoria."""

import os
import tempfile
import unittest

from database.database import VaultEntry
from services import backup as backup_service
from services import totp as totp_service
from services.vault_audit import IssueLevel, VaultAuditor


def sample_entries():
    return [
        VaultEntry(title="GitHub", username="wilson", password="Xk#mQ7pLw!2vRt$9Zc",
                   url="https://github.com", category="Trabalho", favorite=True),
        VaultEntry(title="Nubank", username="wilson@mail.com", password="senha123",
                   url="http://nubank.com.br"),
        VaultEntry(title="Gmail", username="wilson@gmail.com", password="senha123"),
    ]


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_encrypted_backup_roundtrip(self):
        path = os.path.join(self.dir, "b.ikbak")
        entries = sample_entries()
        backup_service.export_encrypted_backup(entries, "senha-do-backup", path)

        restored, meta = backup_service.read_encrypted_backup(path, "senha-do-backup")
        self.assertEqual(meta["entry_count"], 3)
        self.assertEqual([e.title for e in restored], [e.title for e in entries])
        self.assertEqual(restored[0].password, entries[0].password)

    def test_backup_is_self_contained_and_encrypted(self):
        """
        REGRESSÃO: o "backup" da v1 era uma cópia do .db, inútil sem o
        config.json que ficava só na máquina de origem.
        """
        path = os.path.join(self.dir, "b.ikbak")
        backup_service.export_encrypted_backup(sample_entries(), "pw", path)
        with open(path, "rb") as fh:
            raw = fh.read()
        for leak in (b"GitHub", b"wilson", b"senha123"):
            self.assertNotIn(leak, raw)
        # Restaura sem nenhum outro arquivo presente.
        restored, _ = backup_service.read_encrypted_backup(path, "pw")
        self.assertEqual(len(restored), 3)

    def test_wrong_passphrase_and_tampering_rejected(self):
        path = os.path.join(self.dir, "b.ikbak")
        backup_service.export_encrypted_backup(sample_entries(), "certa", path)

        with self.assertRaises(backup_service.BackupError):
            backup_service.read_encrypted_backup(path, "errada")

        with open(path, encoding="utf-8") as fh:
            content = fh.read().replace('"data": "', '"data": "AA')
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        with self.assertRaises(backup_service.BackupError):
            backup_service.read_encrypted_backup(path, "certa")

    def test_non_backup_file_rejected(self):
        path = os.path.join(self.dir, "x.ikbak")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("não sou um backup")
        with self.assertRaises(backup_service.BackupError):
            backup_service.read_encrypted_backup(path, "pw")

    def test_merge_skips_duplicates(self):
        existing = sample_entries()
        incoming = sample_entries() + [VaultEntry(title="Novo", username="u", password="p")]
        new, skipped = backup_service.merge_entries(existing, incoming)
        self.assertEqual(len(new), 1)
        self.assertEqual(skipped, 3)

    def test_csv_roundtrip(self):
        path = os.path.join(self.dir, "e.csv")
        backup_service.export_csv(sample_entries(), path)
        imported, _ = backup_service.import_csv(path)
        self.assertEqual([e.title for e in imported], ["GitHub", "Nubank", "Gmail"])

    def test_csv_import_from_bitwarden_layout(self):
        path = os.path.join(self.dir, "bw.csv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                "folder,favorite,type,name,notes,fields,login_uri,login_username,"
                "login_password,login_totp\n"
                "Trabalho,1,login,GitHub,minha nota,,https://github.com,wilson,"
                "Sup3r!Secret,JBSWY3DPEHPK3PXP\n"
            )
        entries, _ = backup_service.import_csv(path)
        self.assertEqual(entries[0].title, "GitHub")
        self.assertEqual(entries[0].username, "wilson")
        self.assertEqual(entries[0].password, "Sup3r!Secret")
        self.assertEqual(entries[0].url, "https://github.com")

    def test_csv_without_password_column_rejected(self):
        path = os.path.join(self.dir, "bad.csv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("nome,email\nA,b@c.d\n")
        with self.assertRaises(backup_service.BackupError):
            backup_service.import_csv(path)


class TotpTests(unittest.TestCase):
    def test_rfc6238_reference_vector(self):
        # Segredo "12345678901234567890" em Base32, T=59s, SHA-1, 8 dígitos.
        config = totp_service.TotpConfig(secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits=8)
        self.assertEqual(totp_service.generate_code(config, at=59), "94287082")
        self.assertEqual(totp_service.generate_code(config, at=1111111109), "07081804")

    def test_normalization_and_validation(self):
        self.assertEqual(totp_service.normalize_secret("jbsw y3dp ehpk-3pxp"),
                         "JBSWY3DPEHPK3PXP")
        with self.assertRaises(totp_service.TotpError):
            totp_service.normalize_secret("1890!!")

    def test_otpauth_uri(self):
        config = totp_service.parse_otpauth_uri(
            "otpauth://totp/GitHub:wilson?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30"
        )
        self.assertEqual(config.secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(config.issuer, "GitHub")
        self.assertEqual(config.account, "wilson")

    def test_code_changes_between_periods(self):
        config = totp_service.parse_secret_or_uri("JBSWY3DPEHPK3PXP")
        self.assertNotEqual(totp_service.generate_code(config, at=0),
                            totp_service.generate_code(config, at=30))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.auditor = VaultAuditor()

    def test_detects_reuse_weak_and_http(self):
        report = self.auditor.audit(sample_entries())
        kinds = {issue.kind for issue in report.issues}
        self.assertIn("reuse", kinds)
        self.assertIn("weak", kinds)
        self.assertIn("insecure_url", kinds)
        self.assertLess(report.score, 90)

    def test_healthy_vault_scores_high(self):
        entries = [
            VaultEntry(title="A", password="Xk#mQ7pLw!2vRt$9Zc", url="https://a.com"),
            VaultEntry(title="B", password="Tordo-Cravo-Vinte-Marfim-71-Zc$", url="https://b.com"),
        ]
        report = self.auditor.audit(entries)
        self.assertEqual(report.issues, [])
        self.assertEqual(report.score, 100)

    def test_pwned_results_are_included(self):
        import hashlib

        entries = [VaultEntry(title="A", password="senha123")]
        digest = hashlib.sha1(b"senha123").hexdigest().upper()
        report = self.auditor.audit(entries, {digest: 4242})
        pwned = [i for i in report.issues if i.kind == "pwned"]
        self.assertEqual(len(pwned), 1)
        self.assertIs(pwned[0].level, IssueLevel.CRITICAL)


if __name__ == "__main__":
    unittest.main()
