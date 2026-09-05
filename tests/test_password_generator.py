"""Testes do gerador e do avaliador de força."""

import unittest
from collections import Counter

from services.password_generator import (
    AMBIGUOUS,
    GeneratorOptions,
    PasswordGenerator,
)
from services.wordlist import WORDLIST


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.gen = PasswordGenerator()

    def test_length_and_classes(self):
        for length in (8, 16, 32, 64, 128):
            pwd = self.gen.generate(GeneratorOptions(length=length))
            self.assertEqual(len(pwd), length)
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))

    def test_exclusions_respected(self):
        for _ in range(50):
            pwd = self.gen.generate(
                GeneratorOptions(length=32, exclude_ambiguous=True, custom_exclude="aeiou")
            )
            self.assertFalse(set(pwd) & set(AMBIGUOUS))
            self.assertFalse(set(pwd) & set("aeiou"))

    def test_all_excluded_raises(self):
        with self.assertRaises(ValueError):
            self.gen.generate(
                GeneratorOptions(
                    length=16, use_uppercase=False, use_digits=False, use_symbols=False,
                    custom_exclude="abcdefghijklmnopqrstuvwxyz",
                )
            )

    def test_uniqueness(self):
        generated = {self.gen.generate(GeneratorOptions(length=20)) for _ in range(500)}
        self.assertEqual(len(generated), 500)

    def test_distribution_is_roughly_uniform(self):
        """Sem viés posicional: a 1ª posição não pode favorecer uma classe."""
        first_chars = Counter()
        for _ in range(2000):
            first_chars[self.gen.generate(GeneratorOptions(length=16))[0]] += 1
        # 26+26+10+26 símbolos ≈ 88 caracteres; nenhum deve dominar.
        most_common_ratio = first_chars.most_common(1)[0][1] / 2000
        self.assertLess(most_common_ratio, 0.05)

    def test_passphrase(self):
        phrase = self.gen.generate_passphrase(words=5, separator="-")
        self.assertGreaterEqual(len(phrase.split("-")), 5)
        self.assertGreater(self.gen.passphrase_entropy(5), 50)

    def test_wordlist_quality(self):
        self.assertGreater(len(WORDLIST), 1000)
        self.assertTrue(all(w.isascii() and w.isalpha() for w in WORDLIST))
        self.assertEqual(len(WORDLIST), len(set(WORDLIST)))


class StrengthTests(unittest.TestCase):
    def setUp(self):
        self.gen = PasswordGenerator()

    def test_known_weak_passwords(self):
        for weak in ("123456", "senha", "password", "qwerty123", "abc12345"):
            report = self.gen.analyze(weak)
            self.assertLess(report.entropy_bits, 40, weak)
            self.assertFalse(report.is_acceptable, weak)

    def test_repetition_penalised(self):
        """REGRESSÃO: a fórmula antiga dava nota máxima a padrões repetidos."""
        repetitive = self.gen.analyze("Aa1!Aa1!Aa1!Aa1!")
        random_pwd = self.gen.analyze(self.gen.generate(GeneratorOptions(length=16)))
        self.assertLess(repetitive.entropy_bits, random_pwd.entropy_bits)

    def test_sequences_and_years_penalised(self):
        self.assertTrue(any("sequência" in w for w in self.gen.analyze("Abcdefgh1!").warnings))
        self.assertTrue(any("ano" in w for w in self.gen.analyze("Xk#mQ2019pLw!").warnings))

    def test_strong_password_accepted(self):
        report = self.gen.analyze(self.gen.generate(GeneratorOptions(length=24)))
        self.assertGreater(report.entropy_bits, 100)
        self.assertTrue(report.is_acceptable)

    def test_legacy_api_still_works(self):
        label, score = self.gen.calculate_strength("Xk#mQ7pLw!2vRt")
        self.assertIsInstance(label, str)
        self.assertTrue(0 <= score <= 100)


if __name__ == "__main__":
    unittest.main()
