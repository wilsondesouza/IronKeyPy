from __future__ import annotations

import math
import re
import secrets
import string
import unicodedata
from dataclasses import dataclass, field
from typing import List, Tuple

from services.wordlist import WORDLIST

AMBIGUOUS = "0OoIl1|`'\";:.,{}[]()<>"
SAFE_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
URL_SAFE_SYMBOLS = "!@#$%*_+-="

# Padrões que reduzem drasticamente a entropia efetiva.
COMMON_PATTERNS = (
    "123", "1234", "12345", "123456", "abc", "abcd", "qwerty", "qwertz",
    "asdf", "zxcv", "senha", "password", "admin", "master", "iloveyou",
    "welcome", "letmein", "brasil", "flamengo", "corinthians", "deus",
)
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")


@dataclass
class GeneratorOptions:
    length: int = 20
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    url_safe_symbols: bool = False
    custom_exclude: str = ""


@dataclass
class StrengthReport:
    entropy_bits: float
    score: int                       # 0-100, derivado da entropia
    label: str                       # "Muito Fraca" .. "Excelente"
    crack_time: str                  # estimativa legível
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    @property
    def is_acceptable(self) -> bool:
        return self.entropy_bits >= 60


class PasswordGenerator:
    def __init__(self) -> None:
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = SAFE_SYMBOLS

    # ------------------------------------------------------------------
    # Geração
    # ------------------------------------------------------------------
    def _pools(self, opts: GeneratorOptions) -> List[str]:
        symbols = URL_SAFE_SYMBOLS if opts.url_safe_symbols else self.symbols
        raw_pools = []
        if opts.use_lowercase:
            raw_pools.append(self.lowercase)
        if opts.use_uppercase:
            raw_pools.append(self.uppercase)
        if opts.use_digits:
            raw_pools.append(self.digits)
        if opts.use_symbols:
            raw_pools.append(symbols)
        if not raw_pools:  # nada marcado: cai no conjunto alfanumérico seguro
            raw_pools = [self.lowercase, self.uppercase, self.digits]

        banned = set(opts.custom_exclude)
        if opts.exclude_ambiguous:
            banned |= set(AMBIGUOUS)

        pools = ["".join(ch for ch in pool if ch not in banned) for pool in raw_pools]
        pools = [pool for pool in pools if pool]
        if not pools:
            raise ValueError(
                "Todos os caracteres possíveis foram excluídos. "
                "Reveja as opções de exclusão."
            )
        return pools

    def generate(self, opts: GeneratorOptions) -> str:
        """
        Gera senha garantindo ao menos um caractere de cada classe escolhida.

        Usa *rejection sampling*: sorteia a senha inteira de forma uniforme e
        repete enquanto alguma classe exigida estiver ausente. Isso preserva a
        distribuição uniforme (não introduz viés posicional).
        """
        pools = self._pools(opts)
        length = max(len(pools), min(int(opts.length), 256))
        alphabet = "".join(pools)

        for _ in range(1000):
            candidate = "".join(secrets.choice(alphabet) for _ in range(length))
            if all(any(ch in pool for ch in candidate) for pool in pools):
                return candidate

        # Fallback determinístico (praticamente inalcançável): garante as classes
        # e embaralha com Fisher-Yates usando `secrets`.
        chars = [secrets.choice(pool) for pool in pools]
        chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)

    # Compatibilidade com a assinatura antiga -----------------------------
    def generate_password(
        self,
        length: int = 20,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        return self.generate(
            GeneratorOptions(
                length=length,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_ambiguous=exclude_ambiguous,
            )
        )

    def generate_passphrase(
        self,
        words: int = 5,
        separator: str = "-",
        capitalize: bool = True,
        add_number: bool = True,
    ) -> str:
        """Frase-senha estilo Diceware (≈10,2 bits por palavra nesta lista)."""
        words = max(3, min(int(words), 12))
        chosen = [secrets.choice(WORDLIST) for _ in range(words)]
        if capitalize:
            chosen = [w.capitalize() for w in chosen]
        phrase = separator.join(chosen)
        if add_number:
            phrase += separator + str(secrets.randbelow(90) + 10)
        return phrase

    @staticmethod
    def passphrase_entropy(words: int, add_number: bool = True) -> float:
        bits = words * math.log2(len(WORDLIST))
        if add_number:
            bits += math.log2(90)
        return bits

    # ------------------------------------------------------------------
    # Avaliação de força
    # ------------------------------------------------------------------
    def _charset_size(self, password: str) -> int:
        size = 0
        if any(c.islower() for c in password):
            size += 26
        if any(c.isupper() for c in password):
            size += 26
        if any(c.isdigit() for c in password):
            size += 10
        if any(c in SAFE_SYMBOLS for c in password):
            size += len(SAFE_SYMBOLS)
        extras = {c for c in password if not c.isalnum() and c not in SAFE_SYMBOLS}
        size += len(extras) * 2
        return max(size, 1)

    @staticmethod
    def _normalize(password: str) -> str:
        stripped = unicodedata.normalize("NFKD", password.lower())
        return "".join(c for c in stripped if not unicodedata.combining(c))

    def analyze(self, password: str) -> StrengthReport:
        if not password:
            return StrengthReport(0.0, 0, "Vazia", "instantâneo",
                                  ["Nenhuma senha informada."], [])

        warnings: List[str] = []
        suggestions: List[str] = []

        base_entropy = len(password) * math.log2(self._charset_size(password))
        penalty = 0.0
        lowered = self._normalize(password)

        # 1. Repetição de caracteres (aaaa, abab)
        unique_ratio = len(set(password)) / len(password)
        if unique_ratio < 0.5:
            penalty += base_entropy * (0.5 - unique_ratio)
            warnings.append("Muitos caracteres repetidos.")
        if re.search(r"(.)\1{2,}", password):
            penalty += 6
            warnings.append("Contém o mesmo caractere repetido 3+ vezes seguidas.")

        # 2. Sequências (abc, 987) e padrões de teclado
        if self._has_sequence(lowered):
            penalty += 10
            warnings.append("Contém sequência previsível (ex.: abc, 123, 987).")
        if any(row[i:i + 4] in lowered for row in KEYBOARD_ROWS for i in range(len(row) - 3)):
            penalty += 12
            warnings.append("Contém padrão de teclado (ex.: qwerty, asdf).")

        # 3. Palavras/padrões comuns
        for pattern in COMMON_PATTERNS:
            if pattern in lowered:
                penalty += 12
                warnings.append(f"Contém termo previsível: “{pattern}”.")
                break

        # 4. Datas e anos
        if re.search(r"(19|20)\d{2}", password):
            penalty += 6
            warnings.append("Contém um ano — datas são as primeiras tentativas de um atacante.")

        # 5. Comprimento mínimo
        if len(password) < 12:
            penalty += 8
            suggestions.append("Use pelo menos 16 caracteres.")

        entropy = max(0.0, base_entropy - penalty)

        if not any(c.isupper() for c in password):
            suggestions.append("Adicione letras maiúsculas.")
        if not any(c.isdigit() for c in password):
            suggestions.append("Adicione números.")
        if not any(c in SAFE_SYMBOLS for c in password):
            suggestions.append("Adicione símbolos.")

        return StrengthReport(
            entropy_bits=round(entropy, 1),
            score=self._score_from_entropy(entropy),
            label=self._label_from_entropy(entropy),
            crack_time=self._crack_time(entropy),
            warnings=warnings,
            suggestions=suggestions,
        )

    @staticmethod
    def _has_sequence(text: str, run: int = 4) -> bool:
        for i in range(len(text) - run + 1):
            chunk = text[i:i + run]
            if not chunk.isalnum():
                continue
            deltas = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(run - 1)}
            if deltas in ({1}, {-1}):
                return True
        return False

    @staticmethod
    def _score_from_entropy(bits: float) -> int:
        # 128 bits = 100%. Escala linear truncada, fácil de comunicar na UI.
        return max(0, min(100, round(bits / 128 * 100)))

    @staticmethod
    def _label_from_entropy(bits: float) -> str:
        if bits < 28:
            return "Muito Fraca"
        if bits < 40:
            return "Fraca"
        if bits < 60:
            return "Razoável"
        if bits < 80:
            return "Forte"
        if bits < 110:
            return "Muito Forte"
        return "Excelente"

    @staticmethod
    def _crack_time(bits: float) -> str:
        """
        Estimativa para um atacante *offline* com hardware dedicado.

        Referência: ~1e12 tentativas/s (cluster de GPUs contra hash rápido).
        Em média metade do espaço precisa ser percorrido.
        """
        guesses_per_second = 1e12
        seconds = (2 ** bits) / 2 / guesses_per_second
        if seconds < 1:
            return "instantâneo"
        units = (
            (60, "segundos"), (60, "minutos"), (24, "horas"),
            (365, "dias"), (100, "anos"), (1000, "séculos"),
        )
        value = seconds
        name = "segundos"
        for factor, unit_name in units:
            if value < factor:
                break
            value /= factor
            name = unit_name
        if name == "séculos" and value > 1000:
            return "bilhões de séculos"
        return f"{value:,.0f} {name}".replace(",", ".")

    # Compatibilidade com a API antiga -----------------------------------
    def calculate_strength(self, password: str) -> Tuple[str, int]:
        report = self.analyze(password)
        return report.label, report.score
