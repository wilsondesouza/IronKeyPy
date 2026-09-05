"""
Regressão dos glifos da interface.

Motivação: em Linux sem fonte de emoji instalada (o caso comum em VMs, WSL e
distribuições minimalistas), todo emoji vira o retângulo ".notdef" — a interface
enche de "tofu" e os botões de ícone ficam ilegíveis. O `ui/theme.py` resolve
isso escolhendo entre emoji e uma alternativa; estes testes garantem que

1. nenhuma alternativa saia do conjunto verificado contra a DejaVu Sans, e
2. nenhum emoji literal reapareça fora da tabela central de glifos.
"""

import pathlib
import re
import unittest

from ui.theme import GLYPHS

# Conferido com fontTools contra /usr/share/fonts/.../DejaVuSans.ttf, a fonte
# padrão do Tk em Linux. ASCII é sempre seguro.
SAFE_GLYPHS = set(
    "◈⊘⚷☺◉○❐✎✖✕✓★☆⚙✱▣⊞❏↺⚠⇅⇄●◐◆◇⨂⋮↑↓△▲‹›·«»"
) | set(chr(c) for c in range(0x20, 0x7F))

EMOJI = re.compile(
    r"[\U0001F000-\U0001FAFF\U0001F1E6-\U0001F1FF\u2B00-\u2BFF\uFE0F"
    r"\uFF00-\uFFEF\u2600-\u27BF]"
)

UI_DIR = pathlib.Path(__file__).resolve().parent.parent / "ui"


class GlyphFallbackTests(unittest.TestCase):
    def test_every_fallback_renders_in_dejavu(self):
        for name, (_emoji, fallback) in GLYPHS.items():
            for char in fallback:
                self.assertIn(
                    char, SAFE_GLYPHS,
                    f"glifo alternativo de '{name}' ({char!r}, "
                    f"U+{ord(char):04X}) não está no conjunto verificado",
                )

    def test_no_hardcoded_emoji_outside_the_glyph_table(self):
        """
        Bug real: `SecretField` usava text="👁" fixo em vez de `g("eye")` e o
        botão de revelar senha aparecia como um retângulo vazio.
        """
        offenders = []
        for path in sorted(UI_DIR.glob("*.py")):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if path.name == "theme.py":
                    continue
                code = line.split("#")[0]
                if '"""' in line or line.strip().startswith("#"):
                    continue
                found = EMOJI.findall(code)
                # Glifos seguros usados diretamente são permitidos.
                found = [c for c in found if c not in SAFE_GLYPHS]
                if found:
                    offenders.append(f"{path.name}:{number}: {''.join(found)}")
        self.assertEqual(offenders, [], "use theme.g(...) em vez de emoji fixo")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
