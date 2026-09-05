from __future__ import annotations

import sys
from typing import Tuple

import customtkinter as ctk

from services.app_paths import resource_path

# ---------------------------------------------------------------------------
# Paleta (light, dark) — contraste verificado contra os fundos do CustomTkinter.
# A versão anterior usava nomes como "yellow" e "lightgreen", ilegíveis sobre o
# tema escuro (contraste < 3:1) e sem par para o tema claro.
# ---------------------------------------------------------------------------
COLORS = {
    "bg_card":       ("#F1F3F5", "#242731"),
    "bg_card_hover": ("#E4E7EB", "#2E323F"),
    "bg_subtle":     ("#E9ECEF", "#1C1E26"),
    "border":        ("#D0D7DE", "#3A3F4B"),
    "text":          ("#11181C", "#ECEDEE"),
    "text_muted":    ("#5F6672", "#9BA1AC"),
    "primary":       ("#2E5FE8", "#3E63DD"),
    "primary_hover": ("#1F4BC4", "#5573E0"),
    "success":       ("#177245", "#3DB77E"),
    "success_hover": ("#0F5A34", "#2E9A67"),
    "warning":       ("#A35200", "#E5A33C"),
    "warning_hover": ("#7C3E00", "#C98A2A"),
    "danger":        ("#C62A2F", "#E5484D"),
    "danger_hover":  ("#9E2126", "#C93B40"),
    "neutral":       ("#6B7280", "#4A4F5C"),
    "neutral_hover": ("#565C66", "#5A6070"),
    # Texto sobre botões âmbar: branco no tema claro (âmbar escuro) e quase
    # preto no tema escuro (âmbar claro). Sem isso o rótulo ficava ilegível.
    "on_warning":    ("#FFFFFF", "#1A1200"),
}

# Escala de força: precisa ser distinguível também por quem não diferencia
# vermelho/verde — por isso a UI sempre acompanha rótulo textual e ícone.
STRENGTH_COLORS = (
    (28,  ("#C62A2F", "#E5484D")),   # Muito Fraca
    (40,  ("#B54708", "#F07C29")),   # Fraca
    (60,  ("#8A5A00", "#E5A33C")),   # Razoável
    (80,  ("#2C6E49", "#5FBF8E")),   # Forte
    (110, ("#177245", "#3DB77E")),   # Muito Forte
    (999, ("#0F5A34", "#2CB67D")),   # Excelente
)

STRENGTH_ICONS = {
    "Vazia": "○", "Muito Fraca": "✕", "Fraca": "▲", "Razoável": "◐",
    "Forte": "●", "Muito Forte": "◉", "Excelente": "★",
}


def strength_color(entropy_bits: float) -> Tuple[str, str]:
    for threshold, color in STRENGTH_COLORS:
        if entropy_bits < threshold:
            return color
    return STRENGTH_COLORS[-1][1]


def color(name: str) -> Tuple[str, str]:
    return COLORS[name]


# ---------------------------------------------------------------------------
# Tipografia
# ---------------------------------------------------------------------------
def font(size: int = 13, weight: str = "normal", mono: bool = False) -> ctk.CTkFont:
    if mono:
        family = {"win32": "Consolas", "darwin": "Menlo"}.get(sys.platform, "DejaVu Sans Mono")
        return ctk.CTkFont(family=family, size=size, weight=weight)
    return ctk.CTkFont(size=size, weight=weight)


# ---------------------------------------------------------------------------
# Glifos com degradação elegante
# ---------------------------------------------------------------------------
EMOJI_FONT_FAMILIES = (
    "Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji",
    "Noto Emoji", "Twemoji Mozilla", "EmojiOne Color", "JoyPixels",
)

# A coluna "alternativa" foi conferida contra a tabela cmap da DejaVu Sans
# (fonte padrão do Tk em Linux) com fontTools; medir a largura do glifo em
# tempo de execução não serve, porque o retângulo .notdef também tem largura.
GLYPHS = {
    #  nome          emoji   alternativa (garantida na DejaVu Sans)
    "shield":       ("🛡",   "◈"),
    "lock":         ("🔒",   "⊘"),
    "key":          ("🔑",   "⚷"),
    "user":         ("👤",   "@"),
    "eye":          ("👁",   "◉"),
    "eye_off":      ("🙈",   "○"),
    "copy":         ("⧉",    "❐"),
    "edit":         ("✎",    "✎"),
    "trash":        ("🗑",   "✖"),
    "star_on":      ("⭐",   "★"),
    "star_off":     ("☆",    "☆"),
    "gear":         ("⚙",    "⚙"),
    "help":         ("？",   "?"),
    "plus":         ("＋",   "+"),
    "search":       ("🔎",   ""),
    "dice":         ("🎲",   "✱"),
    "phrase":       ("📝",   "✎"),
    "export":       ("⤓",    "↓"),
    "save":         ("💾",   "▣"),
    "import":       ("📥",   "↑"),
    "file":         ("📄",   "❏"),
    "history":      ("🕘",   "↺"),
    "warn":         ("⚠",    "⚠"),
    "ok":           ("✓",    "✓"),
    "fail":         ("✕",    "✕"),
    "clipboard":    ("📋",   "❐"),
    "folder":       ("📁",   "❏"),
    "sort":         ("⇅",    "⇅"),
    "vault":        ("🗝",   "◈"),
    "magnifier":    ("🔍",   "✱"),
    "totp":         ("🔐",   "⚷"),
    "reuse":        ("🔁",   "⇄"),
}

_emoji_supported: bool | None = None


def emoji_supported() -> bool:
    """
    Detecta se o sistema tem fonte capaz de desenhar emojis.

    O resultado só é memorizado quando a consulta é possível — ``tkfont.families()``
    exige uma raiz Tk viva, e cachear um ``False`` obtido antes disso desligaria
    os emojis também no Windows/macOS.
    """
    global _emoji_supported
    if _emoji_supported is not None:
        return _emoji_supported
    try:
        import tkinter
        import tkinter.font as tkfont

        if tkinter._default_root is None:  # type: ignore[attr-defined]
            return False                   # ainda sem raiz: não memoriza
        families = {family.lower() for family in tkfont.families()}
    except Exception:
        return False
    _emoji_supported = any(family.lower() in families for family in EMOJI_FONT_FAMILIES)
    return _emoji_supported


def g(name: str) -> str:
    """Retorna o glifo apropriado para o ambiente atual."""
    emoji, fallback = GLYPHS.get(name, ("", ""))
    return emoji if emoji_supported() else fallback


def gt(name: str, text: str) -> str:
    """Glifo + texto, sem espaço duplo quando o glifo é vazio."""
    glyph = g(name)
    return f"{glyph} {text}".strip()


# ---------------------------------------------------------------------------
# Ícone da janela (multiplataforma e à prova de assets ausentes)
# ---------------------------------------------------------------------------
_icon_photo = None


def apply_icon(window) -> None:
    """
    Define o ícone da janela sem quebrar em nenhuma plataforma.

    Bug corrigido: ``wm_iconbitmap("assets/images/icon.ico")`` era chamado com
    caminho relativo e sem tratamento de erro. Em Linux/macOS o formato .ico não
    é suportado e, num clone limpo (a pasta ``assets`` está no .gitignore), o
    arquivo sequer existe — o aplicativo **fechava com TclError antes de abrir
    a primeira tela**.
    """
    global _icon_photo

    ico = resource_path("assets", "images", "icon.ico")
    # 256 px basta para a barra de tarefas; evita carregar um PNG 1024² na RAM.
    png = resource_path("assets", "images", "icon-256.png")
    if not png.exists():
        png = resource_path("assets", "images", "icon.png")

    if sys.platform == "win32" and ico.exists():
        try:
            window.iconbitmap(default=str(ico))
            return
        except Exception:
            pass

    if png.exists():
        try:
            import tkinter as tk

            if _icon_photo is None:
                _icon_photo = tk.PhotoImage(file=str(png))
            window.iconphoto(False, _icon_photo)
        except Exception:
            pass


def center_on_parent(window, parent, width: int, height: int) -> None:
    """
    Centraliza relativa à janela-mãe e mantém o resultado dentro da tela.
    """
    window.update_idletasks()
    screen_w = window.winfo_screenwidth()
    screen_h = window.winfo_screenheight()

    width = min(width, screen_w - 40)
    height = min(height, screen_h - 80)

    if parent is not None and parent.winfo_viewable():
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        x = px + (pw - width) // 2
        y = py + (ph - height) // 3
    else:
        x = (screen_w - width) // 2
        y = (screen_h - height) // 3

    x = max(10, min(x, screen_w - width - 10))
    y = max(10, min(y, screen_h - height - 40))
    window.geometry(f"{width}x{height}+{x}+{y}")
