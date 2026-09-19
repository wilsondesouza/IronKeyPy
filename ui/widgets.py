"""
Widgets reutilizáveis: toasts, campos de segredo, medidor de força e diálogos.

Problemas de UX corrigidos
--------------------------
* Toda ação de sucesso disparava um ``messagebox`` modal — inclusive copiar uma
  senha, a ação mais frequente do aplicativo. Isso exigia dois cliques para
  copiar algo e roubava o foco. Substituído por *toasts* não-bloqueantes.
* Não havia forma de **ver** a senha digitada/salva (campos sempre mascarados
  ou sempre visíveis). Agora todo campo sensível alterna entre ocultar e
    revelar, com reocultação automática.
* ``CTkToplevel`` sem ``transient``/``grab_set`` corretos abria atrás da janela
  principal e com o fundo branco padrão do Tk piscando por ~200 ms.
* Nenhum diálogo respondia a ``Esc``/``Enter``.
"""

from __future__ import annotations

from typing import Callable, List, Optional

import customtkinter as ctk

from ui.theme import (
    apply_icon, center_on_parent, color, font, g, strength_color, STRENGTH_ICONS,
)


# ---------------------------------------------------------------------------
# Toast
# ---------------------------------------------------------------------------
class ToastManager:
    """Empilha notificações efêmeras no canto inferior direito da janela."""

    _KINDS = {
        "success": ("success", "✓"),
        "error": ("danger", "✕"),
        "warning": ("warning", "!"),
        "info": ("primary", "i"),
    }

    def __init__(self, root: ctk.CTk, max_visible: int = 4):
        self.root = root
        self.max_visible = max_visible
        self._toasts: List[ctk.CTkFrame] = []

    def show(self, message: str, kind: str = "info", duration: int = 3200,
             action_label: str = "", action: Optional[Callable[[], None]] = None) -> None:
        palette, glyph = self._KINDS.get(kind, self._KINDS["info"])

        frame = ctk.CTkFrame(
            self.root, corner_radius=10, fg_color=color("bg_card"),
            border_width=2, border_color=color(palette),
        )
        badge = ctk.CTkLabel(
            frame, text=glyph, width=26, height=26, corner_radius=13,
            fg_color=color(palette), text_color="#FFFFFF", font=font(13, "bold"),
        )
        badge.pack(side="left", padx=(10, 8), pady=10)
        ctk.CTkLabel(
            frame, text=message, font=font(12), justify="left",
            text_color=color("text"), wraplength=280,
        ).pack(side="left", padx=(0, 10), pady=10)

        if action and action_label:
            def run_action() -> None:
                self._dismiss(frame)
                action()

            ctk.CTkButton(
                frame, text=action_label, width=70, height=26, font=font(11, "bold"),
                fg_color="transparent", text_color=color(palette), hover_color=color("bg_card_hover"),
                command=run_action,
            ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            frame, text="✕", width=22, height=22, font=font(11),
            fg_color="transparent", text_color=color("text_muted"),
            hover_color=color("bg_card_hover"), command=lambda: self._dismiss(frame),
        ).pack(side="right", padx=(0, 8))

        self._toasts.append(frame)
        while len(self._toasts) > self.max_visible:
            self._dismiss(self._toasts[0])
        self._reflow()

        if duration > 0:
            self.root.after(duration, lambda: self._dismiss(frame))

    def _reflow(self) -> None:
        for index, toast in enumerate(reversed(self._toasts)):
            toast.place(relx=1.0, rely=1.0, x=-18, y=-18 - index * 62, anchor="se")
            toast.lift()

    def _dismiss(self, frame: ctk.CTkFrame) -> None:
        if frame in self._toasts:
            self._toasts.remove(frame)
        try:
            frame.destroy()
        except Exception:
            pass
        self._reflow()

    def clear(self) -> None:
        for toast in list(self._toasts):
            self._dismiss(toast)


# ---------------------------------------------------------------------------
# Campo de segredo com alternância de visibilidade
# ---------------------------------------------------------------------------
class SecretEntry(ctk.CTkFrame):
    """Entry mascarado com botão 👁 e (opcionalmente) botão de cópia."""

    def __init__(self, master, placeholder: str = "", width: int = 320,
                 height: int = 38, revealed: bool = False, mono: bool = True,
                 on_change: Optional[Callable[[str], None]] = None,
                 on_copy: Optional[Callable[[str], None]] = None,
                 on_submit: Optional[Callable[[], None]] = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._revealed = revealed
        self._on_change = on_change

        self.entry = ctk.CTkEntry(
            self, placeholder_text=placeholder, width=width, height=height,
            font=font(14, mono=mono), show="" if revealed else "•",
        )
        self.entry.pack(side="left", fill="x", expand=True)

        self.toggle_btn = ctk.CTkButton(
            self, text=g("eye"), width=height, height=height, font=font(14),
            fg_color=color("neutral"), hover_color=color("neutral_hover"),
            command=self.toggle,
        )
        self.toggle_btn.pack(side="left", padx=(6, 0))
        Tooltip(self.toggle_btn, "Mostrar/ocultar (Ctrl+H)")

        if on_copy:
            copy_btn = ctk.CTkButton(
                self, text=g("copy"), width=height, height=height, font=font(15),
                fg_color=color("primary"), hover_color=color("primary_hover"),
                command=lambda: on_copy(self.get()),
            )
            copy_btn.pack(side="left", padx=(6, 0))
            Tooltip(copy_btn, "Copiar para a área de transferência")

        if on_change:
            self.entry.bind("<KeyRelease>", lambda _e: on_change(self.get()))
        if on_submit:
            self.entry.bind("<Return>", lambda _e: on_submit())
        self.entry.bind("<Control-h>", lambda _e: (self.toggle(), "break")[1])

    # API ---------------------------------------------------------------
    def get(self) -> str:
        return self.entry.get()

    def set(self, value: str) -> None:
        self.entry.delete(0, "end")
        self.entry.insert(0, value)
        if self._on_change:
            self._on_change(value)

    def clear(self) -> None:
        self.entry.delete(0, "end")

    def focus(self) -> None:  # type: ignore[override]
        self.entry.focus_set()

    def toggle(self) -> None:
        self._revealed = not self._revealed
        self.entry.configure(show="" if self._revealed else "•")
        self.toggle_btn.configure(
            text=g("eye_off") if self._revealed else g("eye"))

    def hide(self) -> None:
        if self._revealed:
            self.toggle()

    def configure_state(self, state: str) -> None:
        self.entry.configure(state=state)


# ---------------------------------------------------------------------------
# Medidor de força
# ---------------------------------------------------------------------------
class StrengthMeter(ctk.CTkFrame):
    """Barra + rótulo + tempo estimado de quebra + dicas acionáveis."""

    def __init__(self, master, show_details: bool = True, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.show_details = show_details

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x")
        self.bar = ctk.CTkProgressBar(row, height=8, corner_radius=4)
        self.bar.pack(side="left", fill="x", expand=True, pady=(4, 0))
        self.bar.set(0)
        self.label = ctk.CTkLabel(row, text="—", font=font(12, "bold"), width=140, anchor="e")
        self.label.pack(side="left", padx=(10, 0))

        self.detail = ctk.CTkLabel(
            self, text="", font=font(11), text_color=color("text_muted"),
            justify="left", anchor="w", wraplength=520,
        )
        if show_details:
            self.detail.pack(fill="x", pady=(4, 0))

    def update_report(self, report) -> None:
        tone = strength_color(report.entropy_bits)
        icon = STRENGTH_ICONS.get(report.label, "●")
        self.bar.configure(progress_color=tone)
        self.bar.set(min(1.0, report.score / 100))
        self.label.configure(text=f"{icon} {report.label}", text_color=tone)

        if not self.show_details:
            return
        if report.entropy_bits <= 0:
            self.detail.configure(text="")
            return
        parts = [f"{report.entropy_bits:.0f} bits · quebra estimada: {report.crack_time}"]
        parts += report.warnings[:2]
        if report.suggestions and report.entropy_bits < 80:
            parts.append("Sugestão: " + report.suggestions[0])
        self.detail.configure(text="\n".join(parts))

    def reset(self) -> None:
        self.bar.set(0)
        self.label.configure(text="—", text_color=color("text_muted"))
        self.detail.configure(text="")


# ---------------------------------------------------------------------------
# Tooltip
# ---------------------------------------------------------------------------
class Tooltip:
    """Dica de contexto — a versão anterior não tinha nenhuma affordance."""

    def __init__(self, widget, text: str, delay: int = 550):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after_id: Optional[str] = None
        self._window: Optional[ctk.CTkToplevel] = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay, self._show)

    def _cancel(self) -> None:
        if self._after_id:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self) -> None:
        if self._window is not None:
            return
        try:
            x = self.widget.winfo_rootx() + 12
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
            self._window = ctk.CTkToplevel(self.widget)
            self._window.wm_overrideredirect(True)
            self._window.wm_geometry(f"+{x}+{y}")
            self._window.attributes("-topmost", True)
            ctk.CTkLabel(
                self._window, text=self.text, font=font(11), justify="left",
                fg_color=color("bg_card"), text_color=color("text"),
                corner_radius=6, padx=8, pady=4,
            ).pack()
        except Exception:
            self._window = None

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self._window is not None:
            try:
                self._window.destroy()
            except Exception:
                pass
            self._window = None


# ---------------------------------------------------------------------------
# Diálogo modal base
# ---------------------------------------------------------------------------
class ModalDialog(ctk.CTkToplevel):
    """
    Base para todos os diálogos.

    Encapsula as correções conhecidas do CustomTkinter: aplicar ``grab_set``
    depois do primeiro ciclo de eventos (senão falha em X11), esconder a janela
    até o layout estar pronto (evita o "flash" branco) e centralizar em relação
    à janela-mãe.
    """

    def __init__(self, parent, title: str, width: int = 520, height: int = 420,
                 resizable: bool = False):
        super().__init__(parent)
        self.parent = parent
        self.result = None
        self._closed = False

        self.withdraw()
        self.title(title)
        self.configure(fg_color=color("bg_subtle"))
        self.transient(parent)
        self.resizable(resizable, resizable)
        center_on_parent(self, parent, width, height)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.bind("<Escape>", lambda _e: self.on_cancel())

        # O rodapé é empacotado ANTES do corpo: no gerenciador ``pack`` do Tk o
        # primeiro widget com ``expand=True`` consome todo o espaço restante, o
        # que fazia os botões "Salvar/Cancelar" desaparecerem em diálogos com
        # conteúdo alto (era exatamente o caso da tela de Configurações).
        self.footer = ctk.CTkFrame(self, fg_color="transparent")
        self.footer.pack(side="bottom", fill="x", padx=22, pady=(0, 18))

        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(side="top", fill="both", expand=True, padx=22, pady=(20, 8))

    def finish_setup(self) -> None:
        """Chame ao final do ``__init__`` da subclasse."""
        apply_icon(self)
        self.deiconify()
        self.after(60, self._grab)

    def _grab(self) -> None:
        try:
            self.grab_set()
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def on_cancel(self) -> None:
        self.result = None
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def show(self):
        """Bloqueia até o diálogo fechar e devolve ``self.result``."""
        self.wait_window()
        return self.result

    # Helpers de layout --------------------------------------------------
    def add_title(self, text: str, subtitle: str = "") -> None:
        ctk.CTkLabel(self.body, text=text, font=font(19, "bold"), anchor="w").pack(
            fill="x", pady=(0, 2)
        )
        if subtitle:
            ctk.CTkLabel(
                self.body, text=subtitle, font=font(12), text_color=color("text_muted"),
                anchor="w", justify="left", wraplength=460,
            ).pack(fill="x", pady=(0, 12))

    def add_button_row(self, confirm_text: str, on_confirm: Callable[[], None],
                       cancel_text: str = "Cancelar", danger: bool = False):
        row = ctk.CTkFrame(self.footer, fg_color="transparent")
        row.pack(side="bottom", fill="x")
        ctk.CTkButton(
            row, text=cancel_text, width=110, height=38, font=font(13),
            fg_color="transparent", border_width=1, border_color=color("border"),
            text_color=color("text"), hover_color=color("bg_card_hover"),
            command=self.on_cancel,
        ).pack(side="right")
        confirm = ctk.CTkButton(
            row, text=confirm_text, width=150, height=38, font=font(13, "bold"),
            fg_color=color("danger" if danger else "primary"),
            hover_color=color("danger_hover" if danger else "primary_hover"),
            command=on_confirm,
        )
        confirm.pack(side="right", padx=(0, 10))
        self.bind("<Return>", lambda _e: on_confirm())
        return confirm


class ConfirmDialog(ModalDialog):
    """
    Confirmação destrutiva com digitação obrigatória.

    Ações irreversíveis (apagar cofre, sobrescrever senhas, substituir cofre)
    exigem digitação explícita para evitar cliques acidentais. O tamanho da
    janela é calculado dinamicamente para comportar o texto e o campo de input.
    """

    def __init__(self, parent, title: str, message: str, confirm_word: str = "",
                 confirm_text: str = "Confirmar", danger: bool = True,
                 width: int = 560, height: Optional[int] = None):
        if height is None:
            # Estima altura necessária com base nas quebras de linha e texto
            lines = sum(max(1, len(line) // 60 + 1) for line in message.splitlines()) if message else 1
            calculated = 210 + lines * 19 + (90 if confirm_word else 0)
            height = max(340 if confirm_word else 240, min(620, calculated))

        super().__init__(parent, title, width=width, height=height)
        self.confirm_word = confirm_word
        self.confirm_text = confirm_text
        self._entry: Optional[ctk.CTkEntry] = None

        self.add_title(title, message)

        if confirm_word:
            prompt_frame = ctk.CTkFrame(self.body, fg_color="transparent")
            prompt_frame.pack(fill="x", pady=(10, 0))

            ctk.CTkLabel(
                prompt_frame, text=f'Digite "{confirm_word}" para confirmar:',
                font=font(12, "bold"), anchor="w",
            ).pack(fill="x", pady=(0, 4))

            self._entry = ctk.CTkEntry(
                prompt_frame, height=38, font=font(13),
                placeholder_text=f'Digite exatamente "{confirm_word}"',
            )
            self._entry.pack(fill="x")
            self._entry.bind("<Return>", lambda _e: self._confirm())
            self._entry.bind("<KeyRelease>", self._on_key_release)

        self._confirm_btn = self.add_button_row(confirm_text, self._confirm, danger=danger)
        self.finish_setup()
        if self._entry:
            self.after(120, self._entry.focus_set)

    def _on_key_release(self, _event=None) -> None:
        if not self.confirm_word or self._entry is None:
            return
        typed = self._entry.get().strip()
        if typed.upper() == self.confirm_word.upper():
            self._entry.configure(border_color=color("primary"), border_width=2)
        else:
            self._entry.configure(border_color=color("border"), border_width=1)

    def _confirm(self) -> None:
        if self.confirm_word and self._entry is not None:
            typed = self._entry.get().strip()
            if typed.upper() != self.confirm_word.upper():
                self._entry.configure(border_color=color("danger"), border_width=2)
                self._entry.focus_set()
                return
        self.result = True
        self.close()


class TextPromptDialog(ModalDialog):
    """Solicita um texto (opcionalmente mascarado) — substitui ``simpledialog``."""

    def __init__(self, parent, title: str, message: str, secret: bool = False,
                 confirm_text: str = "Confirmar", initial: str = ""):
        super().__init__(parent, title, width=520, height=260)
        self.add_title(title, message)

        if secret:
            self._field = SecretEntry(self.body, width=440, on_submit=self._confirm)
            self._field.pack(fill="x", pady=(4, 0))
        else:
            self._field = ctk.CTkEntry(self.body, height=38, font=font(13))
            self._field.pack(fill="x", pady=(4, 0))
            self._field.insert(0, initial)
            self._field.bind("<Return>", lambda _e: self._confirm())

        self.add_button_row(confirm_text, self._confirm)
        self.finish_setup()
        self.after(120, self._field.focus)

    def _confirm(self) -> None:
        value = self._field.get()
        if not value:
            return
        self.result = value
        self.close()
