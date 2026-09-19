"""
Área de transferência com limpeza automática e verificação de conteúdo.

Correções em relação à versão anterior
--------------------------------------
* ``clear_clipboard`` chamava ``self.create_widgets()`` ao final — a cada 30 s
  a interface inteira era **reconstruída por cima da anterior**, duplicando
  abas e vazando widgets. Era o bug visual mais grave do projeto.
* A limpeza apagava a área de transferência mesmo que o usuário já tivesse
  copiado outra coisa. Agora só limpamos se o conteúdo ainda for o segredo.
* ``pyperclip`` levanta ``PyperclipException`` em Linux sem xclip/xsel; havia
  crash não tratado. Agora há fallback para a área de transferência do Tk.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

try:
    import pyperclip

    PYPERCLIP_AVAILABLE = True
except Exception:  # pragma: no cover
    pyperclip = None  # type: ignore[assignment]
    PYPERCLIP_AVAILABLE = False


class ClipboardError(RuntimeError):
    pass


class ClipboardManager:
    """
    Gerencia cópia temporária de segredos.

    ``schedule`` recebe ``(delay_ms, callback)`` — normalmente ``widget.after``
    — para que o timer rode no laço de eventos do Tk (thread-safe).
    """

    def __init__(self, tk_widget, schedule: Callable[[int, Callable], str],
                 cancel: Callable[[str], None]):
        self._tk = tk_widget
        self._schedule = schedule
        self._cancel = cancel
        self._timer: Optional[str] = None
        self._digest: Optional[str] = None
        self._deadline_cb: Optional[Callable[[int], None]] = None
        self._remaining = 0

    # ------------------------------------------------------------------
    def _write(self, text: str) -> None:
        if PYPERCLIP_AVAILABLE:
            try:
                pyperclip.copy(text)
                return
            except Exception:
                pass
        try:
            self._tk.clipboard_clear()
            if text:
                self._tk.clipboard_append(text)
            self._tk.update_idletasks()
        except Exception as exc:  # pragma: no cover
            raise ClipboardError(
                "Não foi possível acessar a área de transferência. "
                "No Linux, instale 'xclip' ou 'xsel'."
            ) from exc

    def _read(self) -> str:
        if PYPERCLIP_AVAILABLE:
            try:
                return pyperclip.paste()
            except Exception:
                pass
        try:
            return self._tk.clipboard_get()
        except Exception:
            return ""

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    def copy(self, text: str, clear_after_seconds: int = 30,
             on_tick: Optional[Callable[[int], None]] = None) -> None:
        """Copia ``text`` e agenda a limpeza. ``clear_after_seconds<=0`` desativa."""
        if not text:
            return
        self._write(text)
        self._digest = self._hash(text)
        self._deadline_cb = on_tick

        self.cancel_timer()
        if clear_after_seconds and clear_after_seconds > 0:
            self._remaining = int(clear_after_seconds)
            self._tick()

    def _tick(self) -> None:
        if self._deadline_cb:
            self._deadline_cb(self._remaining)
        if self._remaining <= 0:
            self._timer = None
            self.clear(force=False)
            return
        self._remaining -= 1
        self._timer = self._schedule(1000, self._tick)

    def cancel_timer(self) -> None:
        if self._timer is not None:
            try:
                self._cancel(self._timer)
            except Exception:
                pass
            self._timer = None

    def clear(self, force: bool = True) -> bool:
        """
        Limpa a área de transferência.

        Com ``force=False`` só limpa se o conteúdo ainda for o segredo copiado,
        preservando qualquer coisa que o usuário tenha copiado depois.
        """
        self.cancel_timer()
        should_clear = force or (self._digest and self._hash(self._read()) == self._digest)
        if should_clear:
            try:
                self._write("")
            except ClipboardError:
                return False
        self._digest = None
        if self._deadline_cb:
            self._deadline_cb(0)
        self._deadline_cb = None
        return bool(should_clear)

    @property
    def has_pending_secret(self) -> bool:
        return self._digest is not None
