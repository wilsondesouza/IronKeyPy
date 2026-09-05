from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from services.login_throttle import LoginThrottle
from services.password_generator import PasswordGenerator
from ui.theme import color, font, g, gt
from ui.widgets import SecretEntry, StrengthMeter, Tooltip

MIN_MASTER_LENGTH = 12
MIN_MASTER_ENTROPY = 60.0


class LockScreen(ctk.CTkFrame):
    def __init__(self, master, mode: str, on_success: Callable[[str], None],
                 on_exit: Callable[[], None], throttle: LoginThrottle,
                 generator: Optional[PasswordGenerator] = None,
                 subtitle_override: str = "", vault_info: str = ""):
        super().__init__(master, fg_color="transparent")
        self.mode = mode                      # "setup" | "unlock"
        self.on_success = on_success
        self.on_exit = on_exit
        self.throttle = throttle
        self.generator = generator or PasswordGenerator()
        self._countdown_job: Optional[str] = None

        # Contêiner rolável: em janelas baixas (netbooks, 1366x768 com barra de
        # tarefas) o cartão de login era cortado e o botão "Criar cofre" ficava
        # inalcançável.
        viewport = ctk.CTkScrollableFrame(self, fg_color="transparent")
        viewport.pack(fill="both", expand=True)

        card = ctk.CTkFrame(viewport, fg_color=color("bg_card"), corner_radius=16,
                            border_width=1, border_color=color("border"))
        card.pack(pady=(40, 24))
        self.card = card

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(padx=44, pady=36)

        ctk.CTkLabel(inner, text=g("shield"), font=font(46)).pack()
        ctk.CTkLabel(inner, text="IronKey Py", font=font(26, "bold")).pack(pady=(2, 0))

        if mode == "setup":
            subtitle = ("Crie sua senha mestre.\n"
                        "Ela protege todo o cofre e NÃO pode ser recuperada.")
        else:
            subtitle = subtitle_override or "Digite sua senha mestre para destravar o cofre."
        ctk.CTkLabel(inner, text=subtitle, font=font(12), justify="center",
                     text_color=color("text_muted")).pack(pady=(6, 18))

        # --- campos -----------------------------------------------------
        ctk.CTkLabel(inner, text="Senha mestre", font=font(12, "bold"),
                     anchor="w").pack(fill="x")
        self.password = SecretEntry(
            inner, width=360, on_submit=self._submit,
            on_change=self._on_password_change if mode == "setup" else None,
        )
        self.password.pack(pady=(4, 10))

        if mode == "setup":
            self.meter = StrengthMeter(inner)
            self.meter.pack(fill="x", pady=(0, 10))

            ctk.CTkLabel(inner, text="Confirme a senha mestre", font=font(12, "bold"),
                         anchor="w").pack(fill="x")
            self.confirm = SecretEntry(inner, width=360, on_submit=self._submit)
            self.confirm.pack(pady=(4, 8))

            suggest = ctk.CTkButton(
                inner, text=gt("dice", "Sugerir frase-senha forte"), height=32, font=font(12),
                fg_color="transparent", border_width=1, border_color=color("border"),
                text_color=color("text"), hover_color=color("bg_card_hover"),
                command=self._suggest_passphrase,
            )
            suggest.pack(fill="x", pady=(0, 10))
            Tooltip(suggest, "Gera uma frase-senha memorizável de alta entropia")

            self.ack_var = ctk.BooleanVar(value=False)
            ctk.CTkCheckBox(
                inner, variable=self.ack_var, font=font(11), checkbox_width=18,
                checkbox_height=18, text=("Entendi que, se eu esquecer esta senha,\n"
                                          "meus dados serão permanentemente perdidos."),
            ).pack(anchor="w", pady=(0, 6))

        # --- feedback ---------------------------------------------------
        self.message = ctk.CTkLabel(inner, text="", font=font(11), justify="center",
                                    text_color=color("danger"), wraplength=360)
        self.message.pack(pady=(2, 8))

        # --- botões -----------------------------------------------------
        buttons = ctk.CTkFrame(inner, fg_color="transparent")
        buttons.pack(fill="x")
        self.submit_btn = ctk.CTkButton(
            buttons, text="Criar cofre" if mode == "setup" else "Destravar",
            height=42, font=font(14, "bold"), fg_color=color("primary"),
            hover_color=color("primary_hover"), command=self._submit,
        )
        self.submit_btn.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(
            buttons, text="Sair", width=90, height=42, font=font(13),
            fg_color="transparent", border_width=1, border_color=color("border"),
            text_color=color("text"), hover_color=color("bg_card_hover"),
            command=self.on_exit,
        ).pack(side="left", padx=(10, 0))

        footer = vault_info or ""
        last = throttle.last_success()
        if mode == "unlock" and last:
            footer = (footer + "  ·  " if footer else "") + f"Último acesso: {last}"
        if footer:
            ctk.CTkLabel(inner, text=footer, font=font(10),
                         text_color=color("text_muted")).pack(pady=(14, 0))

        self.after(150, self.password.focus)
        self._refresh_throttle()

    # ------------------------------------------------------------------
    def _on_password_change(self, value: str) -> None:
        if getattr(self, "meter", None) is None:
            return
        self.meter.update_report(self.generator.analyze(value))

    def _suggest_passphrase(self) -> None:
        phrase = self.generator.generate_passphrase(words=5)
        self.password.set(phrase)
        self.confirm.set(phrase)
        self.password.hide()
        self.confirm.hide()
        self._show_message(
            "Frase-senha gerada. Guarde-a em um local físico seguro antes de continuar.",
            "warning",
        )

    def _show_message(self, text: str, kind: str = "error") -> None:
        tone = {"error": "danger", "warning": "warning", "info": "text_muted"}.get(kind, "danger")
        self.message.configure(text=text, text_color=color(tone))

    # ------------------------------------------------------------------
    def _submit(self) -> None:
        password = self.password.get()
        if not password:
            self._show_message("Digite a senha mestre.")
            return

        if self.mode == "setup":
            self._submit_setup(password)
        else:
            self._submit_unlock(password)

    def _submit_setup(self, password: str) -> None:
        if password != self.confirm.get():
            self._show_message("As senhas não coincidem.")
            self.confirm.clear()
            self.confirm.focus()
            return
        if len(password) < MIN_MASTER_LENGTH:
            self._show_message(
                f"A senha mestre precisa de pelo menos {MIN_MASTER_LENGTH} caracteres. "
                "Prefira uma frase-senha."
            )
            return

        report = self.generator.analyze(password)
        if report.entropy_bits < MIN_MASTER_ENTROPY:
            reason = report.warnings[0] if report.warnings else "Ela é previsível demais."
            self._show_message(
                f"Senha mestre fraca ({report.entropy_bits:.0f} bits). {reason} "
                "Use o botão de sugestão para gerar uma frase-senha."
            )
            return
        if not self.ack_var.get():
            self._show_message("Confirme que você entendeu o aviso de irrecuperabilidade.")
            return

        self.on_success(password)

    def _submit_unlock(self, password: str) -> None:
        status = self.throttle.status()
        if not status.allowed:
            self._show_message(status.message)
            return

        self.submit_btn.configure(state="disabled", text="Verificando…")
        self.update_idletasks()
        try:
            self.on_success(password)
        finally:
            try:
                self.submit_btn.configure(state="normal", text="Destravar")
            except Exception:
                pass  # widget já destruído após desbloqueio bem-sucedido

    # ------------------------------------------------------------------
    def report_failure(self) -> None:
        """Chamado pelo app quando a senha estava incorreta."""
        status = self.throttle.register_failure()
        self.password.clear()
        self.password.focus()
        if status.allowed:
            self._show_message(
                "Senha incorreta. " + (status.message or
                                       f"Restam {status.remaining_attempts} tentativa(s).")
            )
        else:
            self._start_countdown(status.wait_seconds)

    def _refresh_throttle(self) -> None:
        if self.mode != "unlock":
            return
        status = self.throttle.status()
        if not status.allowed:
            self._start_countdown(status.wait_seconds)

    def _start_countdown(self, seconds: int) -> None:
        self._cancel_countdown()
        self.submit_btn.configure(state="disabled")
        self.password.configure_state("disabled")

        def tick(remaining: int) -> None:
            if remaining <= 0:
                self.submit_btn.configure(state="normal", text="Destravar")
                self.password.configure_state("normal")
                self._show_message("Você já pode tentar novamente.", "info")
                self.password.focus()
                self._countdown_job = None
                return
            minutes, secs = divmod(remaining, 60)
            self._show_message(
                f"Muitas tentativas incorretas. Aguarde {minutes:02d}:{secs:02d}."
            )
            self.submit_btn.configure(text=f"Bloqueado ({remaining}s)")
            self._countdown_job = self.after(1000, lambda: tick(remaining - 1))

        tick(max(1, seconds))

    def _cancel_countdown(self) -> None:
        if self._countdown_job:
            try:
                self.after_cancel(self._countdown_job)
            except Exception:
                pass
            self._countdown_job = None

    def destroy(self) -> None:  # type: ignore[override]
        self._cancel_countdown()
        super().destroy()
