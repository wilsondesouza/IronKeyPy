from __future__ import annotations

from typing import Callable, Dict, List, Optional

import customtkinter as ctk

from database.database import VaultEntry
from services import totp as totp_service
from services.password_generator import GeneratorOptions, PasswordGenerator
from services.settings import Settings
from ui.theme import color, font, g, gt
from ui.widgets import ModalDialog, SecretEntry, StrengthMeter, Tooltip

CATEGORIES = ["", "Trabalho", "Pessoal", "Financeiro", "Compras", "Estudos",
              "Redes sociais", "Servidores", "Outros"]


class EntryDialog(ModalDialog):
    """Criação e edição de um registro do cofre."""

    def __init__(self, parent, generator: PasswordGenerator, settings: Settings,
                 entry: Optional[VaultEntry] = None,
                 on_copy: Optional[Callable[[str], None]] = None,
                 on_check_pwned: Optional[Callable[[str], None]] = None,
                 on_show_history: Optional[Callable[[str], None]] = None,
                 existing_categories: Optional[List[str]] = None):
        self.is_edit = entry is not None
        title = "Editar registro" if self.is_edit else "Novo registro"
        super().__init__(parent, title, width=620, height=700, resizable=True)

        self.generator = generator
        self.settings = settings
        self.entry = entry or VaultEntry()
        self.on_check_pwned = on_check_pwned

        self.add_title(
            title,
            "Todos os campos são cifrados com AES-256-GCM antes de tocar o disco.",
        )

        scroll = ctk.CTkScrollableFrame(self.body, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        self.title_entry = self._text_field(scroll, "Serviço / Site *", self.entry.title,
                                            "Ex.: GitHub, Nubank, Gmail")
        self.username_entry = self._text_field(scroll, "Usuário / E-mail", self.entry.username,
                                               "Ex.: voce@exemplo.com")
        self.url_entry = self._text_field(scroll, "URL", self.entry.url,
                                          "https://exemplo.com/login")

        # --- senha ------------------------------------------------------
        ctk.CTkLabel(scroll, text="Senha *", font=font(12, "bold"), anchor="w").pack(
            fill="x", pady=(12, 4)
        )
        self.password_field = SecretEntry(
            scroll, width=380, revealed=not settings.hide_passwords_by_default,
            on_change=self._on_password_change, on_copy=on_copy,
        )
        self.password_field.pack(fill="x")

        self.meter = StrengthMeter(scroll)
        self.meter.pack(fill="x", pady=(6, 6))
        # O valor só é atribuído depois do medidor existir: o callback
        # ``on_change`` dispara imediatamente e referencia ``self.meter``.
        self.password_field.set(self.entry.password)

        gen_row = ctk.CTkFrame(scroll, fg_color="transparent")
        gen_row.pack(fill="x", pady=(0, 4))
        ctk.CTkButton(
            gen_row, text=gt("dice", "Gerar senha"), height=32, font=font(12),
            command=self._generate_password,
        ).pack(side="left")
        ctk.CTkButton(
            gen_row, text=gt("phrase", "Frase-senha"), height=32, font=font(12),
            fg_color=color("neutral"), hover_color=color("neutral_hover"),
            command=self._generate_passphrase,
        ).pack(side="left", padx=6)
        if on_check_pwned:
            ctk.CTkButton(
                gen_row, text=gt("magnifier", "Verificar vazamento"), height=32, font=font(12),
                text_color=color("on_warning"),
                fg_color=color("warning"), hover_color=color("warning_hover"),
                command=lambda: on_check_pwned(self.password_field.get()),
            ).pack(side="left")
        if self.is_edit and on_show_history:
            ctk.CTkButton(
                gen_row, text=gt("history", "Histórico"), height=32, width=100, font=font(12),
                fg_color="transparent", border_width=1, border_color=color("border"),
                text_color=color("text"), hover_color=color("bg_card_hover"),
                command=lambda: on_show_history(self.entry.uid),
            ).pack(side="right")

        # --- categoria e favorito ---------------------------------------
        meta_row = ctk.CTkFrame(scroll, fg_color="transparent")
        meta_row.pack(fill="x", pady=(12, 0))

        left = ctk.CTkFrame(meta_row, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(left, text="Categoria", font=font(12, "bold"), anchor="w").pack(fill="x")
        options = list(dict.fromkeys(CATEGORIES + (existing_categories or [])))
        self.category_box = ctk.CTkComboBox(left, values=[o or "(sem categoria)" for o in options],
                                            height=36, font=font(12))
        self.category_box.pack(fill="x", pady=(4, 0))
        self.category_box.set(self.entry.category or "(sem categoria)")

        self.favorite_var = ctk.BooleanVar(value=bool(self.entry.favorite))
        ctk.CTkCheckBox(meta_row, text=gt("star_on", "Favorito"), variable=self.favorite_var,
                        font=font(12)).pack(side="left", padx=(16, 0), pady=(20, 0))

        # --- TOTP -------------------------------------------------------
        ctk.CTkLabel(scroll, text="Segredo TOTP (autenticação em duas etapas)",
                     font=font(12, "bold"), anchor="w").pack(fill="x", pady=(14, 4))
        self.totp_field = SecretEntry(scroll, width=380, placeholder="Base32 ou otpauth://…",
                                      on_change=self._on_totp_change)
        self.totp_field.pack(fill="x")
        self.totp_status = ctk.CTkLabel(scroll, text="", font=font(11), anchor="w",
                                        text_color=color("text_muted"))
        self.totp_status.pack(fill="x", pady=(4, 0))
        self.totp_field.set(self.entry.totp_secret)
        Tooltip(self.totp_field, "Cole o segredo mostrado pelo site ao configurar o 2FA")

        # --- notas ------------------------------------------------------
        ctk.CTkLabel(scroll, text="Notas", font=font(12, "bold"), anchor="w").pack(
            fill="x", pady=(14, 4)
        )
        self.notes_box = ctk.CTkTextbox(scroll, height=90, font=font(12), wrap="word")
        self.notes_box.pack(fill="x")
        if self.entry.notes:
            self.notes_box.insert("1.0", self.entry.notes)

        self.error_label = ctk.CTkLabel(self.footer, text="", font=font(11),
                                        text_color=color("danger"), anchor="w",
                                        wraplength=540, justify="left")
        self.error_label.pack(fill="x", pady=(0, 8))

        self.add_button_row("Salvar" if self.is_edit else "Criar registro", self._save)
        self.finish_setup()
        self._on_password_change(self.entry.password)
        self._on_totp_change(self.entry.totp_secret)
        self.after(150, self.title_entry.focus_set)

    # ------------------------------------------------------------------
    def _text_field(self, parent, label: str, value: str, placeholder: str = "") -> ctk.CTkEntry:
        ctk.CTkLabel(parent, text=label, font=font(12, "bold"), anchor="w").pack(
            fill="x", pady=(12, 4)
        )
        field = ctk.CTkEntry(parent, height=36, font=font(13), placeholder_text=placeholder)
        field.pack(fill="x")
        if value:
            field.insert(0, value)
        return field

    def _on_password_change(self, value: str) -> None:
        if getattr(self, "meter", None) is None:
            return
        self.meter.update_report(self.generator.analyze(value))

    def _on_totp_change(self, value: str) -> None:
        if getattr(self, "totp_status", None) is None:
            return
        value = (value or "").strip()
        if not value:
            self.totp_status.configure(text="", text_color=color("text_muted"))
            return
        try:
            config = totp_service.parse_secret_or_uri(value)
            code = totp_service.generate_code(config)
            remaining = totp_service.seconds_remaining(config)
            self.totp_status.configure(
                text=f"{g('ok')} Válido — código atual: {totp_service.format_code(code)} "
                     f"(expira em {remaining}s)",
                text_color=color("success"),
            )
        except totp_service.TotpError as exc:
            self.totp_status.configure(text=f"{g('fail')} {exc}", text_color=color("danger"))

    def _generate_password(self) -> None:
        options = GeneratorOptions(
            length=self.settings.default_length,
            use_lowercase=self.settings.default_use_lowercase,
            use_uppercase=self.settings.default_use_uppercase,
            use_digits=self.settings.default_use_digits,
            use_symbols=self.settings.default_use_symbols,
            exclude_ambiguous=self.settings.default_exclude_ambiguous,
        )
        self.password_field.set(self.generator.generate(options))

    def _generate_passphrase(self) -> None:
        self.password_field.set(
            self.generator.generate_passphrase(words=self.settings.default_passphrase_words)
        )

    # ------------------------------------------------------------------
    def _save(self) -> None:
        title = self.title_entry.get().strip()
        password = self.password_field.get()

        if not title:
            self.error_label.configure(text="Informe o serviço/site.")
            self.title_entry.focus_set()
            return
        if not password:
            self.error_label.configure(text="Informe (ou gere) uma senha.")
            self.password_field.focus()
            return

        totp_secret = self.totp_field.get().strip()
        if totp_secret:
            try:
                totp_secret = totp_service.parse_secret_or_uri(totp_secret).secret
            except totp_service.TotpError as exc:
                self.error_label.configure(text=f"TOTP inválido: {exc}")
                return

        category = self.category_box.get().strip()
        if category == "(sem categoria)":
            category = ""

        self.entry.title = title
        self.entry.username = self.username_entry.get().strip()
        self.entry.password = password
        self.entry.url = self.url_entry.get().strip()
        self.entry.notes = self.notes_box.get("1.0", "end").strip()
        self.entry.category = category
        self.entry.totp_secret = totp_secret
        self.entry.favorite = bool(self.favorite_var.get())

        self.result = self.entry
        self.close()


class PasswordHistoryDialog(ModalDialog):
    def __init__(self, parent, entry_title: str, history: List[tuple],
                 on_copy: Optional[Callable[[str], None]] = None):
        super().__init__(parent, "Histórico de senhas", width=560, height=440, resizable=True)
        self.add_title(
            f"Histórico — {entry_title}",
            "Senhas anteriores, mantidas cifradas. Útil para recuperar acesso a "
            "sistemas que ainda não sincronizaram a troca.",
        )

        if not history:
            ctk.CTkLabel(self.body, text="Nenhuma senha anterior registrada.",
                         font=font(12), text_color=color("text_muted")).pack(pady=30)
        else:
            scroll = ctk.CTkScrollableFrame(self.body, fg_color="transparent")
            scroll.pack(fill="both", expand=True)
            for password, replaced_at in history:
                row = ctk.CTkFrame(scroll, fg_color=color("bg_card"), corner_radius=8)
                row.pack(fill="x", pady=4)
                info = ctk.CTkFrame(row, fg_color="transparent")
                info.pack(side="left", fill="x", expand=True, padx=12, pady=8)
                ctk.CTkLabel(info, text="•" * min(len(password), 24), font=font(13, mono=True),
                             anchor="w").pack(fill="x")
                ctk.CTkLabel(info, text=f"Substituída em {replaced_at[:19].replace('T', ' ')}",
                             font=font(10), text_color=color("text_muted"), anchor="w").pack(fill="x")
                if on_copy:
                    ctk.CTkButton(row, text=g("copy"), width=34, height=30, font=font(14),
                                  command=lambda p=password: on_copy(p)).pack(side="right", padx=10)

        ctk.CTkButton(self.footer, text="Fechar", height=36, command=self.close).pack(fill="x")
        self.finish_setup()


class ChangeMasterPasswordDialog(ModalDialog):
    """
    Troca da senha mestre.

    Graças ao envelope KEK/DEK a operação apenas reembrulha a chave de dados:
    o banco não precisa ser reescrito, então não há janela em que os registros
    fiquem parcialmente convertidos.
    """

    def __init__(self, parent, generator: PasswordGenerator,
                 verify: Callable[[str], bool]):
        super().__init__(parent, "Alterar senha mestre", width=560, height=520)
        self.generator = generator
        self.verify = verify

        self.add_title(
            "Alterar senha mestre",
            "A chave que cifra seus dados é reembrulhada com a nova senha. "
            "Nenhum registro é reescrito, portanto a operação é instantânea e segura.",
        )

        ctk.CTkLabel(self.body, text="Senha mestre atual", font=font(12, "bold"),
                     anchor="w").pack(fill="x", pady=(6, 4))
        self.current = SecretEntry(self.body, width=420)
        self.current.pack(fill="x")

        ctk.CTkLabel(self.body, text="Nova senha mestre", font=font(12, "bold"),
                     anchor="w").pack(fill="x", pady=(14, 4))
        self.new = SecretEntry(self.body, width=420, on_change=self._on_change)
        self.new.pack(fill="x")

        self.meter = StrengthMeter(self.body)
        self.meter.pack(fill="x", pady=(6, 8))

        ctk.CTkLabel(self.body, text="Confirme a nova senha", font=font(12, "bold"),
                     anchor="w").pack(fill="x", pady=(0, 4))
        self.confirm = SecretEntry(self.body, width=420, on_submit=self._submit)
        self.confirm.pack(fill="x")

        ctk.CTkButton(
            self.body, text=gt("dice", "Sugerir frase-senha"), height=32, font=font(12),
            fg_color="transparent", border_width=1, border_color=color("border"),
            text_color=color("text"), hover_color=color("bg_card_hover"),
            command=self._suggest,
        ).pack(fill="x", pady=(10, 0))

        self.error_label = ctk.CTkLabel(self.footer, text="", font=font(11),
                                        text_color=color("danger"), wraplength=480,
                                        justify="left", anchor="w")
        self.error_label.pack(fill="x", pady=(0, 8))

        self.add_button_row("Alterar senha", self._submit)
        self.finish_setup()
        self.after(150, self.current.focus)

    def _on_change(self, value: str) -> None:
        if getattr(self, "meter", None) is None:
            return
        self.meter.update_report(self.generator.analyze(value))

    def _suggest(self) -> None:
        phrase = self.generator.generate_passphrase(words=5)
        self.new.set(phrase)
        self.confirm.set(phrase)
        self.new.hide()
        self.confirm.hide()

    def _submit(self) -> None:
        current, new, confirm = self.current.get(), self.new.get(), self.confirm.get()
        if not self.verify(current):
            self.error_label.configure(text="Senha mestre atual incorreta.")
            self.current.clear()
            self.current.focus()
            return
        if new != confirm:
            self.error_label.configure(text="A confirmação não coincide com a nova senha.")
            return
        if new == current:
            self.error_label.configure(text="A nova senha deve ser diferente da atual.")
            return
        if len(new) < 12:
            self.error_label.configure(text="A nova senha precisa de pelo menos 12 caracteres.")
            return
        report = self.generator.analyze(new)
        if report.entropy_bits < 60:
            reason = report.warnings[0] if report.warnings else ""
            self.error_label.configure(
                text=f"Nova senha fraca ({report.entropy_bits:.0f} bits). {reason}"
            )
            return

        self.result = (current, new)
        self.close()


class SettingsDialog(ModalDialog):
    """Preferências de segurança e aparência (antes, constantes no código)."""

    def __init__(self, parent, settings: Settings, kdf_description: str,
                 data_dir: str, on_open_folder: Callable[[], None]):
        super().__init__(parent, "Configurações", width=640, height=680, resizable=True)
        self.settings = settings
        self.add_title("Configurações", "As alterações são aplicadas imediatamente.")

        tabs = ctk.CTkTabview(self.body)
        tabs.pack(fill="both", expand=True)

        # Abas roláveis: em telas de 768 px de altura o conteúdo de "Segurança"
        # não cabia e as últimas opções ficavam inacessíveis.
        def scrollable(name: str) -> ctk.CTkScrollableFrame:
            frame = ctk.CTkScrollableFrame(tabs.add(name), fg_color="transparent")
            frame.pack(fill="both", expand=True)
            return frame

        security = scrollable("Segurança")
        appearance = scrollable("Aparência")
        about = scrollable("Sobre o cofre")

        # --- Segurança ---------------------------------------------------
        self.autolock_var = ctk.IntVar(value=settings.auto_lock_seconds)
        self._slider_row(
            security, "Bloqueio automático por inatividade", self.autolock_var,
            0, 1800, 60, self._format_seconds,
            "0 = desativado. Recomendado: 5 minutos.",
        )

        self.clipboard_var = ctk.IntVar(value=settings.clipboard_clear_seconds)
        self._slider_row(
            security, "Limpar área de transferência após", self.clipboard_var,
            0, 180, 18, self._format_seconds,
            "A senha copiada é apagada automaticamente — só se ainda for ela.",
        )

        self.attempts_var = ctk.IntVar(value=settings.max_unlock_attempts)
        self._slider_row(
            security, "Tentativas antes do bloqueio temporário", self.attempts_var,
            3, 15, 12, lambda v: f"{v} tentativas",
            "Após o limite, aplica-se espera exponencial (15 s, 30 s, 1 min…).",
        )

        self.clear_exit_var = ctk.BooleanVar(value=settings.clear_clipboard_on_exit)
        self._switch(security, "Limpar área de transferência ao sair", self.clear_exit_var)

        self.hide_var = ctk.BooleanVar(value=settings.hide_passwords_by_default)
        self._switch(security, "Ocultar senhas por padrão", self.hide_var)

        self.history_var = ctk.BooleanVar(value=settings.keep_password_history)
        self._switch(security, "Guardar histórico de senhas (cifrado)", self.history_var)

        self.hibp_var = ctk.BooleanVar(value=settings.check_hibp_on_save)
        self._switch(
            security, "Consultar Have I Been Pwned ao salvar", self.hibp_var,
            "Envia apenas 5 caracteres do hash SHA-1 (k-anonymity). Requer internet.",
        )

        # --- Aparência ---------------------------------------------------
        ctk.CTkLabel(appearance, text="Tema", font=font(12, "bold"), anchor="w").pack(
            fill="x", pady=(10, 4), padx=6
        )
        self.appearance_var = ctk.StringVar(value=settings.appearance_mode)
        ctk.CTkSegmentedButton(
            appearance, values=["dark", "light", "system"], variable=self.appearance_var,
            command=lambda v: ctk.set_appearance_mode(v),
        ).pack(fill="x", padx=6)

        self.scaling_var = ctk.DoubleVar(value=settings.ui_scaling)
        ctk.CTkLabel(appearance, text="Escala da interface", font=font(12, "bold"),
                     anchor="w").pack(fill="x", pady=(16, 4), padx=6)
        scaling_label = ctk.CTkLabel(appearance, text=f"{settings.ui_scaling:.0%}", font=font(11))
        scaling_label.pack(anchor="e", padx=6)
        ctk.CTkSlider(
            appearance, from_=0.8, to=1.6, number_of_steps=8, variable=self.scaling_var,
            command=lambda v: scaling_label.configure(text=f"{float(v):.0%}"),
        ).pack(fill="x", padx=6)
        ctk.CTkLabel(
            appearance, text="Útil em telas 4K ou para baixa visão.",
            font=font(10), text_color=color("text_muted"), anchor="w",
        ).pack(fill="x", padx=6, pady=(2, 0))

        ctk.CTkLabel(appearance, text="Ordenação da lista", font=font(12, "bold"),
                     anchor="w").pack(fill="x", pady=(16, 4), padx=6)
        self.sort_var = ctk.StringVar(value=settings.sort_order)
        ctk.CTkSegmentedButton(
            appearance,
            values=["updated_desc", "title_asc", "created_desc"],
            variable=self.sort_var,
        ).pack(fill="x", padx=6)
        ctk.CTkLabel(
            appearance,
            text="updated_desc = alterados recentemente · title_asc = A→Z · "
                 "created_desc = mais novos",
            font=font(10), text_color=color("text_muted"), anchor="w", wraplength=520,
            justify="left",
        ).pack(fill="x", padx=6, pady=(2, 0))

        # --- Sobre --------------------------------------------------------
        info = (
            f"Derivação de chave:  {kdf_description}\n"
            f"Cifra dos registros: AES-256-GCM (AEAD autenticado)\n"
            f"Modelo de chaves:    envelope KEK/DEK\n"
            f"Aleatoriedade:       os.urandom / secrets (CSPRNG do SO)\n\n"
            f"Pasta de dados:\n{data_dir}\n\n"
            "Arquivos:\n"
            "  • config.json  — parâmetros de KDF e chave de dados embrulhada\n"
            "  • ironkeypy.db — registros cifrados (SQLite)\n"
            "  • settings.json — preferências (não contém segredos)\n"
            "  • state.json   — controle de tentativas de login"
        )
        ctk.CTkLabel(about, text=info, font=font(11, mono=True), justify="left",
                     anchor="w").pack(fill="both", expand=True, padx=8, pady=8)
        ctk.CTkButton(about, text=gt("folder", "Abrir pasta de dados"), height=34,
                      command=on_open_folder).pack(fill="x", padx=8, pady=(0, 8))

        self.add_button_row("Salvar preferências", self._save, cancel_text="Fechar")
        self.finish_setup()

    # ------------------------------------------------------------------
    @staticmethod
    def _format_seconds(value: int) -> str:
        value = int(value)
        if value == 0:
            return "desativado"
        if value < 60:
            return f"{value} s"
        minutes, seconds = divmod(value, 60)
        return f"{minutes} min" + (f" {seconds} s" if seconds else "")

    def _slider_row(self, parent, label: str, variable, low: int, high: int,
                    steps: int, formatter, helper: str = "") -> None:
        ctk.CTkLabel(parent, text=label, font=font(12, "bold"), anchor="w").pack(
            fill="x", pady=(12, 2), padx=6
        )
        value_label = ctk.CTkLabel(parent, text=formatter(variable.get()), font=font(11),
                                   text_color=color("primary"))
        value_label.pack(anchor="e", padx=6)
        ctk.CTkSlider(
            parent, from_=low, to=high, number_of_steps=steps, variable=variable,
            command=lambda v: value_label.configure(text=formatter(int(float(v)))),
        ).pack(fill="x", padx=6)
        if helper:
            ctk.CTkLabel(parent, text=helper, font=font(10), text_color=color("text_muted"),
                         anchor="w", wraplength=540, justify="left").pack(fill="x", padx=6)

    def _switch(self, parent, label: str, variable, helper: str = "") -> None:
        ctk.CTkSwitch(parent, text=label, variable=variable, font=font(12)).pack(
            anchor="w", padx=6, pady=(12, 0)
        )
        if helper:
            ctk.CTkLabel(parent, text=helper, font=font(10), text_color=color("text_muted"),
                         anchor="w", wraplength=540, justify="left").pack(
                fill="x", padx=(34, 6)
            )

    def _save(self) -> None:
        self.settings.auto_lock_seconds = int(self.autolock_var.get())
        self.settings.clipboard_clear_seconds = int(self.clipboard_var.get())
        self.settings.max_unlock_attempts = int(self.attempts_var.get())
        self.settings.clear_clipboard_on_exit = bool(self.clear_exit_var.get())
        self.settings.hide_passwords_by_default = bool(self.hide_var.get())
        self.settings.keep_password_history = bool(self.history_var.get())
        self.settings.check_hibp_on_save = bool(self.hibp_var.get())
        self.settings.appearance_mode = self.appearance_var.get()
        self.settings.ui_scaling = float(self.scaling_var.get())
        self.settings.sort_order = self.sort_var.get()
        self.result = self.settings
        self.close()


class HelpDialog(ModalDialog):
    def __init__(self, parent, shortcuts: Dict[str, str]):
        super().__init__(parent, "Ajuda", width=620, height=560, resizable=True)
        self.add_title("Ajuda e atalhos", "IronKey Py — gerenciador de senhas local.")

        tabs = ctk.CTkTabview(self.body)
        tabs.pack(fill="both", expand=True)

        shortcuts_tab = tabs.add("Atalhos")
        for combo, description in shortcuts.items():
            row = ctk.CTkFrame(shortcuts_tab, fg_color="transparent")
            row.pack(fill="x", pady=3, padx=6)
            ctk.CTkLabel(row, text=combo, font=font(11, "bold", mono=True), width=140,
                         anchor="w", text_color=color("primary")).pack(side="left")
            ctk.CTkLabel(row, text=description, font=font(11), anchor="w").pack(
                side="left", fill="x", expand=True
            )

        security_tab = tabs.add("Boas práticas")
        tips = (
            "1. A senha mestre é a única coisa entre um atacante e todo o seu cofre.\n"
            "   Use uma frase-senha longa e exclusiva — nunca reaproveitada.\n\n"
            "2. Exporte um backup .ikbak periodicamente e guarde-o em outro\n"
            "   dispositivo. O backup é autocontido e cifrado.\n\n"
            "3. Rode a auditoria do cofre com frequência: senhas reutilizadas são\n"
            "   a causa nº 1 de invasão de contas.\n\n"
            "4. Ative o 2FA nos serviços críticos e guarde o segredo TOTP aqui\n"
            "   apenas se o dispositivo tiver criptografia de disco.\n\n"
            "5. Este aplicativo protege dados em repouso. Ele não protege contra\n"
            "   malware com acesso à sua sessão (keylogger, leitura de memória).\n"
            "   Mantenha o sistema atualizado.\n\n"
            "6. Nunca envie o config.json junto de prints ou logs — ele contém a\n"
            "   chave de dados embrulhada."
        )
        ctk.CTkLabel(security_tab, text=tips, font=font(11), justify="left", anchor="w").pack(
            fill="both", expand=True, padx=8, pady=8
        )

        ctk.CTkButton(self.footer, text="Fechar", height=36, command=self.close).pack(fill="x")
        self.finish_setup()
