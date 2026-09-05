from __future__ import annotations

import threading
from typing import Dict, List, Optional

import customtkinter as ctk

from database.database import VaultEntry
from services import totp as totp_service
from services.password_generator import GeneratorOptions, PasswordGenerator
from services.vault_audit import AuditReport, IssueLevel
from ui.theme import color, font, g, gt, strength_color
from ui.widgets import SecretEntry, StrengthMeter, Tooltip

MASK = "••••••••••••"   # comprimento fixo: não revela o tamanho da senha real


class VaultView(ctk.CTkFrame):

    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")

        # Rótulos dos filtros montados aqui (e não no corpo da classe) porque a
        # detecção de fonte de emoji exige uma raiz Tk já existente.
        self.FILTERS = (
            "Todos",
            gt("star_on", "Favoritos"),
            gt("warn", "Fracas"),
            gt("reuse", "Reutilizadas"),
            gt("totp", "Com 2FA"),
        )
        self.app = app
        self.generator: PasswordGenerator = app.password_generator
        self.settings = app.settings

        self._search_job: Optional[str] = None
        self._revealed: Dict[str, bool] = {}
        self._totp_job: Optional[str] = None
        self._totp_labels: Dict[str, tuple] = {}
        self._cards: Dict[str, ctk.CTkFrame] = {}
        self._audit_report: Optional[AuditReport] = None

        self._build_header()
        self._build_tabs()
        self._build_status_bar()
        self.refresh_list()
        self._tick_totp()

    # ==================================================================
    # Cabeçalho
    # ==================================================================
    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent", height=54)
        header.pack(fill="x", padx=16, pady=(12, 6))

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.pack(side="left")
        ctk.CTkLabel(brand, text=g("shield"), font=font(24)).pack(side="left")
        ctk.CTkLabel(brand, text="IronKey Py", font=font(19, "bold")).pack(side="left", padx=(8, 0))

        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.pack(side="right")

        def action(text: str, command, tip: str, palette: str = "neutral", width: int = 42):
            button = ctk.CTkButton(
                actions, text=text, width=width, height=36, font=font(14),
                fg_color=color(palette), hover_color=color(palette + "_hover"),
                command=command,
            )
            button.pack(side="left", padx=4)
            Tooltip(button, tip)
            return button

        action(gt("plus", "Novo"), self.app.new_entry, "Criar registro (Ctrl+N)", "primary", 96)
        action(g("lock"), self.app.lock_vault, "Bloquear agora (Ctrl+L)", "danger")
        action(g("gear"), self.app.open_settings, "Configurações (Ctrl+,)")
        action(g("help"), self.app.open_help, "Ajuda e atalhos (F1)")

    # ==================================================================
    # Abas
    # ==================================================================
    def _build_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(self, fg_color=color("bg_subtle"),
                                   segmented_button_selected_color=color("primary"),
                                   segmented_button_selected_hover_color=color("primary_hover"))
        self.tabs.pack(fill="both", expand=True, padx=16, pady=(0, 6))
        self.tabs.add("Cofre")
        self.tabs.add("Gerador")
        self.tabs.add("Auditoria")
        self._build_vault_tab(self.tabs.tab("Cofre"))
        self._build_generator_tab(self.tabs.tab("Gerador"))
        self._build_audit_tab(self.tabs.tab("Auditoria"))

    # ------------------------------------------------------------------
    # Aba: Cofre
    # ------------------------------------------------------------------
    def _build_vault_tab(self, tab) -> None:
        toolbar = ctk.CTkFrame(tab, fg_color="transparent")
        toolbar.pack(fill="x", pady=(4, 8))

        self.search_entry = ctk.CTkEntry(
            toolbar, placeholder_text=gt("search", " Buscar por serviço, usuário, URL ou nota…"),
            height=38, font=font(13),
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self._on_search_key)
        self.search_entry.bind("<Escape>", lambda _e: self._clear_search())

        self.filter_var = ctk.StringVar(value=self.FILTERS[0])
        self.filter_box = ctk.CTkOptionMenu(
            toolbar, values=list(self.FILTERS),
            variable=self.filter_var, width=150, height=38, font=font(12),
            command=lambda _v: self.refresh_list(),
        )
        self.filter_box.pack(side="left", padx=(8, 0))
        Tooltip(self.filter_box, "Filtrar a lista")

        ctk.CTkButton(
            toolbar, text=g("sort"), width=42, height=38, font=font(15),
            fg_color=color("neutral"), hover_color=color("neutral_hover"),
            command=self._cycle_sort,
        ).pack(side="left", padx=(8, 0))

        self.count_label = ctk.CTkLabel(tab, text="", font=font(11),
                                        text_color=color("text_muted"), anchor="w")
        self.count_label.pack(fill="x", pady=(0, 4))

        self.list_frame = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        self.list_frame.pack(fill="both", expand=True)

        footer = ctk.CTkFrame(tab, fg_color="transparent")
        footer.pack(fill="x", pady=(8, 4))
        for text, command, tip, palette in (
            (gt("save", "Exportar backup"), self.app.export_backup,
             "Backup cifrado autocontido (.ikbak)", "success"),
            (gt("import", "Importar backup"), self.app.import_backup,
             "Restaurar ou mesclar um backup .ikbak", "neutral"),
            (gt("file", "Importar CSV"), self.app.import_csv,
             "Migrar do Bitwarden, LastPass, Chrome, KeePass…", "neutral"),
            (gt("export", "Exportar CSV"), self.app.export_csv,
             "TEXTO PURO — apenas para migração", "warning"),
            (gt("key", "Alterar senha mestre"), self.app.change_master_password,
             "Reembrulha a chave de dados", "neutral"),
        ):
            button = ctk.CTkButton(
                footer, text=text, height=34, font=font(11),
                fg_color=color(palette), hover_color=color(palette + "_hover"),
                text_color=color("on_warning") if palette == "warning" else None,
                command=command,
            )
            button.pack(side="left", padx=(0, 6))
            Tooltip(button, tip)

    def _on_search_key(self, _event=None) -> None:
        """Debounce de 180 ms — antes, cada tecla redesenhava a lista inteira."""
        if self._search_job:
            self.after_cancel(self._search_job)
        self._search_job = self.after(180, self.refresh_list)

    def _clear_search(self) -> None:
        self.search_entry.delete(0, "end")
        self.refresh_list()

    def _cycle_sort(self) -> None:
        order = ["updated_desc", "title_asc", "created_desc"]
        labels = {"updated_desc": "alterados recentemente",
                  "title_asc": "ordem alfabética",
                  "created_desc": "mais recentes primeiro"}
        current = order.index(self.settings.sort_order) if self.settings.sort_order in order else 0
        self.settings.sort_order = order[(current + 1) % len(order)]
        self.app.save_settings()
        self.app.toast(f"Ordenação: {labels[self.settings.sort_order]}", "info", 1800)
        self.refresh_list()

    # ------------------------------------------------------------------
    def refresh_list(self) -> None:
        self._search_job = None
        for widget in self.list_frame.winfo_children():
            widget.destroy()
        self._cards.clear()
        self._totp_labels.clear()

        try:
            term = self.search_entry.get().strip()
            entries = self.app.database.search_entries(term, self.settings.sort_order)
            total = self.app.database.count()
        except Exception as exc:
            ctk.CTkLabel(self.list_frame, text=f"Erro ao ler o cofre: {exc}",
                         font=font(12), text_color=color("danger")).pack(pady=30)
            return

        entries = self._apply_filter(entries)

        if not entries:
            self._render_empty_state(bool(term) or self.filter_var.get() != self.FILTERS[0], total)
            self.count_label.configure(text=f"{total} registro(s) no cofre")
            return

        for entry in entries:
            self._render_card(entry)

        self._refresh_totp_labels()   # evita 1 s de rótulo 2FA vazio após redesenhar

        shown = len(entries)
        suffix = "" if shown == total else f" de {total}"
        self.count_label.configure(text=f"Exibindo {shown} registro(s){suffix}")

    def _apply_filter(self, entries: List[VaultEntry]) -> List[VaultEntry]:
        mode = self.filter_var.get()
        if mode == self.FILTERS[1]:      # Favoritos
            return [e for e in entries if e.favorite]
        if mode == self.FILTERS[4]:      # Com 2FA
            return [e for e in entries if e.totp_secret]
        if mode == self.FILTERS[2]:      # Fracas
            return [e for e in entries
                    if e.password and self.generator.analyze(e.password).entropy_bits < 60]
        if mode == self.FILTERS[3]:      # Reutilizadas
            seen: Dict[str, int] = {}
            for entry in entries:
                if entry.password:
                    seen[entry.password] = seen.get(entry.password, 0) + 1
            return [e for e in entries if seen.get(e.password, 0) > 1]
        return entries

    def _render_empty_state(self, filtered: bool, total: int) -> None:
        box = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        box.pack(pady=60)
        if filtered:
            ctk.CTkLabel(box, text=g("magnifier"), font=font(42)).pack()
            ctk.CTkLabel(box, text="Nenhum registro encontrado",
                         font=font(16, "bold")).pack(pady=(10, 4))
            ctk.CTkLabel(box, text="Tente outro termo ou remova o filtro ativo.",
                         font=font(12), text_color=color("text_muted")).pack()
            ctk.CTkButton(box, text="Limpar busca e filtros", height=34,
                          command=self._reset_filters).pack(pady=14)
        else:
            ctk.CTkLabel(box, text=g("vault"), font=font(42)).pack()
            ctk.CTkLabel(box, text="Seu cofre está vazio",
                         font=font(16, "bold")).pack(pady=(10, 4))
            ctk.CTkLabel(
                box, text="Crie o primeiro registro ou importe suas senhas de\n"
                          "outro gerenciador em poucos segundos.",
                font=font(12), text_color=color("text_muted"), justify="center",
            ).pack()
            row = ctk.CTkFrame(box, fg_color="transparent")
            row.pack(pady=16)
            ctk.CTkButton(row, text=gt("plus", "Criar registro"), height=38, width=170,
                          font=font(13, "bold"), command=self.app.new_entry).pack(side="left", padx=5)
            ctk.CTkButton(row, text=gt("file", "Importar CSV"), height=38, width=160,
                          fg_color=color("neutral"), hover_color=color("neutral_hover"),
                          command=self.app.import_csv).pack(side="left", padx=5)
        del total

    def _reset_filters(self) -> None:
        self.search_entry.delete(0, "end")
        self.filter_var.set(self.FILTERS[0])
        self.refresh_list()

    # ------------------------------------------------------------------
    def _render_card(self, entry: VaultEntry) -> None:
        card = ctk.CTkFrame(self.list_frame, fg_color=color("bg_card"), corner_radius=10,
                            border_width=1, border_color=color("border"))
        card.pack(fill="x", pady=4, padx=2)
        self._cards[entry.uid] = card

        left = ctk.CTkFrame(card, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=14, pady=10)

        title_row = ctk.CTkFrame(left, fg_color="transparent")
        title_row.pack(fill="x")

        star = ctk.CTkButton(
            title_row, text=g("star_on") if entry.favorite else g("star_off"), width=26, height=26,
            font=font(14), fg_color="transparent",
            text_color=color("warning") if entry.favorite else color("text_muted"),
            hover_color=color("bg_card_hover"),
            command=lambda e=entry: self.app.toggle_favorite(e),
        )
        star.pack(side="left", padx=(0, 4))
        Tooltip(star, "Marcar como favorito")

        ctk.CTkLabel(title_row, text=entry.display_title, font=font(15, "bold"),
                     anchor="w").pack(side="left")

        if entry.category:
            ctk.CTkLabel(
                title_row, text=f" {entry.category} ", font=font(10),
                fg_color=color("bg_subtle"), corner_radius=6,
                text_color=color("text_muted"), padx=6,
            ).pack(side="left", padx=8)

        if entry.password:
            report = self.generator.analyze(entry.password)
            ctk.CTkLabel(
                title_row, text=f"● {report.label}", font=font(10, "bold"),
                text_color=strength_color(report.entropy_bits),
            ).pack(side="left", padx=4)

        if entry.username:
            user_row = ctk.CTkFrame(left, fg_color="transparent")
            user_row.pack(fill="x", pady=(3, 0))
            ctk.CTkLabel(user_row, text=entry.username, font=font(12),
                         text_color=color("text_muted"), anchor="w").pack(side="left")

        pass_row = ctk.CTkFrame(left, fg_color="transparent")
        pass_row.pack(fill="x", pady=(3, 0))
        password_label = ctk.CTkLabel(pass_row, text=MASK, font=font(12, mono=True),
                                      text_color=color("text_muted"), anchor="w")
        password_label.pack(side="left")

        reveal_btn = ctk.CTkButton(
            pass_row, text=g("eye"), width=26, height=22, font=font(11),
            fg_color="transparent", text_color=color("text_muted"),
            hover_color=color("bg_card_hover"),
        )
        reveal_btn.configure(
            command=lambda e=entry, lbl=password_label, btn=reveal_btn: self._toggle_reveal(e, lbl, btn)
        )
        reveal_btn.pack(side="left", padx=4)
        Tooltip(reveal_btn, "Mostrar senha")

        if entry.totp_secret:
            totp_label = ctk.CTkLabel(pass_row, text="", font=font(12, "bold", mono=True),
                                      text_color=color("success"))
            totp_label.pack(side="left", padx=(16, 0))
            totp_btn = ctk.CTkButton(
                pass_row, text=g("copy"), width=26, height=22, font=font(12),
                fg_color="transparent", text_color=color("success"),
                hover_color=color("bg_card_hover"),
                command=lambda e=entry: self.app.copy_totp(e),
            )
            totp_btn.pack(side="left", padx=2)
            Tooltip(totp_btn, "Copiar código 2FA")
            self._totp_labels[entry.uid] = (totp_label, entry.totp_secret)

        # --- ações --------------------------------------------------------
        right = ctk.CTkFrame(card, fg_color="transparent")
        right.pack(side="right", padx=12, pady=10)

        def action(text: str, command, tip: str, palette: str):
            button = ctk.CTkButton(
                right, text=text, width=38, height=32, font=font(13),
                fg_color=color(palette), hover_color=color(palette + "_hover"),
                command=command,
            )
            button.pack(side="left", padx=3)
            Tooltip(button, tip)
            return button

        if entry.username:
            action(g("user"), lambda e=entry: self.app.copy_username(e), "Copiar usuário", "neutral")
        action(g("key"), lambda e=entry: self.app.copy_password(e), "Copiar senha", "primary")
        action(g("edit"), lambda e=entry: self.app.edit_entry(e), "Editar registro", "neutral")
        action(g("trash"), lambda e=entry: self.app.delete_entry(e), "Excluir registro", "danger")

    def _toggle_reveal(self, entry: VaultEntry, label, button) -> None:
        revealed = not self._revealed.get(entry.uid, False)
        self._revealed[entry.uid] = revealed
        if revealed:
            label.configure(text=entry.password or "(vazia)", text_color=color("text"))
            button.configure(text=g("eye_off"))
            # Reoculta sozinho: reduz o risco de shoulder surfing e de a senha
            # ficar visível em uma gravação de tela esquecida.
            self.after(20000, lambda: self._auto_hide(entry, label, button))
        else:
            label.configure(text=MASK, text_color=color("text_muted"))
            button.configure(text=g("eye"))

    def _auto_hide(self, entry: VaultEntry, label, button) -> None:
        if not self._revealed.get(entry.uid):
            return
        self._revealed[entry.uid] = False
        try:
            label.configure(text=MASK, text_color=color("text_muted"))
            button.configure(text=g("eye"))
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _tick_totp(self) -> None:
        """Atualiza os códigos 2FA visíveis uma vez por segundo."""
        self._refresh_totp_labels()
        self._totp_job = self.after(1000, self._tick_totp)

    def _refresh_totp_labels(self) -> None:
        for uid, (label, secret) in list(self._totp_labels.items()):
            try:
                config = totp_service.parse_secret_or_uri(secret)
                code = totp_service.generate_code(config)
                remaining = totp_service.seconds_remaining(config)
                tone = color("warning") if remaining <= 5 else color("success")
                label.configure(text=f"{totp_service.format_code(code)} ({remaining:02d}s)",
                                text_color=tone)
            except Exception:
                try:
                    label.configure(text="2FA inválido", text_color=color("danger"))
                except Exception:
                    self._totp_labels.pop(uid, None)

    # ==================================================================
    # Aba: Gerador
    # ==================================================================
    def _build_generator_tab(self, tab) -> None:
        wrapper = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        wrapper.pack(fill="both", expand=True)

        self.gen_mode = ctk.StringVar(value="Senha aleatória")
        ctk.CTkSegmentedButton(
            wrapper, values=["Senha aleatória", "Frase-senha"], variable=self.gen_mode,
            height=36, command=lambda _v: self._switch_generator_mode(),
        ).pack(fill="x", pady=(6, 14))

        # --- resultado ---------------------------------------------------
        result_card = ctk.CTkFrame(wrapper, fg_color=color("bg_card"), corner_radius=12,
                                   border_width=1, border_color=color("border"))
        result_card.pack(fill="x", pady=(0, 14))
        inner = ctk.CTkFrame(result_card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)

        self.generated_field = SecretEntry(
            inner, width=420, revealed=True, on_change=self._on_generated_change,
            on_copy=lambda value: self.app.copy_text(value, "Senha gerada copiada"),
        )
        self.generated_field.pack(fill="x")

        self.gen_meter = StrengthMeter(inner)
        self.gen_meter.pack(fill="x", pady=(10, 0))

        buttons = ctk.CTkFrame(inner, fg_color="transparent")
        buttons.pack(fill="x", pady=(12, 0))
        ctk.CTkButton(buttons, text=gt("dice", "Gerar"), height=38, width=140, font=font(13, "bold"),
                      command=self.generate).pack(side="left")
        ctk.CTkButton(buttons, text=gt("magnifier", "Verificar vazamento"), height=38, font=font(12),
                      text_color=color("on_warning"),
                      fg_color=color("warning"), hover_color=color("warning_hover"),
                      command=self._check_generated_pwned).pack(side="left", padx=8)
        ctk.CTkButton(buttons, text=gt("save", "Salvar no cofre"), height=38, font=font(12),
                      fg_color=color("success"), hover_color=color("success_hover"),
                      command=self._save_generated).pack(side="left")

        # --- opções: senha aleatória --------------------------------------
        self.random_options = ctk.CTkFrame(wrapper, fg_color=color("bg_card"), corner_radius=12,
                                           border_width=1, border_color=color("border"))
        options_inner = ctk.CTkFrame(self.random_options, fg_color="transparent")
        options_inner.pack(fill="x", padx=16, pady=14)

        length_row = ctk.CTkFrame(options_inner, fg_color="transparent")
        length_row.pack(fill="x")
        ctk.CTkLabel(length_row, text="Comprimento", font=font(13, "bold")).pack(side="left")
        self.length_value = ctk.CTkLabel(length_row, text=str(self.settings.default_length),
                                         font=font(15, "bold"), text_color=color("primary"),
                                         width=40)
        self.length_value.pack(side="right")

        self.length_var = ctk.IntVar(value=self.settings.default_length)
        # Antes o máximo era 32 — insuficiente para chaves de API e para políticas
        # modernas. Agora vai a 128 com passo de 1.
        ctk.CTkSlider(options_inner, from_=8, to=128, number_of_steps=120,
                      variable=self.length_var, command=self._on_length_change).pack(
            fill="x", pady=(6, 12)
        )

        self.lower_var = ctk.BooleanVar(value=self.settings.default_use_lowercase)
        self.upper_var = ctk.BooleanVar(value=self.settings.default_use_uppercase)
        self.digits_var = ctk.BooleanVar(value=self.settings.default_use_digits)
        self.symbols_var = ctk.BooleanVar(value=self.settings.default_use_symbols)
        self.ambiguous_var = ctk.BooleanVar(value=self.settings.default_exclude_ambiguous)
        self.urlsafe_var = ctk.BooleanVar(value=False)

        grid = ctk.CTkFrame(options_inner, fg_color="transparent")
        grid.pack(fill="x")
        checks = (
            ("Minúsculas (a-z)", self.lower_var, ""),
            ("Maiúsculas (A-Z)", self.upper_var, ""),
            ("Números (0-9)", self.digits_var, ""),
            ("Símbolos (!@#$…)", self.symbols_var, ""),
            ("Evitar ambíguos (0/O, 1/l/I)", self.ambiguous_var,
             "Reduz erro de digitação ao transcrever a senha"),
            ("Só símbolos seguros para URL", self.urlsafe_var,
             "Evita caracteres que quebram formulários e query strings"),
        )
        for index, (label, variable, tip) in enumerate(checks):
            box = ctk.CTkCheckBox(grid, text=label, variable=variable, font=font(12),
                                  command=self.generate)
            box.grid(row=index // 2, column=index % 2, sticky="w", pady=5, padx=(0, 24))
            if tip:
                Tooltip(box, tip)

        ctk.CTkLabel(options_inner, text="Excluir caracteres específicos (opcional)",
                     font=font(11, "bold"), anchor="w").pack(fill="x", pady=(12, 4))
        self.exclude_entry = ctk.CTkEntry(options_inner, height=32, font=font(12, mono=True),
                                          placeholder_text="Ex.: $%& — caracteres que o site rejeita")
        self.exclude_entry.pack(fill="x")
        self.exclude_entry.bind("<KeyRelease>", lambda _e: self.generate())

        # --- opções: frase-senha ------------------------------------------
        self.passphrase_options = ctk.CTkFrame(wrapper, fg_color=color("bg_card"),
                                               corner_radius=12, border_width=1,
                                               border_color=color("border"))
        phrase_inner = ctk.CTkFrame(self.passphrase_options, fg_color="transparent")
        phrase_inner.pack(fill="x", padx=16, pady=14)

        words_row = ctk.CTkFrame(phrase_inner, fg_color="transparent")
        words_row.pack(fill="x")
        ctk.CTkLabel(words_row, text="Número de palavras", font=font(13, "bold")).pack(side="left")
        self.words_value = ctk.CTkLabel(words_row, text=str(self.settings.default_passphrase_words),
                                        font=font(15, "bold"), text_color=color("primary"), width=40)
        self.words_value.pack(side="right")

        self.words_var = ctk.IntVar(value=self.settings.default_passphrase_words)
        ctk.CTkSlider(phrase_inner, from_=3, to=10, number_of_steps=7, variable=self.words_var,
                      command=self._on_words_change).pack(fill="x", pady=(6, 12))

        sep_row = ctk.CTkFrame(phrase_inner, fg_color="transparent")
        sep_row.pack(fill="x")
        ctk.CTkLabel(sep_row, text="Separador", font=font(12)).pack(side="left")
        self.separator_var = ctk.StringVar(value="-")
        ctk.CTkSegmentedButton(sep_row, values=["-", ".", "_", " "], variable=self.separator_var,
                               command=lambda _v: self.generate(), width=200).pack(side="right")

        self.capitalize_var = ctk.BooleanVar(value=True)
        self.add_number_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(phrase_inner, text="Capitalizar palavras", variable=self.capitalize_var,
                        font=font(12), command=self.generate).pack(anchor="w", pady=(12, 4))
        ctk.CTkCheckBox(phrase_inner, text="Acrescentar número", variable=self.add_number_var,
                        font=font(12), command=self.generate).pack(anchor="w")

        ctk.CTkLabel(
            phrase_inner,
            text="Frases-senha são mais fáceis de memorizar e digitar em TVs, "
                 "consoles e celulares — ideais para a senha mestre.",
            font=font(10), text_color=color("text_muted"), wraplength=520,
            justify="left", anchor="w",
        ).pack(fill="x", pady=(10, 0))

        self._switch_generator_mode()
        self.generate()

    def _switch_generator_mode(self) -> None:
        if self.gen_mode.get() == "Frase-senha":
            self.random_options.pack_forget()
            self.passphrase_options.pack(fill="x")
        else:
            self.passphrase_options.pack_forget()
            self.random_options.pack(fill="x")
        self.generate()

    def _on_length_change(self, value) -> None:
        self.length_value.configure(text=str(int(float(value))))
        self.generate()

    def _on_words_change(self, value) -> None:
        self.words_value.configure(text=str(int(float(value))))
        self.generate()

    def _on_generated_change(self, value: str) -> None:
        self.gen_meter.update_report(self.generator.analyze(value))

    def generate(self) -> None:
        try:
            if self.gen_mode.get() == "Frase-senha":
                password = self.generator.generate_passphrase(
                    words=self.words_var.get(),
                    separator=self.separator_var.get(),
                    capitalize=self.capitalize_var.get(),
                    add_number=self.add_number_var.get(),
                )
            else:
                password = self.generator.generate(
                    GeneratorOptions(
                        length=self.length_var.get(),
                        use_lowercase=self.lower_var.get(),
                        use_uppercase=self.upper_var.get(),
                        use_digits=self.digits_var.get(),
                        use_symbols=self.symbols_var.get(),
                        exclude_ambiguous=self.ambiguous_var.get(),
                        url_safe_symbols=self.urlsafe_var.get(),
                        custom_exclude=self.exclude_entry.get(),
                    )
                )
        except ValueError as exc:
            self.app.toast(str(exc), "error")
            return
        self.generated_field.set(password)

    def _save_generated(self) -> None:
        password = self.generated_field.get()
        if not password:
            self.app.toast("Gere uma senha primeiro.", "warning")
            return
        self.app.new_entry(prefill_password=password)

    def _check_generated_pwned(self) -> None:
        password = self.generated_field.get()
        if not password:
            self.app.toast("Gere uma senha primeiro.", "warning")
            return
        self.app.check_pwned(password)

    # ==================================================================
    # Aba: Auditoria
    # ==================================================================
    def _build_audit_tab(self, tab) -> None:
        header = ctk.CTkFrame(tab, fg_color="transparent")
        header.pack(fill="x", pady=(6, 8))

        ctk.CTkLabel(header, text="Saúde do cofre", font=font(17, "bold")).pack(side="left")

        self.audit_button = ctk.CTkButton(
            header, text="Analisar agora", height=34, width=140, font=font(12, "bold"),
            command=self.run_audit,
        )
        self.audit_button.pack(side="right")

        self.audit_online_var = ctk.BooleanVar(value=False)
        online_check = ctk.CTkCheckBox(
            header, text="Consultar vazamentos (online)", variable=self.audit_online_var,
            font=font(11),
        )
        online_check.pack(side="right", padx=(0, 14))
        Tooltip(online_check,
                "Usa k-anonymity: apenas 5 caracteres do hash SHA-1 saem da máquina")

        self.audit_score = ctk.CTkLabel(tab, text="", font=font(13, "bold"), anchor="w")
        self.audit_score.pack(fill="x")

        self.audit_bar = ctk.CTkProgressBar(tab, height=8, corner_radius=4)
        self.audit_bar.pack(fill="x", pady=(4, 10))
        self.audit_bar.set(0)

        self.audit_results = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        self.audit_results.pack(fill="both", expand=True)
        ctk.CTkLabel(
            self.audit_results,
            text="Clique em “Analisar agora” para verificar senhas reutilizadas,\n"
                 "fracas, antigas e (opcionalmente) expostas em vazamentos.",
            font=font(12), text_color=color("text_muted"), justify="center",
        ).pack(pady=40)

    def run_audit(self) -> None:
        self.audit_button.configure(state="disabled", text="Analisando…")
        for widget in self.audit_results.winfo_children():
            widget.destroy()
        status = ctk.CTkLabel(self.audit_results, text="Analisando registros…",
                              font=font(12), text_color=color("text_muted"))
        status.pack(pady=30)

        entries = self.app.database.get_all_entries()
        online = self.audit_online_var.get()

        def worker() -> None:
            pwned_counts = None
            error = ""
            if online:
                try:
                    def progress(done: int, total: int) -> None:
                        self.after(0, lambda: self._safe_configure(
                            status, text=f"Consultando vazamentos… {done}/{total} prefixos"
                        ))

                    pwned_counts = self.app.pwned_checker.check_many(
                        [e.password for e in entries if e.password], progress=progress
                    )
                except Exception as exc:
                    error = str(exc)
            report = self.app.auditor.audit(entries, pwned_counts)
            self.after(0, lambda: self._render_audit(report, error))

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _safe_configure(widget, **kwargs) -> None:
        try:
            widget.configure(**kwargs)
        except Exception:
            pass

    def _render_audit(self, report: AuditReport, error: str = "") -> None:
        self._audit_report = report
        self.audit_button.configure(state="normal", text="Analisar agora")
        for widget in self.audit_results.winfo_children():
            widget.destroy()

        tone = (color("success") if report.score >= 80
                else color("warning") if report.score >= 50 else color("danger"))
        self.audit_score.configure(
            text=f"Pontuação: {report.score}/100  ·  {report.summary()}", text_color=tone
        )
        self.audit_bar.configure(progress_color=tone)
        self.audit_bar.set(report.score / 100)

        if error:
            ctk.CTkLabel(
                self.audit_results,
                text=f'{g("warn")} Verificação online indisponível: {error}\n'
                     "A análise offline abaixo foi concluída normalmente.",
                font=font(11), text_color=color("warning"), justify="left", anchor="w",
            ).pack(fill="x", pady=(0, 8))

        if not report.issues:
            box = ctk.CTkFrame(self.audit_results, fg_color="transparent")
            box.pack(pady=50)
            ctk.CTkLabel(box, text=g("ok"), font=font(46), text_color=color("success")).pack()
            ctk.CTkLabel(box, text="Nenhum problema encontrado",
                         font=font(16, "bold")).pack(pady=(8, 4))
            ctk.CTkLabel(box, text=f"{report.total_entries} registro(s) analisado(s).",
                         font=font(12), text_color=color("text_muted")).pack()
            return

        groups = (
            ("Críticos", report.critical, "danger"),
            ("Avisos", report.warnings, "warning"),
            ("Observações", report.infos, "text_muted"),
        )
        for label, issues, palette in groups:
            if not issues:
                continue
            ctk.CTkLabel(self.audit_results, text=f"{label} ({len(issues)})",
                         font=font(13, "bold"), text_color=color(palette),
                         anchor="w").pack(fill="x", pady=(12, 4))
            for issue in issues:
                self._render_issue(issue, palette)

    def _render_issue(self, issue, palette: str) -> None:
        row = ctk.CTkFrame(self.audit_results, fg_color=color("bg_card"), corner_radius=8,
                           border_width=1, border_color=color("border"))
        row.pack(fill="x", pady=3)

        stripe = ctk.CTkFrame(row, fg_color=color(palette), width=4, height=1, corner_radius=2)
        stripe.pack(side="left", fill="y", padx=(6, 8), pady=8)
        stripe.pack_propagate(False)

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, pady=8)
        ctk.CTkLabel(info, text=f"{issue.entry_title} — {issue.title}",
                     font=font(12, "bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(info, text=issue.detail, font=font(11), text_color=color("text_muted"),
                     anchor="w", justify="left", wraplength=560).pack(fill="x")

        if issue.entry_uid and issue.level is not IssueLevel.INFO:
            ctk.CTkButton(
                row, text="Corrigir", width=80, height=30, font=font(11),
                command=lambda uid=issue.entry_uid: self.app.edit_entry_by_uid(uid),
            ).pack(side="right", padx=10)

    # ==================================================================
    # Barra de status
    # ==================================================================
    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=color("bg_card"), height=30, corner_radius=8)
        bar.pack(fill="x", padx=16, pady=(0, 10))

        self.status_left = ctk.CTkLabel(bar, text="", font=font(10),
                                        text_color=color("text_muted"), anchor="w")
        self.status_left.pack(side="left", padx=12, pady=5)

        self.status_clipboard = ctk.CTkLabel(bar, text="", font=font(10, "bold"),
                                             text_color=color("warning"))
        self.status_clipboard.pack(side="right", padx=12)

        self.status_lock = ctk.CTkLabel(bar, text="", font=font(10),
                                        text_color=color("text_muted"))
        self.status_lock.pack(side="right", padx=12)

        self.update_status()

    def update_status(self, clipboard_seconds: Optional[int] = None,
                      lock_seconds: Optional[int] = None) -> None:
        self.status_left.configure(text=f"Cofre destravado · {self.app.crypto_kdf_label}")

        if clipboard_seconds is None or clipboard_seconds <= 0:
            self.status_clipboard.configure(text="")
        else:
            self.status_clipboard.configure(
                text=f'{g("clipboard")} limpando em {clipboard_seconds}s'
            )

        if lock_seconds is None or lock_seconds <= 0:
            self.status_lock.configure(text="")
        else:
            minutes, seconds = divmod(lock_seconds, 60)
            self.status_lock.configure(text=f'{g("lock")} auto-bloqueio em {minutes}:{seconds:02d}')

    # ------------------------------------------------------------------
    def focus_search(self) -> None:
        self.tabs.set("Cofre")
        self.search_entry.focus_set()

    def destroy(self) -> None:  # type: ignore[override]
        if self._totp_job:
            try:
                self.after_cancel(self._totp_job)
            except Exception:
                pass
        super().destroy()
