#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import threading
import time
import traceback
from tkinter import filedialog, messagebox
from typing import Callable, List, Optional

import customtkinter as ctk

from api.pwned_checker import PwnedChecker, PwnedError
from database.database import PasswordDatabase, VaultEntry
from services import backup as backup_service
from services import totp as totp_service
from services.app_paths import (
    get_app_data_dir,
    get_config_path,
    get_database_path,
    open_in_file_manager,
)
from services.clipboard import ClipboardManager
from services.crypto_manager import CryptoError, CryptoManager
from services.login_throttle import LoginThrottle
from services.password_generator import PasswordGenerator
from services.settings import Settings
from services.vault_audit import VaultAuditor
from ui.dialogs import (
    ChangeMasterPasswordDialog,
    EntryDialog,
    HelpDialog,
    PasswordHistoryDialog,
    SettingsDialog,
)
from ui.lock_screen import LockScreen
from ui.theme import apply_icon, color
from ui.vault_view import VaultView
from ui.widgets import ConfirmDialog, TextPromptDialog, ToastManager

APP_VERSION = "2.0.0"

SHORTCUTS = {
    "Ctrl+N": "Novo registro",
    "Ctrl+F": "Buscar no cofre",
    "Ctrl+G": "Gerar nova senha",
    "Ctrl+L": "Bloquear o cofre agora",
    "Ctrl+E": "Exportar backup cifrado",
    "Ctrl+,": "Abrir configurações",
    "Ctrl+H": "Mostrar/ocultar o campo em foco",
    "F1": "Ajuda",
    "F5": "Recarregar a lista",
    "Esc": "Fechar diálogo / limpar busca",
}


class IronKeyApp(ctk.CTk):
    def __init__(self, settings: Optional[Settings] = None) -> None:
        # As preferências globais de tema/escala são aplicadas em ``main()``,
        # ANTES da raiz existir. Motivo: ``ctk.set_widget_scaling()`` chama
        # ``_set_scaling()`` em cada janela viva, que fixa minsize == maxsize no
        # tamanho corrente e só libera 1000 ms depois. Chamado após o
        # ``super().__init__()``, ele prendia a janela no padrão 600x500 do
        # CustomTkinter e ela "pulava" para o tamanho real ~1,5 s mais tarde.
        self.settings = settings or Settings.load()
        super().__init__()

        self.title(f"IronKey Py {APP_VERSION}")
        self.configure(fg_color=color("bg_subtle"))
        self.minsize(900, 640)
        self._restore_geometry()
        apply_icon(self)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # --- serviços -----------------------------------------------------
        self.crypto_manager = CryptoManager(config_file=get_config_path())
        self.database = PasswordDatabase(db_name=get_database_path())
        self.password_generator = PasswordGenerator()
        self.pwned_checker = PwnedChecker()
        self.auditor = VaultAuditor(self.password_generator)
        self.throttle = LoginThrottle(self.settings.max_unlock_attempts)
        self.clipboard = ClipboardManager(self, self.after, self.after_cancel)
        self.toasts = ToastManager(self)

        # --- estado -------------------------------------------------------
        self.vault_view: Optional[VaultView] = None
        self.lock_screen: Optional[LockScreen] = None
        self._master_password_cache: Optional[str] = None
        self._last_activity = time.time()
        self._lock_job: Optional[str] = None
        self._lock_warned = False
        self.crypto_kdf_label = "—"

        self._bind_shortcuts()
        self.show_lock_screen()

    # ==================================================================
    # Janela
    # ==================================================================
    def _restore_geometry(self) -> None:
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        width = min(1180, max(900, screen_w - 200))
        height = min(820, max(640, screen_h - 160))
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 3)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _bind_shortcuts(self) -> None:
        bindings = {
            "<Control-n>": lambda _e: self._if_unlocked(self.new_entry),
            "<Control-f>": lambda _e: self._if_unlocked(
                lambda: self.vault_view and self.vault_view.focus_search()
            ),
            "<Control-g>": lambda _e: self._if_unlocked(self._focus_generator),
            "<Control-l>": lambda _e: self._if_unlocked(self.lock_vault),
            "<Control-e>": lambda _e: self._if_unlocked(self.export_backup),
            "<Control-comma>": lambda _e: self._if_unlocked(self.open_settings),
            "<F1>": lambda _e: self.open_help(),
            "<F5>": lambda _e: self._if_unlocked(self.refresh),
        }
        for sequence, handler in bindings.items():
            self.bind_all(sequence, handler)

        for sequence in ("<Any-KeyPress>", "<Any-Button>", "<Motion>"):
            self.bind_all(sequence, self._register_activity, add="+")

    def _if_unlocked(self, action: Callable[[], None]):
        if self.crypto_manager.is_unlocked() and self.vault_view is not None:
            action()
        return "break"

    def _focus_generator(self) -> None:
        if self.vault_view:
            self.vault_view.tabs.set("Gerador")
            self.vault_view.generate()

    # ==================================================================
    # Ciclo de autenticação
    # ==================================================================
    def show_lock_screen(self, message: str = "") -> None:
        if self.vault_view is not None:
            self.vault_view.destroy()
            self.vault_view = None
        if self.lock_screen is not None:
            self.lock_screen.destroy()

        is_setup = not self.crypto_manager.is_initialized()
        vault_info = ""
        if not is_setup:
            try:
                vault_info = f"Proteção: {self.crypto_manager.kdf_description()}"
            except Exception:
                vault_info = ""

        self.lock_screen = LockScreen(
            self,
            mode="setup" if is_setup else "unlock",
            on_success=self._create_vault if is_setup else self._try_unlock,
            on_exit=self.on_closing,
            throttle=self.throttle,
            generator=self.password_generator,
            subtitle_override=message,
            vault_info=vault_info,
        )
        self.lock_screen.pack(fill="both", expand=True)

    def _create_vault(self, master_password: str) -> None:
        try:
            self.crypto_manager.create_vault(master_password)
        except CryptoError as exc:
            self._error("Não foi possível criar o cofre", str(exc))
            return
        self.throttle.register_success()
        self._enter_vault(master_password)
        self.toast("Cofre criado. Guarde sua senha mestre em local seguro.", "success", 6000)

    def _try_unlock(self, master_password: str) -> None:
        try:
            unlocked = self.crypto_manager.unlock(master_password)
        except CryptoError as exc:
            self._error("Falha ao abrir o cofre", str(exc))
            return

        if not unlocked:
            if self.lock_screen:
                self.lock_screen.report_failure()
            return

        self.throttle.register_success()
        self._enter_vault(master_password)

    def _enter_vault(self, master_password: str) -> None:
        self.database.set_crypto_manager(self.crypto_manager)
        self._master_password_cache = master_password
        self.crypto_kdf_label = self.crypto_manager.kdf_description()

        try:
            self._run_migrations(master_password)
        except Exception as exc:
            self._error("Falha na migração do cofre", str(exc))

        if self.lock_screen is not None:
            self.lock_screen.destroy()
            self.lock_screen = None

        self.vault_view = VaultView(self, self)
        self.vault_view.pack(fill="both", expand=True)

        self._last_activity = time.time()
        self._lock_warned = False
        self._schedule_lock_check()

    def _run_migrations(self, master_password: str) -> None:
        """Converte cofres do formato v1 (Fernet, campos em texto puro)."""
        if not self.database.needs_migration() and not self.crypto_manager.is_legacy_vault():
            return

        migrated, legacy_backup = 0, None
        if self.database.needs_migration():
            migrated, legacy_backup = self.database.migrate_from_v1()
        if self.crypto_manager.is_legacy_vault():
            self.crypto_manager.finalize_migration(master_password)
            self.database.reencrypt_all()
            self.database._reclaim_space()
            self.crypto_kdf_label = self.crypto_manager.kdf_description()

        if migrated:
            self.toast(
                f"{migrated} registro(s) migrado(s) para o formato v2 "
                "(AES-256-GCM + Argon2id). Agora site, usuário e notas também "
                "são cifrados.",
                "success", 10000,
            )
            if legacy_backup:
                self.toast(
                    "Uma cópia do banco antigo foi guardada como "
                    f"“{os.path.basename(legacy_backup)}”. Ela ainda contém "
                    "nomes de sites em texto puro — apague-a depois de conferir "
                    "que está tudo certo.",
                    "warning", 14000,
                    action_label="Abrir pasta", action=self._open_data_folder,
                )

    # ------------------------------------------------------------------
    def lock_vault(self, reason: str = "") -> None:
        if not self.crypto_manager.is_unlocked():
            return
        self._cancel_lock_check()
        self.clipboard.clear(force=False)
        self.toasts.clear()
        self.crypto_manager.lock()
        self.database.invalidate_cache()
        self.database.set_crypto_manager(self.crypto_manager)
        self._master_password_cache = None
        self.show_lock_screen(reason or "Cofre bloqueado. Digite a senha mestre para continuar.")

    # ==================================================================
    # Auto-bloqueio
    # ==================================================================
    def _register_activity(self, _event=None) -> None:
        self._last_activity = time.time()
        self._lock_warned = False

    def _schedule_lock_check(self) -> None:
        self._cancel_lock_check()
        self._lock_job = self.after(1000, self._check_lock)

    def _cancel_lock_check(self) -> None:
        if self._lock_job:
            try:
                self.after_cancel(self._lock_job)
            except Exception:
                pass
            self._lock_job = None

    def _check_lock(self) -> None:
        if not self.crypto_manager.is_unlocked():
            return

        timeout = self.settings.auto_lock_seconds
        if timeout <= 0:
            if self.vault_view:
                self.vault_view.update_status(lock_seconds=None)
            self._lock_job = self.after(1000, self._check_lock)
            return

        remaining = int(timeout - (time.time() - self._last_activity))
        if remaining <= 0:
            self.lock_vault("Bloqueado automaticamente por inatividade.")
            return

        if remaining <= 30 and not self._lock_warned:
            self._lock_warned = True
            self.toast(
                f"Bloqueio automático em {remaining}s. Mova o mouse para continuar.",
                "warning", 5000,
            )

        if self.vault_view:
            self.vault_view.update_status(lock_seconds=remaining if remaining <= 120 else None)
        self._lock_job = self.after(1000, self._check_lock)

    # ==================================================================
    # Notificações
    # ==================================================================
    def toast(self, message: str, kind: str = "info", duration: int = 3200,
              action_label: str = "", action: Optional[Callable[[], None]] = None) -> None:
        self.toasts.show(message, kind, duration, action_label, action)

    def _error(self, title: str, detail: str) -> None:
        messagebox.showerror(title, detail, parent=self)

    # ==================================================================
    # Área de transferência
    # ==================================================================
    def copy_text(self, text: str, label: str = "Copiado") -> None:
        if not text:
            self.toast("Nada para copiar.", "warning")
            return
        seconds = self.settings.clipboard_clear_seconds
        try:
            self.clipboard.copy(text, seconds, on_tick=self._on_clipboard_tick)
        except Exception as exc:
            self.toast(str(exc), "error", 6000)
            return
        suffix = f" · será limpo em {seconds}s" if seconds > 0 else ""
        self.toast(f"{label}{suffix}", "success", 2400)

    def _on_clipboard_tick(self, remaining: int) -> None:
        if self.vault_view:
            self.vault_view.update_status(clipboard_seconds=remaining)

    def copy_password(self, entry: VaultEntry) -> None:
        self.copy_text(entry.password, f"Senha de “{entry.display_title}” copiada")

    def copy_username(self, entry: VaultEntry) -> None:
        self.copy_text(entry.username, "Usuário copiado")

    def copy_totp(self, entry: VaultEntry) -> None:
        try:
            config = totp_service.parse_secret_or_uri(entry.totp_secret)
            code = totp_service.generate_code(config)
        except totp_service.TotpError as exc:
            self.toast(f"TOTP inválido: {exc}", "error")
            return
        remaining = totp_service.seconds_remaining(config)
        self.copy_text(code, f"Código 2FA copiado (válido por {remaining}s)")

    # ==================================================================
    # CRUD
    # ==================================================================
    def refresh(self) -> None:
        self.database.invalidate_cache()
        if self.vault_view:
            self.vault_view.refresh_list()

    def _categories(self) -> List[str]:
        return sorted({e.category for e in self.database.get_all_entries() if e.category})

    def new_entry(self, prefill_password: str = "") -> None:
        dialog = EntryDialog(
            self, self.password_generator, self.settings, entry=None,
            on_copy=lambda value: self.copy_text(value, "Senha copiada"),
            on_check_pwned=self.check_pwned,
            existing_categories=self._categories(),
        )
        if prefill_password:
            dialog.password_field.set(prefill_password)
        result = dialog.show()
        if result is None:
            return
        try:
            self.database.add_entry(result)
        except Exception as exc:
            self._error("Erro ao salvar", str(exc))
            return
        self.refresh()
        self.toast(f"“{result.display_title}” salvo no cofre.", "success")
        if self.settings.check_hibp_on_save:
            self._check_pwned_async(result.password, quiet_when_safe=True)

    def edit_entry(self, entry: VaultEntry) -> None:
        dialog = EntryDialog(
            self, self.password_generator, self.settings, entry=entry,
            on_copy=lambda value: self.copy_text(value, "Senha copiada"),
            on_check_pwned=self.check_pwned,
            on_show_history=self.show_history,
            existing_categories=self._categories(),
        )
        result = dialog.show()
        if result is None:
            return
        try:
            ok = self.database.update_entry(
                result,
                keep_history=self.settings.keep_password_history,
                history_limit=self.settings.password_history_limit,
            )
        except Exception as exc:
            self._error("Erro ao atualizar", str(exc))
            return
        if ok:
            self.refresh()
            self.toast(f"“{result.display_title}” atualizado.", "success")
        else:
            self.toast("Registro não encontrado — a lista foi recarregada.", "warning")
            self.refresh()

    def edit_entry_by_uid(self, uid: str) -> None:
        entry = self.database.get_entry(uid)
        if entry:
            self.edit_entry(entry)

    def delete_entry(self, entry: VaultEntry) -> None:
        confirmed = ConfirmDialog(
            self,
            "Excluir registro",
            f"“{entry.display_title}” será removido do cofre junto com seu "
            "histórico de senhas. Esta ação não pode ser desfeita.",
            confirm_text="Excluir",
        ).show()
        if not confirmed:
            return

        snapshot = VaultEntry(**{k: v for k, v in entry.payload().items()})
        if self.database.delete_entry(entry.uid):
            self.refresh()
            self.toast(
                f"“{entry.display_title}” excluído.", "info", 6000,
                action_label="Desfazer",
                action=lambda: self._restore_entry(snapshot),
            )
        else:
            self.toast("Não foi possível excluir o registro.", "error")

    def _restore_entry(self, entry: VaultEntry) -> None:
        entry.uid = ""
        entry.row_id = None
        try:
            self.database.add_entry(entry)
        except Exception as exc:
            self._error("Erro ao restaurar", str(exc))
            return
        self.refresh()
        self.toast("Registro restaurado.", "success")

    def toggle_favorite(self, entry: VaultEntry) -> None:
        entry.favorite = not entry.favorite
        try:
            self.database.update_entry(entry, keep_history=False)
        except Exception as exc:
            self._error("Erro ao atualizar", str(exc))
            return
        self.refresh()

    def show_history(self, uid: str) -> None:
        entry = self.database.get_entry(uid)
        if entry is None:
            return
        history = self.database.get_password_history(uid)
        PasswordHistoryDialog(
            self, entry.display_title, history,
            on_copy=lambda value: self.copy_text(value, "Senha antiga copiada"),
        ).show()

    # ==================================================================
    # Have I Been Pwned
    # ==================================================================
    def check_pwned(self, password: str) -> None:
        if not password:
            self.toast("Nenhuma senha para verificar.", "warning")
            return
        self.toast("Consultando Have I Been Pwned…", "info", 2000)
        self._check_pwned_async(password)

    def _check_pwned_async(self, password: str, quiet_when_safe: bool = False) -> None:
        def worker() -> None:
            try:
                is_pwned, count = self.pwned_checker.check_password(password)
                advice = self.pwned_checker.get_password_strength_advice(is_pwned, count)
            except PwnedError as exc:
                # O nome ligado por ``except ... as`` é apagado ao sair do bloco;
                # capturar ``exc`` dentro de um lambda adiado gera NameError.
                # (O mesmo defeito existia na versão anterior, em
                # ``show_error(str(e))`` agendado via ``after``.)
                message = str(exc)
                self.after(0, lambda m=message: self.toast(m, "warning", 6000))
                return
            except Exception as exc:  # rede/DNS inesperado
                message = f"Verificação indisponível: {exc}"
                self.after(0, lambda m=message: self.toast(m, "warning", 6000))
                return

            def present() -> None:
                if is_pwned:
                    self.toast(advice, "error", 9000)
                elif not quiet_when_safe:
                    self.toast(advice, "success", 4000)

            self.after(0, present)

        threading.Thread(target=worker, daemon=True).start()

    # ==================================================================
    # Backup e migração
    # ==================================================================
    def export_backup(self) -> None:
        entries = self.database.get_all_entries()
        if not entries:
            self.toast("O cofre está vazio — nada a exportar.", "warning")
            return

        path = filedialog.asksaveasfilename(
            parent=self, title="Salvar backup cifrado",
            defaultextension=".ikbak", initialfile="ironkeypy-backup.ikbak",
            filetypes=[("Backup IronKey Py", "*.ikbak"), ("Todos os arquivos", "*.*")],
        )
        if not path:
            return

        passphrase = TextPromptDialog(
            self, "Senha do backup",
            "Escolha uma senha para proteger este arquivo. Ela pode ser a mesma "
            "senha mestre. Sem ela o backup é irrecuperável — nem por nós.",
            secret=True, confirm_text="Exportar",
        ).show()
        if not passphrase:
            return

        try:
            count = backup_service.export_encrypted_backup(entries, passphrase, path)
        except Exception as exc:
            self._error("Falha ao exportar", str(exc))
            return
        self.toast(
            f"{count} registro(s) exportados com AES-256-GCM. "
            "O arquivo é autocontido: pode ser restaurado em outra máquina.",
            "success", 7000,
        )

    def import_backup(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Selecionar backup",
            filetypes=[("Backup IronKey Py", "*.ikbak"), ("Todos os arquivos", "*.*")],
        )
        if not path:
            return

        passphrase = TextPromptDialog(
            self, "Senha do backup", "Digite a senha usada ao exportar este arquivo.",
            secret=True, confirm_text="Verificar",
        ).show()
        if not passphrase:
            return

        # Valida ANTES de tocar no cofre
        try:
            entries, meta = backup_service.read_encrypted_backup(path, passphrase)
        except backup_service.BackupError as exc:
            self._error("Backup não pôde ser lido", str(exc))
            return

        existing = self.database.get_all_entries()
        new_entries, skipped = backup_service.merge_entries(existing, entries)

        confirmed = ConfirmDialog(
            self, "Importar backup",
            f"Backup de {meta['exported_at']} com {meta['entry_count']} registro(s).\n\n"
            f"• {len(new_entries)} serão adicionados\n"
            f"• {skipped} já existem e serão ignorados\n\n"
            "Nada do que já está no cofre será apagado.",
            confirm_text="Importar", danger=False,
        ).show()
        if not confirmed:
            return

        imported = self.database.bulk_add(new_entries)
        self.refresh()
        self.toast(f"{imported} registro(s) importados.", "success", 5000)

    def import_csv(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Importar CSV de outro gerenciador",
            filetypes=[("CSV", "*.csv"), ("Todos os arquivos", "*.*")],
        )
        if not path:
            return
        try:
            entries, warnings = backup_service.import_csv(path)
        except backup_service.BackupError as exc:
            self._error("CSV não pôde ser lido", str(exc))
            return
        except Exception as exc:
            self._error("CSV não pôde ser lido", f"{exc}")
            return

        existing = self.database.get_all_entries()
        new_entries, skipped = backup_service.merge_entries(existing, entries)

        detail = (
            f"{len(entries)} linha(s) lida(s).\n\n"
            f"• {len(new_entries)} serão adicionados\n"
            f"• {skipped} duplicado(s) ignorado(s)\n"
        )
        if warnings:
            detail += f"\n{len(warnings)} aviso(s), ex.: {warnings[0]}"
        detail += (
            "\n\nApague o arquivo CSV depois de importar: ele contém suas "
            "senhas em texto puro."
        )

        if not ConfirmDialog(self, "Importar CSV", detail,
                             confirm_text="Importar", danger=False).show():
            return

        imported = self.database.bulk_add(new_entries)
        self.refresh()
        self.toast(f"{imported} registro(s) importados do CSV.", "success", 5000)

    def export_csv(self) -> None:
        entries = self.database.get_all_entries()
        if not entries:
            self.toast("O cofre está vazio — nada a exportar.", "warning")
            return

        confirmed = ConfirmDialog(
            self, "Exportar em TEXTO PURO",
            "O arquivo CSV conterá TODAS as suas senhas legíveis por qualquer "
            "pessoa ou programa. Use apenas para migrar para outro gerenciador "
            "e apague o arquivo em seguida.\n\n"
            "Para backup, use “Exportar backup” (.ikbak, cifrado).",
            confirm_word="EXPORTAR", confirm_text="Exportar mesmo assim",
        ).show()
        if not confirmed:
            return

        path = filedialog.asksaveasfilename(
            parent=self, title="Exportar CSV (texto puro)",
            defaultextension=".csv", initialfile="ironkeypy-export-INSEGURO.csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        try:
            count = backup_service.export_csv(entries, path)
        except Exception as exc:
            self._error("Falha ao exportar", str(exc))
            return
        self.toast(f"{count} registro(s) exportados em texto puro. Apague o arquivo "
                   "assim que terminar a migração.", "warning", 9000)

    # ==================================================================
    # Configurações e senha mestre
    # ==================================================================
    def save_settings(self) -> None:
        try:
            self.settings.save()
        except Exception as exc:
            self.toast(f"Não foi possível salvar as preferências: {exc}", "error")

    def open_settings(self) -> None:
        dialog = SettingsDialog(
            self, self.settings, self.crypto_manager.kdf_description(),
            str(get_app_data_dir()), lambda: self._open_data_folder(),
        )
        result = dialog.show()
        # O tema pode ter sido alterado ao vivo mesmo sem salvar; realinha.
        ctk.set_appearance_mode(self.settings.appearance_mode)
        if result is None:
            return
        ctk.set_widget_scaling(self.settings.ui_scaling)
        self.throttle.max_attempts = self.settings.max_unlock_attempts
        self.save_settings()
        self.toast("Preferências salvas.", "success")
        self.refresh()

    def _open_data_folder(self) -> None:
        if not open_in_file_manager(get_app_data_dir()):
            self.toast(f"Abra manualmente: {get_app_data_dir()}", "warning", 8000)

    def change_master_password(self) -> None:
        result = ChangeMasterPasswordDialog(
            self, self.password_generator, self.crypto_manager.verify_master_password
        ).show()
        if result is None:
            return
        current, new = result
        try:
            ok = self.crypto_manager.change_master_password(current, new)
        except CryptoError as exc:
            self._error("Falha ao alterar a senha mestre", str(exc))
            return
        if not ok:
            self.toast("Senha mestre atual incorreta.", "error")
            return
        self._master_password_cache = new
        self.crypto_kdf_label = self.crypto_manager.kdf_description()
        self.toast(
            "Senha mestre alterada. Backups antigos continuam válidos com a "
            "senha usada na exportação.", "success", 7000,
        )

    def open_help(self) -> None:
        HelpDialog(self, SHORTCUTS).show()

    # ==================================================================
    # Encerramento
    # ==================================================================
    def on_closing(self) -> None:
        if self.settings.clear_clipboard_on_exit and self.clipboard.has_pending_secret:
            self.clipboard.clear(force=False)
        try:
            self.crypto_manager.lock()
            self.save_settings()
        except Exception:
            pass
        self._cancel_lock_check()
        self.destroy()


def main() -> int:
    settings = Settings.load()
    ctk.set_appearance_mode(settings.appearance_mode)
    ctk.set_default_color_theme(settings.color_theme)
    if abs(settings.ui_scaling - 1.0) > 0.01:
        ctk.set_widget_scaling(settings.ui_scaling)

    try:
        app = IronKeyApp(settings)
    except Exception:
        traceback.print_exc()
        try:
            messagebox.showerror(
                "IronKey Py",
                "Falha ao iniciar a aplicação:\n\n" + traceback.format_exc(limit=3),
            )
        except Exception:
            pass
        return 1

    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
