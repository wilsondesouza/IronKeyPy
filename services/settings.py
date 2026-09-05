from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, fields
from typing import Any, Dict

from services.app_paths import get_settings_path, harden_path


@dataclass
class Settings:
    # Segurança
    auto_lock_seconds: int = 300           # 0 = desativado
    lock_on_minimize: bool = False
    clipboard_clear_seconds: int = 30      # 0 = não limpar
    clear_clipboard_on_exit: bool = True
    max_unlock_attempts: int = 5
    check_hibp_on_save: bool = False       # opt-in explícito (requer rede)
    hide_passwords_by_default: bool = True
    keep_password_history: bool = True
    password_history_limit: int = 10

    # Aparência / usabilidade
    appearance_mode: str = "dark"          # dark | light | system
    color_theme: str = "blue"
    ui_scaling: float = 1.0
    default_length: int = 20
    default_use_lowercase: bool = True
    default_use_uppercase: bool = True
    default_use_digits: bool = True
    default_use_symbols: bool = True
    default_exclude_ambiguous: bool = True
    default_passphrase_words: int = 5
    sort_order: str = "updated_desc"       # updated_desc | title_asc | created_desc
    show_onboarding: bool = True

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | None = None) -> "Settings":
        path = path or get_settings_path()
        instance = cls()
        if not os.path.exists(path):
            return instance
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data: Dict[str, Any] = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return instance  # arquivo corrompido: volta aos padrões seguros

        valid = {f.name: f.type for f in fields(cls)}
        for key, value in data.items():
            if key not in valid:
                continue
            try:
                current = getattr(instance, key)
                if isinstance(current, bool):
                    value = bool(value)
                elif isinstance(current, int):
                    value = int(value)
                elif isinstance(current, float):
                    value = float(value)
                elif isinstance(current, str):
                    value = str(value)
                setattr(instance, key, value)
            except (TypeError, ValueError):
                continue
        return instance.sanitized()

    def sanitized(self) -> "Settings":
        """Impede valores inseguros/absurdos vindos de edição manual do JSON."""
        self.auto_lock_seconds = _clamp(self.auto_lock_seconds, 0, 24 * 3600)
        self.clipboard_clear_seconds = _clamp(self.clipboard_clear_seconds, 0, 600)
        self.max_unlock_attempts = _clamp(self.max_unlock_attempts, 3, 20)
        self.password_history_limit = _clamp(self.password_history_limit, 0, 100)
        self.default_length = _clamp(self.default_length, 8, 128)
        self.default_passphrase_words = _clamp(self.default_passphrase_words, 3, 12)
        self.ui_scaling = min(max(float(self.ui_scaling), 0.8), 1.6)
        if self.appearance_mode not in ("dark", "light", "system"):
            self.appearance_mode = "dark"
        if self.sort_order not in ("updated_desc", "title_asc", "created_desc"):
            self.sort_order = "updated_desc"
        return self

    def save(self, path: str | None = None) -> None:
        path = path or get_settings_path()
        directory = os.path.dirname(os.path.abspath(path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".settings-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(asdict(self.sanitized()), fh, indent=2, sort_keys=True)
            harden_path(tmp)
            os.replace(tmp, path)
            harden_path(path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(int(value), high))
