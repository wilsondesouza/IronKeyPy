"""
Preferências do usuário, persistidas em ``settings.json``.

Antes, valores como o tempo de auto-bloqueio (300 s) e o de limpeza da área de
transferência (30 s) eram constantes no código — o usuário não tinha controle
sobre o principal trade-off entre segurança e conveniência do produto.
"""

from __future__ import annotations

import json
import os
import platform
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass, fields
from typing import Any, Dict, Tuple

from services.app_paths import get_settings_path, harden_path

DEVICE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _is_device_id(value: Any) -> bool:
    return bool(DEVICE_ID_RE.match(str(value or "")))


def default_device_label() -> str:
    """Rótulo inicial do dispositivo (só exibição; não é segredo)."""
    host = platform.node() or ""
    system = {"win32": "Windows", "darwin": "macOS", "linux": "Linux"}.get(
        "win32" if os.name == "nt" else ("darwin" if platform.system() == "Darwin" else "linux"),
        platform.system() or "Dispositivo",
    )
    return f"{system}{(' — ' + host) if host else ''}"[:60]


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

    # Sincronização entre dispositivos (ver docs/CONTRATO-DE-SINCRONIZACAO.md)
    device_id: str = ""                    # UUIDv4 hex; gerado na primeira execução
    device_label: str = ""                 # nome amigável exibido nos conflitos
    sync_enabled: bool = False
    sync_dir: str = ""                     # pasta sincronizada pelo usuário
    sync_interval_seconds: int = 60        # 0 = sem verificação periódica
    sync_on_unlock: bool = True
    sync_on_lock: bool = True
    tombstone_max_age_days: int = 90       # decisão D1: teto fixo

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
        self.sync_interval_seconds = _clamp(self.sync_interval_seconds, 0, 3600)
        self.tombstone_max_age_days = _clamp(self.tombstone_max_age_days, 7, 3650)
        self.sync_dir = str(self.sync_dir or "")
        self.device_label = str(self.device_label or "")[:60]
        if not _is_device_id(self.device_id):
            # Identificador inválido ou ausente: um novo é gerado. Perder o
            # device_id não perde dados, apenas desliga a detecção de conflito
            # com o "outro eu" que tinha esse identificador.
            self.device_id = uuid.uuid4().hex
        self.ui_scaling = min(max(float(self.ui_scaling), 0.8), 1.6)
        if self.appearance_mode not in ("dark", "light", "system"):
            self.appearance_mode = "dark"
        if self.sort_order not in ("updated_desc", "title_asc", "created_desc"):
            self.sort_order = "updated_desc"
        return self

    @property
    def device_name(self) -> str:
        """Rótulo do dispositivo, com um padrão derivado do sistema se vazio."""
        return self.device_label or default_device_label()

    def sync_configured(self) -> bool:
        """Sincronização pronta para uso (ativada e com pasta definida)."""
        return bool(self.sync_enabled and self.sync_dir and os.path.isdir(self.sync_dir))

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
