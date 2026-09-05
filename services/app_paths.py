from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "IronKeyPy"


def _base_data_dir() -> Path:
    if sys.platform == "win32":
        root = os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming")
    elif sys.platform == "darwin":
        root = os.path.expanduser("~/Library/Application Support")
    else:
        root = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(root)


def get_app_data_dir() -> Path:
    """Diretório persistente da aplicação, criado com permissão 0700 em POSIX."""
    override = os.environ.get("IRONKEYPY_DATA_DIR")
    app_dir = Path(override).expanduser() if override else _base_data_dir() / APP_NAME

    app_dir.mkdir(parents=True, exist_ok=True)
    harden_path(app_dir, directory=True)
    return app_dir


def get_config_path() -> str:
    return str(get_app_data_dir() / "config.json")


def get_database_path() -> str:
    return str(get_app_data_dir() / "ironkeypy.db")


def get_settings_path() -> str:
    return str(get_app_data_dir() / "settings.json")


def get_state_path() -> str:
    """Estado volátil (tentativas de login, bloqueio temporário)."""
    return str(get_app_data_dir() / "state.json")


def resource_path(*parts: str) -> Path:
    """
    Caminho de um recurso empacotado (ícones, wordlist).

    Funciona tanto executando do código-fonte quanto de um binário PyInstaller
    (``--onefile`` extrai os dados em ``sys._MEIPASS``).
    """
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base.joinpath(*parts)


def harden_path(path: os.PathLike | str, directory: bool = False) -> None:
    """Restringe o acesso ao dono do arquivo (no-op fora de POSIX)."""
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o700 if directory else 0o600)
    except OSError:
        pass


def open_in_file_manager(path: os.PathLike | str) -> bool:
    """Abre uma pasta no gerenciador de arquivos do SO (multiplataforma)."""
    import subprocess

    target = str(path)
    try:
        if sys.platform == "win32":
            os.startfile(target)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
        return True
    except Exception:
        return False
