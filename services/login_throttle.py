from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from services.app_paths import get_state_path, harden_path


@dataclass
class ThrottleStatus:
    allowed: bool
    remaining_attempts: int
    wait_seconds: int = 0

    @property
    def message(self) -> str:
        if self.allowed:
            if self.remaining_attempts <= 2:
                return f"Atenção: restam {self.remaining_attempts} tentativa(s) antes do bloqueio temporário."
            return ""
        minutes, seconds = divmod(self.wait_seconds, 60)
        if minutes:
            return f"Muitas tentativas incorretas. Aguarde {minutes}min {seconds}s."
        return f"Muitas tentativas incorretas. Aguarde {seconds}s."


class LoginThrottle:
    """Backoff exponencial: 15s, 30s, 1min, 2min... até 15 minutos."""

    BASE_DELAY = 15
    MAX_DELAY = 900

    def __init__(self, max_attempts: int = 5, path: Optional[str] = None):
        self.max_attempts = max(3, int(max_attempts))
        self.path = path or get_state_path()
        self._state = self._read()

    # ------------------------------------------------------------------
    def _read(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {
                "failed": int(data.get("failed", 0)),
                "locked_until": float(data.get("locked_until", 0)),
                "lockouts": int(data.get("lockouts", 0)),
                "last_success": data.get("last_success"),
            }
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return {"failed": 0, "locked_until": 0.0, "lockouts": 0, "last_success": None}

    def _write(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh)
            harden_path(self.path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    def status(self) -> ThrottleStatus:
        now = time.time()
        locked_until = self._state.get("locked_until", 0)
        if locked_until > now:
            return ThrottleStatus(False, 0, int(locked_until - now) + 1)
        remaining = max(0, self.max_attempts - self._state.get("failed", 0))
        return ThrottleStatus(True, remaining or self.max_attempts)

    def register_failure(self) -> ThrottleStatus:
        self._state["failed"] = self._state.get("failed", 0) + 1
        if self._state["failed"] >= self.max_attempts:
            self._state["lockouts"] = self._state.get("lockouts", 0) + 1
            delay = min(self.BASE_DELAY * (2 ** (self._state["lockouts"] - 1)), self.MAX_DELAY)
            self._state["locked_until"] = time.time() + delay
            self._state["failed"] = 0
            self._write()
            return ThrottleStatus(False, 0, int(delay))
        self._write()
        return ThrottleStatus(True, self.max_attempts - self._state["failed"])

    def register_success(self) -> None:
        self._state = {
            "failed": 0,
            "locked_until": 0.0,
            "lockouts": 0,
            "last_success": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._write()

    def last_success(self) -> Optional[str]:
        return self._state.get("last_success")

    def reset(self) -> None:
        self._state = {"failed": 0, "locked_until": 0.0, "lockouts": 0, "last_success": None}
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass