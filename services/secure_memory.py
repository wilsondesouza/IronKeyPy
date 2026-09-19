from __future__ import annotations

import hmac
from typing import Iterable


class SecretBytes:

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | bytearray | str):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._buf = bytearray(data)
        self._wiped = False

    def __enter__(self) -> "SecretBytes":
        return self

    def __exit__(self, *exc) -> None:
        self.wipe()

    def __len__(self) -> int:
        return len(self._buf)

    def __bool__(self) -> bool:
        return bool(self._buf)

    def bytes(self) -> bytes:
        if self._wiped:
            raise ValueError("Segredo já foi apagado da memória.")
        return bytes(self._buf)

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        del self._buf[:]
        self._wiped = True

    # Evita vazamento acidental em logs / tracebacks.
    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<SecretBytes len={len(self._buf)} wiped={self._wiped}>"

    __str__ = __repr__


def wipe_all(secrets: Iterable[SecretBytes | None]) -> None:
    for secret in secrets:
        if secret is not None:
            secret.wipe()


def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
